"""
TRUS-2475 — admin form posts are same-origin only, and the temporary password
never rides back on a URL.

`ans_admin_session` is `SameSite=Lax`, and SameSite is decided per *site*, not
per origin: every `*.trustmodel.ai` host is the same site as the registry, so
the browser attaches the cookie to a POST from any sibling subdomain. Form
posts are "simple" requests, so nothing is preflighted and CORS never sees
them. `require_same_origin` is the control that actually stops it.

`/admin/users/add` also used to redirect to `?temp_pw=<password>`, putting a
live credential into browser history, `Referer` and any proxy log that records
full URLs.
"""

import pytest
from sqlmodel import select

from app.auth import (
    ADMIN_ROLES,
    AdminUser,
    create_session,
    hash_password,
    SESSION_COOKIE,
)
from tests.conftest import register

# TestClient serves on http://testserver, so that is this app's own origin.
OWN = "http://testserver"
SIBLING = "https://acme.trustmodel.ai"       # wildcard DNS -> our front end
THIRD_PARTY = "https://www.trustmodel.ai"    # same site, someone else's host
FOREIGN = "https://evil.example"


def _admin(session, role="superadmin", email="super@predixtions.com"):
    admin = AdminUser(
        email=email,
        name="Test Super",
        password_hash=hash_password("pw"),
        salt="",
        role=role,
    )
    session.add(admin)
    session.commit()
    session.refresh(admin)
    return admin


def _as(client, session, role="superadmin"):
    """Give `client` a live session cookie for an admin of `role`."""
    admin = _admin(session, role=role)
    client.cookies.set(SESSION_COOKIE, create_session(admin, session))
    return admin


def _add(client, origin=OWN, role="admin", email="new@predixtions.com", **headers):
    if origin is not None:
        headers["Origin"] = origin
    return client.post(
        "/admin/users/add",
        data={"name": "New Admin", "email": email, "role": role},
        headers=headers,
        follow_redirects=False,
    )


def _users(session):
    return session.exec(select(AdminUser)).all()


# ── The attack the ticket describes ──────────────────────────────────────

@pytest.mark.parametrize("origin", [SIBLING, THIRD_PARTY, FOREIGN])
def test_cross_origin_add_rejected_and_creates_no_user(client, session, origin):
    """A page on any other host cannot drive the superadmin's session."""
    _as(client, session)
    before = len(_users(session))

    resp = _add(client, origin=origin)

    assert resp.status_code == 403
    assert len(_users(session)) == before


def test_missing_origin_and_referer_fails_closed(client, session):
    _as(client, session)
    before = len(_users(session))

    resp = _add(client, origin=None)

    assert resp.status_code == 403
    assert len(_users(session)) == before


def test_same_origin_add_still_works(client, session):
    _as(client, session)

    resp = _add(client)

    assert resp.status_code == 200
    created = session.exec(
        select(AdminUser).where(AdminUser.email == "new@predixtions.com")
    ).one()
    assert created.role == "admin"


def test_referer_stands_in_for_a_missing_origin(client, session):
    """Some browsers omit `Origin` on same-origin form posts; `Referer` carries
    the same fact and keeps those working."""
    _as(client, session)

    resp = _add(client, origin=None, Referer=f"{OWN}/admin/users")

    assert resp.status_code == 200


@pytest.mark.parametrize("referer", [f"{SIBLING}/x", f"{FOREIGN}/x", "not-a-url"])
def test_foreign_referer_rejected(client, session, referer):
    _as(client, session)
    before = len(_users(session))

    resp = _add(client, origin=None, Referer=referer)

    assert resp.status_code == 403
    assert len(_users(session)) == before


def test_origin_wins_over_a_same_origin_referer(client, session):
    """`Origin` is the authoritative header. A forged `Referer` must not rescue
    a cross-origin post."""
    _as(client, session)
    before = len(_users(session))

    resp = _add(client, origin=SIBLING, Referer=f"{OWN}/admin/users")

    assert resp.status_code == 403
    assert len(_users(session)) == before


# ── Login CSRF ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("origin", [SIBLING, THIRD_PARTY, FOREIGN])
def test_login_csrf_rejected(client, session, origin):
    """Logging a victim into an attacker-controlled account is also CSRF."""
    _admin(session, role="admin", email="someone@predixtions.com")

    resp = client.post(
        "/admin/login",
        data={"email": "someone@predixtions.com", "password": "pw"},
        headers={"Origin": origin},
        follow_redirects=False,
    )

    assert resp.status_code == 403
    assert SESSION_COOKIE not in resp.cookies


def test_same_origin_login_still_works(client, session):
    _admin(session, role="admin", email="someone@predixtions.com")

    resp = client.post(
        "/admin/login",
        data={"email": "someone@predixtions.com", "password": "pw"},
        headers={"Origin": OWN},
        follow_redirects=False,
    )

    assert resp.status_code == 302
    assert resp.cookies.get(SESSION_COOKIE)


# ── The credential is out of the URL ─────────────────────────────────────

def test_temp_password_is_not_in_any_url(client, session):
    _as(client, session)

    resp = _add(client)

    assert "temp_pw" not in resp.headers.get("location", "")
    assert "temp_pw" not in str(resp.url)
    assert resp.status_code == 200


def test_temp_password_is_shown_once_in_the_body(client, session):
    """It is only stored hashed, so the response is the one chance to read it."""
    _as(client, session)

    resp = _add(client)

    created = session.exec(
        select(AdminUser).where(AdminUser.email == "new@predixtions.com")
    ).one()
    # The page shows a 16-hex-character password that verifies against the row.
    import re

    from app.auth import verify_password

    shown = re.findall(r"\b[0-9a-f]{16}\b", resp.text)
    assert shown, "no temporary password rendered"
    assert any(verify_password(p, created.salt, created.password_hash) for p in shown)


# ── Role validation ──────────────────────────────────────────────────────

@pytest.mark.parametrize("role", ["owner", "SUPERADMIN", "admin; drop", "viewer "])
def test_unknown_role_rejected_and_creates_no_user(client, session, role):
    _as(client, session)
    before = len(_users(session))

    resp = _add(client, role=role)

    assert 400 <= resp.status_code < 500
    assert len(_users(session)) == before


def test_empty_role_field_falls_back_to_the_default(client, session):
    """An empty form field reads as absent, so `Form("admin")` supplies the
    default rather than storing "". Pinned because the validation above would
    otherwise look like it covers this case."""
    _as(client, session)

    resp = _add(client, role="")

    assert resp.status_code == 200
    created = session.exec(
        select(AdminUser).where(AdminUser.email == "new@predixtions.com")
    ).one()
    assert created.role == "admin"


@pytest.mark.parametrize("role", ADMIN_ROLES)
def test_every_documented_role_is_accepted(client, session, role):
    _as(client, session)

    resp = _add(client, role=role, email=f"{role}@predixtions.com")

    assert resp.status_code == 200
    created = session.exec(
        select(AdminUser).where(AdminUser.email == f"{role}@predixtions.com")
    ).one()
    assert created.role == role


# ── Regressions: what must not change ────────────────────────────────────

def test_non_superadmin_still_blocked(client, session):
    """Authorization is unchanged and is checked independently of CSRF."""
    _as(client, session, role="admin")
    before = len(_users(session))

    resp = _add(client)

    assert resp.status_code == 403
    assert len(_users(session)) == before


def test_api_key_caller_is_exempt(client, session, admin_key):
    """`X-ANS-Admin-Key` is never attached by a browser, and setting it
    cross-origin forces a preflight CORS rejects, so these callers carry no
    CSRF risk and must keep working without an Origin."""
    resp = client.post(
        "/admin/users/add",
        data={"name": "Svc", "email": "svc@predixtions.com", "role": "admin"},
        headers={"X-ANS-Admin-Key": admin_key},
        follow_redirects=False,
    )

    assert resp.status_code == 200
    assert session.exec(
        select(AdminUser).where(AdminUser.email == "svc@predixtions.com")
    ).one()


def test_json_admin_routes_unaffected(client, session, admin_key):
    """JSON routes were never form posts; the guard is not on them."""
    register(client, "acme-sales-agent", owner_email="ai@acme.com")

    resp = client.post(
        "/ans/transfer",
        json={
            "ans_name": "acme-sales-agent",
            "from_email": "ai@acme.com",
            "to_org": "New Co",
            "to_email": "new@newco.example",
        },
        headers={"X-ANS-Admin-Key": admin_key, "Origin": FOREIGN},
        follow_redirects=False,
    )

    assert resp.status_code == 200


def test_cookie_is_still_lax_and_hardened(client, session):
    """The cookie flags are the other half of the defence; keep them pinned."""
    _admin(session, role="admin", email="someone@predixtions.com")

    resp = client.post(
        "/admin/login",
        data={"email": "someone@predixtions.com", "password": "pw"},
        headers={"Origin": OWN},
        follow_redirects=False,
    )

    set_cookie = resp.headers["set-cookie"].lower()
    assert "httponly" in set_cookie
    assert "samesite=lax" in set_cookie
