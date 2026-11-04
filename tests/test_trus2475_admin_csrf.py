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

import json
import logging
import re

import pytest
from sqlmodel import select

from app.auth import (
    AdminUser,
    create_session,
    hash_password,
    SESSION_COOKIE,
)
from app.models import Agent
from tests.conftest import register, verify_email

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


def _passwords_in(body):
    """The 16-hex-character temporary passwords rendered in `body`."""
    return re.findall(r"\b[0-9a-f]{16}\b", body)


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


def test_rejected_origin_is_capped_and_sanitised_in_the_log(client, session, caplog):
    """`/admin/login` is unauthenticated, so anyone can drive this log line.

    An uncapped, unsanitised header lets a stranger write arbitrary length and
    control characters — newlines especially — into our logs (TRUS-2475
    review).
    """
    _admin(session, role="admin", email="someone@predixtions.com")
    nasty = "https://evil.example/" + ("A" * 500) + "\r\nFAKE-LOG-LINE: injected\x00"

    with caplog.at_level(logging.WARNING):
        resp = client.post(
            "/admin/login",
            data={"email": "someone@predixtions.com", "password": "pw"},
            headers={"Origin": nasty},
            follow_redirects=False,
        )

    assert resp.status_code == 403
    recorded = [
        r.stated_origin for r in caplog.records if hasattr(r, "stated_origin")
    ]
    assert recorded, "the rejection was not logged"
    for value in recorded:
        assert len(value) <= 160, "attacker-controlled origin was not capped"
        assert "\n" not in value and "\r" not in value and "\x00" not in value
        assert "FAKE-LOG-LINE" not in value


def test_opaque_origin_rejected(client, session):
    """A sandboxed iframe or a redirected post sends `Origin: null`.

    It is a literal string, not an absent header, so the `Referer` fallback
    must not run and rescue it (TRUS-2475 review).
    """
    _as(client, session)
    before = len(_users(session))

    resp = _add(client, origin="null", Referer=f"{OWN}/admin/users")

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

    # Checking the parameter name only proves the old redirect is gone. The
    # value itself must not reach any header either — `Location`, a cookie, or
    # anything else a proxy records (TRUS-2475 review).
    for candidate in _passwords_in(resp.text):
        for header, value in resp.headers.items():
            assert candidate not in value, f"password leaked into {header!r}"


def test_temp_password_page_is_not_cacheable(client, session):
    """The body holds a live credential, so no cache may retain it."""
    _as(client, session)

    resp = _add(client)

    assert "no-store" in resp.headers.get("cache-control", "")


def test_temp_password_is_never_logged(client, session, caplog):
    """A credential in a log record outlives the one-time display."""
    _as(client, session)

    with caplog.at_level(logging.DEBUG):
        resp = _add(client)

    shown = _passwords_in(resp.text)
    assert shown, "no temporary password rendered"
    logged = "\n".join(
        [r.getMessage() for r in caplog.records]
        + [str(getattr(r, "args", "")) for r in caplog.records]
    )
    for candidate in shown:
        assert candidate not in logged, "temporary password reached a log record"


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

# "viewer" is in this list deliberately. It used to be accepted, but no code
# path reads `role` to deny a write, so the label promised a restriction
# nobody enforced. Removed in TRUS-2475; enforcing roles properly is
# TRUS-2494. Pinned here so it cannot drift back in unnoticed.
@pytest.mark.parametrize(
    "role", ["owner", "SUPERADMIN", "admin; drop", "viewer", "viewer "]
)
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


# Pinned as a literal, not `ADMIN_ROLES`. Parametrizing on the constant means
# narrowing it silently narrows the test too, so a role could be dropped
# without anything failing (TRUS-2475 review).
@pytest.mark.parametrize("role", ["superadmin", "admin"])
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
    """A *valid* `X-ANS-Admin-Key` identifies a programmatic caller.

    A browser never attaches this header on its own, and a page that sets it
    cross-origin triggers a preflight it cannot satisfy. Such callers carry no
    CSRF risk and must keep working without an Origin.
    """
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


@pytest.mark.parametrize("bogus_key", ["x", "ans-not-a-real-key", " "])
def test_invalid_api_key_does_not_skip_the_guard(client, session, bogus_key):
    """The exemption must depend on the key resolving, not on the header being set.

    `get_current_admin` falls back to the session cookie when the key matches
    no admin, so exempting on mere presence would let any junk value turn a
    cookie-authenticated cross-origin post into an exempt one (TRUS-2475
    review).
    """
    _as(client, session)
    before = len(_users(session))

    resp = _add(client, origin=SIBLING, **{"X-ANS-Admin-Key": bogus_key})

    assert resp.status_code == 403
    assert len(_users(session)) == before


def test_api_key_of_a_disabled_admin_does_not_skip_the_guard(client, session, admin_key):
    """A revoked admin's key must stop exempting the moment it is revoked."""
    _as(client, session)
    holder = session.exec(
        select(AdminUser).where(AdminUser.api_key == admin_key)
    ).one()
    holder.is_active = False
    session.add(holder)
    session.commit()
    before = len(_users(session))

    resp = _add(client, origin=SIBLING, **{"X-ANS-Admin-Key": admin_key})

    assert resp.status_code == 403
    assert len(_users(session)) == before


# ── The JSON admin routes are reachable without a preflight too ──────────

def test_json_admin_route_rejects_a_cross_site_post(client, session):
    """A body with *no* `Content-Type` is parsed as JSON, so there is no preflight.

    `fetch` sends no `Content-Type` for a `BufferSource` body, which makes this
    a simple request: same-site, cookie attached, nothing for CORS to
    intercept. A body with a *wrong* `Content-Type` 422s instead — a different
    case, and the one the ticket originally measured (TRUS-2475 review).
    """
    _as(client, session)
    register(client, "acme-sales-agent", owner_email="ai@acme.com")
    verify_email(client, "acme-sales-agent")

    resp = client.post(
        "/ans/verify/org",
        content=b'{"ans_name":"acme-sales-agent"}',  # deliberately no Content-Type
        headers={"Origin": SIBLING},
    )

    assert resp.status_code == 403
    agent = session.exec(
        select(Agent).where(Agent.ans_name == "acme-sales-agent")
    ).one()
    assert agent.org_validated is False


@pytest.mark.parametrize(
    "path,body",
    [
        ("/ans/verify/org", {"ans_name": "acme-sales-agent"}),
        (
            "/ans/transfer",
            {
                "ans_name": "acme-sales-agent",
                "from_email": "ai@acme.com",
                "to_org": "New Co",
                "to_email": "new@newco.example",
            },
        ),
        (
            "/ans/transfer/accept",
            {"transfer_token": "whatever", "to_email": "new@newco.example"},
        ),
    ],
)
@pytest.mark.parametrize("origin", [SIBLING, THIRD_PARTY, FOREIGN])
def test_every_json_admin_route_is_guarded(client, session, path, body, origin):
    _as(client, session)
    register(client, "acme-sales-agent", owner_email="ai@acme.com")
    verify_email(client, "acme-sales-agent")

    resp = client.post(
        path,
        content=json.dumps(body).encode(),  # no Content-Type
        headers={"Origin": origin},
    )

    assert resp.status_code == 403


def test_json_admin_route_still_works_same_origin(client, session):
    """The guard must not break the legitimate path."""
    _as(client, session)
    register(client, "acme-sales-agent", owner_email="ai@acme.com")
    verify_email(client, "acme-sales-agent")

    resp = client.post(
        "/ans/verify/org",
        json={"ans_name": "acme-sales-agent"},
        headers={"Origin": OWN},
    )

    assert resp.status_code == 200
    agent = session.exec(
        select(Agent).where(Agent.ans_name == "acme-sales-agent")
    ).one()
    assert agent.org_validated is True


def test_json_admin_route_still_works_for_api_key_callers(client, session, admin_key):
    """Programmatic callers send no Origin and must be unaffected."""
    register(client, "acme-sales-agent", owner_email="ai@acme.com")
    verify_email(client, "acme-sales-agent")

    resp = client.post(
        "/ans/verify/org",
        json={"ans_name": "acme-sales-agent"},
        headers={"X-ANS-Admin-Key": admin_key},
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
