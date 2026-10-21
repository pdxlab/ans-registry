"""
TRUS-2006 — ownership transfer is admin-only.

`POST /ans/transfer` used to be public, accepted `from_email == owner_email` as
its only proof of ownership, and returned the transfer token to the caller.
`POST /ans/transfer/accept` was public too, and only checked a `to_email` the
caller had chosen. Together: anyone who knew or guessed an owner's address could
take any name. Both routes now require an admin (API key or session).
"""

from sqlmodel import select

from app.models import Agent, Transfer
from tests.conftest import register

OWNER = "ai@acme.com"
ATTACKER = "evil@bad.example"


def _transfer_body(to_email=ATTACKER, from_email=OWNER):
    return {
        "ans_name": "acme-sales-agent",
        "from_email": from_email,
        "to_org": "Bad Co",
        "to_email": to_email,
    }


def _agent(session):
    return session.exec(select(Agent).where(Agent.ans_name == "acme-sales-agent")).one()


def test_anonymous_transfer_refused_and_creates_no_row(client, session):
    register(client, "acme-sales-agent", owner_email=OWNER)

    # The exact attack: correct owner email, no credential.
    resp = client.post("/ans/transfer", json=_transfer_body(), follow_redirects=False)

    assert resp.status_code in (302, 401, 403)
    assert "transfer_token" not in resp.text
    assert session.exec(select(Transfer)).all() == []


def test_bad_admin_key_refused(client, session):
    register(client, "acme-sales-agent", owner_email=OWNER)

    resp = client.post(
        "/ans/transfer",
        json=_transfer_body(),
        headers={"X-ANS-Admin-Key": "not-a-real-key"},
        follow_redirects=False,
    )

    assert resp.status_code in (302, 401, 403)
    assert session.exec(select(Transfer)).all() == []


def test_anonymous_accept_refused_and_ownership_unchanged(client, session, admin_key):
    register(client, "acme-sales-agent", owner_email=OWNER)
    token = client.post(
        "/ans/transfer", json=_transfer_body(), headers={"X-ANS-Admin-Key": admin_key}
    ).json()["transfer_token"]

    # Even holding a valid token, an anonymous caller cannot complete it.
    resp = client.post(
        "/ans/transfer/accept",
        json={"transfer_token": token, "to_email": ATTACKER},
        follow_redirects=False,
    )

    assert resp.status_code in (302, 401, 403)
    session.expire_all()
    assert _agent(session).owner_email == OWNER
    assert session.exec(select(Transfer)).one().status == "pending"


def test_admin_transfer_happy_path_resets_verification(client, session, admin_key):
    register(client, "acme-sales-agent", owner_email=OWNER)
    client.post("/ans/verify", json={"ans_name": "acme-sales-agent", "method": "email"})
    headers = {"X-ANS-Admin-Key": admin_key}

    init = client.post("/ans/transfer", json=_transfer_body(to_email="ai@newco.example"), headers=headers)
    assert init.status_code == 200
    assert init.json()["status"] == "pending"

    accept = client.post(
        "/ans/transfer/accept",
        json={"transfer_token": init.json()["transfer_token"], "to_email": "ai@newco.example"},
        headers=headers,
    )
    assert accept.status_code == 200

    session.expire_all()
    agent = _agent(session)
    assert agent.owner_email == "ai@newco.example"
    assert agent.owner_org == "Bad Co"
    assert agent.verified is False  # new owner must re-verify


def test_admin_still_needs_current_owner_email(client, session, admin_key):
    register(client, "acme-sales-agent", owner_email=OWNER)

    resp = client.post(
        "/ans/transfer",
        json=_transfer_body(from_email="someone-else@acme.com"),
        headers={"X-ANS-Admin-Key": admin_key},
    )

    assert resp.status_code == 403
    assert session.exec(select(Transfer)).all() == []


def test_completed_token_cannot_be_replayed(client, session, admin_key):
    register(client, "acme-sales-agent", owner_email=OWNER)
    headers = {"X-ANS-Admin-Key": admin_key}
    token = client.post("/ans/transfer", json=_transfer_body(to_email="ai@newco.example"), headers=headers).json()[
        "transfer_token"
    ]
    accept = {"transfer_token": token, "to_email": "ai@newco.example"}
    assert client.post("/ans/transfer/accept", json=accept, headers=headers).status_code == 200

    assert client.post("/ans/transfer/accept", json=accept, headers=headers).status_code == 404


def test_wrong_recipient_email_refused_even_for_admin(client, session, admin_key):
    register(client, "acme-sales-agent", owner_email=OWNER)
    headers = {"X-ANS-Admin-Key": admin_key}
    token = client.post("/ans/transfer", json=_transfer_body(to_email="ai@newco.example"), headers=headers).json()[
        "transfer_token"
    ]

    resp = client.post(
        "/ans/transfer/accept", json={"transfer_token": token, "to_email": ATTACKER}, headers=headers
    )

    assert resp.status_code == 403
    session.expire_all()
    assert _agent(session).owner_email == OWNER


def test_wrongly_moved_name_can_be_recovered_by_admin(client, session, admin_key):
    """Lockout regression: the real owner has a way back (via support/admin)."""
    register(client, "acme-sales-agent", owner_email=OWNER)
    headers = {"X-ANS-Admin-Key": admin_key}
    token = client.post("/ans/transfer", json=_transfer_body(), headers=headers).json()["transfer_token"]
    client.post("/ans/transfer/accept", json={"transfer_token": token, "to_email": ATTACKER}, headers=headers)

    back = client.post(
        "/ans/transfer",
        json={"ans_name": "acme-sales-agent", "from_email": ATTACKER, "to_org": "Acme Inc.", "to_email": OWNER},
        headers=headers,
    ).json()["transfer_token"]
    resp = client.post("/ans/transfer/accept", json={"transfer_token": back, "to_email": OWNER}, headers=headers)

    assert resp.status_code == 200
    session.expire_all()
    assert _agent(session).owner_email == OWNER


def test_public_routes_stay_public(client):
    """Only transfer was gated — registration and lookups must not regress."""
    assert register(client, "acme-sales-agent", owner_email=OWNER).status_code in (200, 201)
    assert client.get("/ans/whois/acme-sales-agent").status_code == 200
    assert client.get("/ans/lookup/acme-sales-agent").status_code == 200
