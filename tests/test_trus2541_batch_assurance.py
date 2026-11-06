"""TRUS-2541 — POST /ans/assurance: assurance_tier for many names in one call.

The console ANS list is served by aurora-gateway's Trust Index, which has no
copy of the registry's tier, so an IV or OV name rendered "Unverified". The
gateway needs every name on a list page (up to 200) in one hop; /ans/whois is
one name per call and writes a LookupLog row each time.

Pinned here: each name's stored tier (IV / DV / OV / unverified), unknown and
non-active names omitted, names normalised like whois, no LookupLog written,
nothing but the tier returned, and the 200-name cap.
"""

from sqlmodel import select

from app.models import Agent, LookupLog
from tests.conftest import register, verify_owner


def _assurance(client, names):
    return client.post("/ans/assurance", json={"names": names})


def test_returns_each_names_stored_tier(client, admin_key):
    for name in ("acme-unverified", "acme-iv", "acme-dv", "acme-ov"):
        register(client, name)
    verify_owner(client, "acme-dv")
    verify_owner(client, "acme-ov")
    headers = {"X-ANS-Admin-Key": admin_key}
    client.post("/ans/verify/org", json={"ans_name": "acme-ov"}, headers=headers)
    client.post("/ans/verify/individual", json={"ans_name": "acme-iv"}, headers=headers)

    resp = _assurance(
        client, ["acme-unverified", "acme-iv", "acme-dv", "acme-ov"]
    )

    assert resp.status_code == 200
    assert resp.json() == {
        "tiers": {
            "acme-unverified": "unverified",
            "acme-iv": "IV",
            "acme-dv": "DV",
            "acme-ov": "OV",
        }
    }


def test_agrees_with_whois(client, admin_key):
    register(client, "acme-ov")
    verify_owner(client, "acme-ov")
    client.post(
        "/ans/verify/org",
        json={"ans_name": "acme-ov"},
        headers={"X-ANS-Admin-Key": admin_key},
    )

    tiers = _assurance(client, ["acme-ov"]).json()["tiers"]

    assert tiers["acme-ov"] == client.get("/ans/whois/acme-ov").json()["assurance_tier"]


def test_unknown_names_are_omitted(client):
    register(client, "acme-agent")

    tiers = _assurance(client, ["acme-agent", "nobody-here"]).json()["tiers"]

    assert tiers == {"acme-agent": "unverified"}


def test_non_active_names_are_omitted(client, session):
    register(client, "acme-agent")
    agent = session.exec(select(Agent).where(Agent.ans_name == "acme-agent")).one()
    agent.status = "revoked"
    session.add(agent)
    session.commit()

    assert _assurance(client, ["acme-agent"]).json()["tiers"] == {}


def test_names_are_normalised_like_whois(client):
    register(client, "acme-agent")

    tiers = _assurance(client, ["  ACME-Agent  "]).json()["tiers"]

    # Keyed by the normalised name, so the caller can look it up by ans_name.
    assert tiers == {"acme-agent": "unverified"}


def test_empty_list_returns_empty_map(client):
    resp = _assurance(client, [])

    assert resp.status_code == 200
    assert resp.json() == {"tiers": {}}


def test_more_than_200_names_is_rejected(client):
    resp = _assurance(client, [f"agent-{i}" for i in range(201)])

    assert resp.status_code == 422


def test_exactly_200_names_is_accepted(client):
    resp = _assurance(client, [f"agent-{i}" for i in range(200)])

    assert resp.status_code == 200


def test_missing_names_field_is_rejected(client):
    assert client.post("/ans/assurance", json={}).status_code == 422


def test_does_not_write_lookup_log(client, session):
    register(client, "acme-agent")

    _assurance(client, ["acme-agent"])

    assert session.exec(select(LookupLog)).all() == []


def test_returns_only_the_tier(client):
    register(client, "acme-agent", owner_email="ai@acme.com")

    body = _assurance(client, ["acme-agent"]).text

    # Public endpoint: no owner identity, only the tier (TRUS-2001).
    assert "ai@acme.com" not in body
    assert "Acme Inc." not in body
