"""TRUS-1678 — IV (Individual-Validated) tier.

aurora-gateway registers a name for an individual's workspace org, then
promotes it to IV through the admin-gated POST /ans/verify/individual. The
public /ans/register must never grant a tier, whatever the body claims.
IV ranks below DV: it never satisfies a DV/OV bar and is not a route to OV.
"""

from sqlmodel import select

from app.models import Agent
from tests.conftest import register, verify_email

IV_URL = "/ans/verify/individual"


def _promote(client, ans_name, admin_key):
    return client.post(
        IV_URL, json={"ans_name": ans_name}, headers={"X-ANS-Admin-Key": admin_key}
    )


def _agent(session, ans_name):
    session.expire_all()
    return session.exec(select(Agent).where(Agent.ans_name == ans_name)).first()


# ── Grant ──


def test_admin_promotes_registered_name_to_iv(client, session, admin_key):
    register(client, "sophia-agent", owner_email="sophia@gmail.com", owner_org="Sophia")

    resp = _promote(client, "sophia-agent", admin_key)

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "individual_validated"
    assert body["assurance_tier"] == "IV"
    assert body["verification_method"] == "individual"
    agent = _agent(session, "sophia-agent")
    assert agent.verified is True
    assert agent.assurance_tier == "IV"
    assert agent.verified_at is not None


def test_promotion_is_idempotent(client, session, admin_key):
    register(client, "sophia-agent")
    _promote(client, "sophia-agent", admin_key)
    first_verified_at = _agent(session, "sophia-agent").verified_at

    resp = _promote(client, "sophia-agent", admin_key)

    assert resp.status_code == 200
    assert resp.json()["status"] == "already_individual_validated"
    assert resp.json()["assurance_tier"] == "IV"
    assert _agent(session, "sophia-agent").verified_at == first_verified_at


def test_unknown_name_is_404(client, admin_key):
    assert _promote(client, "nobody-here", admin_key).status_code == 404


# ── Authorization: IV cannot be self-claimed ──


def test_anonymous_promotion_refused_and_tier_unchanged(client, session):
    register(client, "sophia-agent")

    resp = client.post(IV_URL, json={"ans_name": "sophia-agent"}, follow_redirects=False)

    # require_admin redirects unauthenticated callers to the login page.
    assert resp.status_code == 302
    agent = _agent(session, "sophia-agent")
    assert agent.verified is False
    assert agent.assurance_tier == "unverified"


def test_bad_admin_key_refused_and_tier_unchanged(client, session, admin_key):
    register(client, "sophia-agent")

    resp = client.post(
        IV_URL,
        json={"ans_name": "sophia-agent"},
        headers={"X-ANS-Admin-Key": "not-a-real-key"},
        follow_redirects=False,
    )

    assert resp.status_code == 302
    assert _agent(session, "sophia-agent").assurance_tier == "unverified"


def test_register_ignores_iv_claim_in_body(client, session):
    # The gateway still sends these fields; a direct caller could too.
    resp = register(
        client,
        "sneaky-agent",
        owner_org_kind="workspace",
        owner_validation_level="IV",
        assurance_tier="IV",
        verified=True,
    )

    assert resp.status_code == 200
    assert resp.json()["assurance_tier"] == "unverified"
    agent = _agent(session, "sneaky-agent")
    assert agent.verified is False
    assert agent.assurance_tier == "unverified"


# ── IV never overrides or shortcuts a stronger tier ──


def test_iv_does_not_downgrade_dv(client, session, admin_key):
    register(client, "acme-agent")
    verify_email(client, "acme-agent")

    resp = _promote(client, "acme-agent", admin_key)

    assert resp.status_code == 409
    assert _agent(session, "acme-agent").assurance_tier == "DV"


def test_iv_does_not_downgrade_ov(client, session, admin_key):
    register(client, "acme-agent")
    verify_email(client, "acme-agent")
    client.post(
        "/ans/verify/org", json={"ans_name": "acme-agent"}, headers={"X-ANS-Admin-Key": admin_key}
    )

    resp = _promote(client, "acme-agent", admin_key)

    assert resp.status_code == 409
    assert _agent(session, "acme-agent").assurance_tier == "OV"


def test_iv_name_cannot_be_promoted_straight_to_ov(client, session, admin_key):
    register(client, "sophia-agent")
    _promote(client, "sophia-agent", admin_key)

    resp = client.post(
        "/ans/verify/org", json={"ans_name": "sophia-agent"}, headers={"X-ANS-Admin-Key": admin_key}
    )

    assert resp.status_code == 409
    agent = _agent(session, "sophia-agent")
    assert agent.assurance_tier == "IV"
    assert agent.org_validated is False


def test_suspended_name_cannot_be_promoted(client, session, admin_key):
    register(client, "sophia-agent")
    agent = _agent(session, "sophia-agent")
    agent.status = "suspended"
    session.add(agent)
    session.commit()

    assert _promote(client, "sophia-agent", admin_key).status_code == 409
    assert _agent(session, "sophia-agent").assurance_tier == "unverified"


def test_verify_on_iv_name_reports_iv(client, admin_key):
    register(client, "sophia-agent")
    _promote(client, "sophia-agent", admin_key)

    body = verify_email(client, "sophia-agent").json()

    assert body["status"] == "already_verified"
    assert body["assurance_tier"] == "IV"
    assert body["verification_method"] == "individual"


# ── Read surfaces ──


def test_whois_reports_iv_and_certified(client, admin_key):
    register(client, "sophia-agent")
    _promote(client, "sophia-agent", admin_key)

    whois = client.get("/ans/whois/sophia-agent").json()

    assert whois["verified"] is True
    assert whois["assurance_tier"] == "IV"
    assert whois["verification_method"] == "individual"
    assert whois["agentcert"]["status"] == "certified (IV)"
    assert "registrant_email" not in whois


def test_directory_reports_iv_certified(client, admin_key):
    register(client, "sophia-agent")
    _promote(client, "sophia-agent", admin_key)

    items = client.get("/ans/directory").json()["items"]

    row = next(i for i in items if i["ans_name"] == "sophia-agent")
    assert row["assurance_tier"] == "IV"
    assert row["agentcert_status"] == "certified (IV)"


def test_stats_count_iv(client, admin_key):
    register(client, "sophia-agent")
    register(client, "other-agent")
    _promote(client, "sophia-agent", admin_key)

    by_assurance = client.get("/ans/stats").json()["by_assurance"]

    assert by_assurance["IV"] == 1
    assert by_assurance["unverified"] == 1


def _a2a(client, target, min_assurance=None):
    body = {"target_ans_name": target}
    if min_assurance is not None:
        body["min_assurance"] = min_assurance
    return client.post("/ans/a2a/verify", json=body).json()


def test_a2a_iv_meets_iv_bar(client, admin_key):
    register(client, "sophia-agent")
    _promote(client, "sophia-agent", admin_key)

    assert _a2a(client, "sophia-agent", "IV")["verified"] is True


def test_a2a_iv_does_not_meet_default_dv_bar(client, admin_key):
    register(client, "sophia-agent")
    _promote(client, "sophia-agent", admin_key)

    assert _a2a(client, "sophia-agent")["verified"] is False
    assert _a2a(client, "sophia-agent", "DV")["verified"] is False
    assert _a2a(client, "sophia-agent", "OV")["verified"] is False


def test_a2a_unknown_bar_still_means_dv(client, admin_key):
    register(client, "sophia-agent")
    _promote(client, "sophia-agent", admin_key)
    register(client, "acme-agent")
    verify_email(client, "acme-agent")

    assert _a2a(client, "sophia-agent", "bogus")["verified"] is False
    assert _a2a(client, "acme-agent", "bogus")["verified"] is True


def test_a2a_dv_and_ov_unchanged(client, admin_key):
    register(client, "acme-agent")
    verify_email(client, "acme-agent")

    assert _a2a(client, "acme-agent", "IV")["verified"] is True
    assert _a2a(client, "acme-agent", "DV")["verified"] is True
    assert _a2a(client, "acme-agent", "OV")["verified"] is False
