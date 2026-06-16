"""
Endpoint tests for the AgentCert ANS features:
  TRUS-1257 — registration + org/domain verification + DV/OV tiers
  TRUS-1258 — WHOIS-for-agents lookup
  TRUS-1259 — a2a verify + orphan/typosquat detection
"""

from .conftest import register, verify_email


# ── TRUS-1257: registration + assurance tiers ──

def test_register_starts_unverified(client):
    resp = register(client, "acme-sales-agent")
    assert resp.status_code == 200
    body = resp.json()
    assert body["assurance_tier"] == "unverified"
    assert body["status"] == "registered"
    assert body["typosquat_warning"] is None


def test_email_verification_earns_dv(client):
    register(client, "acme-sales-agent", owner_email="ai@acme.com")
    resp = verify_email(client, "acme-sales-agent")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "verified"
    assert body["assurance_tier"] == "DV"


def test_org_validation_requires_dv_first(client, admin_key):
    register(client, "acme-sales-agent")
    # Not yet domain-verified → OV should be rejected.
    resp = client.post(
        "/ans/verify/org",
        json={"ans_name": "acme-sales-agent"},
        headers={"X-ANS-Admin-Key": admin_key},
    )
    assert resp.status_code == 409


def test_org_validation_promotes_to_ov(client, admin_key):
    register(client, "acme-sales-agent", owner_email="ai@acme.com")
    verify_email(client, "acme-sales-agent")
    resp = client.post(
        "/ans/verify/org",
        json={"ans_name": "acme-sales-agent"},
        headers={"X-ANS-Admin-Key": admin_key},
    )
    assert resp.status_code == 200
    assert resp.json()["assurance_tier"] == "OV"


def test_org_validation_requires_admin(client):
    register(client, "acme-sales-agent")
    verify_email(client, "acme-sales-agent")
    # require_admin raises a 302 redirect to /admin/login when unauthenticated;
    # don't follow it so we observe the auth gate rather than the login page.
    resp = client.post(
        "/ans/verify/org",
        json={"ans_name": "acme-sales-agent"},
        follow_redirects=False,
    )
    assert resp.status_code in (302, 401, 403)
    # And the agent must NOT have been promoted to OV.
    assert client.get("/ans/whois/acme-sales-agent").json()["assurance_tier"] == "DV"


def test_register_flags_typosquat(client):
    register(client, "salesforce-bot", owner_email="ai@salesforce.com")
    # Lookalike using zero-for-o.
    resp = register(client, "salesf0rce-bot", owner_email="evil@bad.com")
    assert resp.status_code == 200
    assert resp.json()["typosquat_warning"] is not None
    assert "salesforce-bot" in resp.json()["typosquat_warning"]


# ── TRUS-1258: WHOIS-for-agents ──

def test_whois_unknown_is_404(client):
    assert client.get("/ans/whois/nope").status_code == 404


def test_whois_returns_record(client):
    register(client, "acme-sales-agent", owner_org="Acme Inc.", owner_email="ai@acme.com")
    resp = client.get("/ans/whois/acme-sales-agent")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ans_name"] == "acme-sales-agent"
    assert body["registrant_org"] == "Acme Inc."
    assert body["assurance_tier"] == "unverified"
    assert body["agentcert"]["status"] == "scored (unverified)"


def test_whois_agentcert_status_after_verification(client):
    register(client, "acme-sales-agent", owner_email="ai@acme.com")
    verify_email(client, "acme-sales-agent")
    body = client.get("/ans/whois/acme-sales-agent").json()
    assert body["agentcert"]["status"] == "certified (DV)"


# ── TRUS-1259: a2a verify ──

def test_a2a_verify_unverified_fails_dv_bar(client):
    register(client, "acme-sales-agent")
    resp = client.post("/ans/a2a/verify", json={"target_ans_name": "acme-sales-agent"})
    body = resp.json()
    assert body["verified"] is False
    assert body["result"] == "unverified"


def test_a2a_verify_passes_when_dv(client):
    register(client, "acme-sales-agent", owner_email="ai@acme.com")
    verify_email(client, "acme-sales-agent")
    resp = client.post(
        "/ans/a2a/verify",
        json={"target_ans_name": "acme-sales-agent", "caller_ans_name": "buyer-bot"},
    )
    body = resp.json()
    assert body["verified"] is True
    assert body["assurance_tier"] == "DV"


def test_a2a_verify_ov_bar_rejects_dv_only(client, admin_key):
    register(client, "acme-sales-agent", owner_email="ai@acme.com")
    verify_email(client, "acme-sales-agent")
    resp = client.post(
        "/ans/a2a/verify",
        json={"target_ans_name": "acme-sales-agent", "min_assurance": "OV"},
    )
    assert resp.json()["verified"] is False


def test_a2a_verify_unknown_name(client):
    resp = client.post("/ans/a2a/verify", json={"target_ans_name": "ghost-agent"})
    body = resp.json()
    assert body["verified"] is False
    assert body["result"] == "not_found"


def test_a2a_verify_flags_typosquat_target(client):
    register(client, "salesforce-bot", owner_email="ai@salesforce.com")
    resp = client.post("/ans/a2a/verify", json={"target_ans_name": "salesf0rce-bot"})
    body = resp.json()
    assert body["verified"] is False
    assert body["result"] == "typosquat_warning"
    assert "salesforce-bot" in body["resembles"]


# ── TRUS-1259: typosquat + orphan endpoints ──

def test_typosquats_endpoint(client):
    register(client, "salesforce-bot", owner_email="ai@salesforce.com")
    register(client, "salesf0rce-bot", owner_email="evil@bad.com")
    resp = client.get("/ans/typosquats/salesforce-bot")
    body = resp.json()
    assert body["registered"] is True
    assert "salesf0rce-bot" in body["typosquats"]


def test_orphans_endpoint_lists_unverified(client):
    register(client, "abandoned-agent")
    resp = client.get("/ans/orphans?min_risk=medium")
    body = resp.json()
    names = [o["ans_name"] for o in body["orphans"]]
    assert "abandoned-agent" in names
    # Unverified agents are at least medium orphan risk.
    risks = {o["ans_name"]: o["orphan_risk"] for o in body["orphans"]}
    assert risks["abandoned-agent"] in ("medium", "high")


def test_verified_agent_not_in_orphans(client):
    register(client, "live-agent", owner_email="ai@acme.com")
    verify_email(client, "live-agent")
    resp = client.get("/ans/orphans?min_risk=low")
    names = [o["ans_name"] for o in resp.json()["orphans"]]
    assert "live-agent" not in names


# ── stats reflects assurance tiers ──

def test_stats_includes_assurance_breakdown(client):
    register(client, "a-agent", owner_email="ai@acme.com")
    verify_email(client, "a-agent")
    resp = client.get("/ans/stats")
    body = resp.json()
    assert body["by_assurance"]["DV"] == 1
    assert body["by_assurance"]["unverified"] == 0
