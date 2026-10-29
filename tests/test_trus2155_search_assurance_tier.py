"""TRUS-2155 — /ans/search returns each name's real assurance_tier.

Search carried only `verified`, so callers inferred the tier from it
(`verified ? 'DV' : 'unverified'`) and an OV name always read as DV. Search now
returns the stored `assurance_tier`, the same value /ans/lookup reports.

Also pinned here, as the ticket asks: search and lookup agree on `verified`
(the divergence this ticket was first filed against), an unverified name stays
unverified, and email verification still refuses a cross-domain claim.
"""

from tests.conftest import register, verify_email


def _search(client, **params):
    resp = client.get("/ans/search", params={"limit": 100, **params})
    assert resp.status_code == 200
    return {a["ans_name"]: a for a in resp.json()["agents"]}


def test_search_returns_each_names_true_tier(client, admin_key):
    register(client, "acme-unverified")
    register(client, "acme-dv")
    register(client, "acme-ov")
    verify_email(client, "acme-dv")
    verify_email(client, "acme-ov")
    promoted = client.post(
        "/ans/verify/org",
        json={"ans_name": "acme-ov"},
        headers={"X-ANS-Admin-Key": admin_key},
    )
    assert promoted.json()["assurance_tier"] == "OV"

    agents = _search(client)

    assert agents["acme-unverified"]["assurance_tier"] == "unverified"
    assert agents["acme-dv"]["assurance_tier"] == "DV"
    assert agents["acme-ov"]["assurance_tier"] == "OV"


def test_search_and_lookup_agree(client, admin_key):
    for name in ("acme-unverified", "acme-dv", "acme-ov"):
        register(client, name)
    verify_email(client, "acme-dv")
    verify_email(client, "acme-ov")
    client.post(
        "/ans/verify/org",
        json={"ans_name": "acme-ov"},
        headers={"X-ANS-Admin-Key": admin_key},
    )

    agents = _search(client)

    for name, row in agents.items():
        owner = client.get(f"/ans/lookup/{name}").json()["owner"]
        assert row["verified"] == owner["verified"], name
        assert row["assurance_tier"] == owner["assurance_tier"], name


def test_existing_search_fields_unchanged(client):
    register(client, "acme-agent")

    row = _search(client)["acme-agent"]

    for key in (
        "ans_id",
        "name",
        "ans_name",
        "owner",
        "verified",
        "type",
        "trust_score",
        "trust_tier",
    ):
        assert key in row


def test_unverified_name_stays_unverified_and_uncounted(client):
    register(client, "acme-agent")

    row = _search(client)["acme-agent"]

    assert row["verified"] is False
    assert row["assurance_tier"] == "unverified"
    assert "acme-agent" not in _search(client, verified_only=True)


def test_cross_domain_email_claim_is_refused(client):
    register(client, "acme-agent", owner_email="someone@other.com", owner_domain="acme.com")

    resp = verify_email(client, "acme-agent")

    assert resp.status_code == 200  # failures are 200 + status (see ticket)
    assert resp.json()["status"] == "email_mismatch"
    assert "assurance_tier" not in resp.json()
    row = _search(client)["acme-agent"]
    assert row["verified"] is False
    assert row["assurance_tier"] == "unverified"
