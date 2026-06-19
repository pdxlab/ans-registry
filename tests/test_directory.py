"""
Endpoint tests for the public AgentCert directory:
  TRUS-1284 — GET /ans/directory (list every agent holding an AgentCert)
"""

from .conftest import register, verify_email


def test_directory_empty(client):
    resp = client.get("/ans/directory")
    assert resp.status_code == 200
    body = resp.json()
    # No agents registered → no certs.
    assert body["total"] == 0
    assert body["count"] == 0
    assert body["items"] == []


def test_directory_lists_certified_agents(client):
    # Every registered agent gets an initial TrustScore eval → holds a cert.
    register(client, "acme-sales-agent", owner_org="Acme Inc.", owner_email="ai@acme.com")
    resp = client.get("/ans/directory")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["count"] == 1
    item = body["items"][0]
    assert item["ans_name"] == "acme-sales-agent"
    assert item["owner_org"] == "Acme Inc."
    assert item["assurance_tier"] == "unverified"
    assert item["cert_status"] == "active"
    assert item["agentcert_status"] == "scored (unverified)"
    assert item["trust_score"] is not None
    assert item["certified_at"] is not None
    assert item["registered_at"] is not None
    assert item["ans_id"] == "ans://acme-sales-agent.trustmodel.ai"


def test_directory_reflects_dv_tier_after_verification(client):
    register(client, "acme-sales-agent", owner_email="ai@acme.com")
    verify_email(client, "acme-sales-agent")
    item = client.get("/ans/directory").json()["items"][0]
    assert item["assurance_tier"] == "DV"
    assert item["agentcert_status"] == "certified (DV)"


def test_directory_search_by_name_and_org(client):
    register(client, "acme-sales-agent", owner_org="Acme Inc.", owner_email="ai@acme.com")
    register(client, "globex-support-bot", owner_org="Globex Corp.", owner_email="ai@globex.com")

    # Search by agent-name substring.
    body = client.get("/ans/directory?q=sales").json()
    names = [i["ans_name"] for i in body["items"]]
    assert names == ["acme-sales-agent"]
    assert body["total"] == 1

    # Search by org substring (case-insensitive).
    body = client.get("/ans/directory?q=globex").json()
    names = [i["ans_name"] for i in body["items"]]
    assert names == ["globex-support-bot"]


def test_directory_sort_by_score_desc_default(client):
    # A verified agent scores higher than an unverified one.
    register(client, "high-agent", owner_email="ai@acme.com")
    verify_email(client, "high-agent")
    register(client, "low-agent", owner_email="ai@acme.com")  # email mismatch → stays unverified

    items = client.get("/ans/directory").json()["items"]
    scores = [i["trust_score"] for i in items]
    # Default sort is score desc.
    assert scores == sorted(scores, reverse=True)
    assert items[0]["ans_name"] == "high-agent"


def test_directory_min_score_filter(client):
    register(client, "high-agent", owner_email="ai@acme.com")
    verify_email(client, "high-agent")
    high = client.get("/ans/directory").json()["items"][0]["trust_score"]

    # min_score above the only agent's score → no rows.
    body = client.get(f"/ans/directory?min_score={high + 1}").json()
    assert body["total"] == 0
    assert body["items"] == []


def test_directory_pagination(client):
    for i in range(5):
        register(client, f"agent-{i}", owner_email="ai@acme.com")

    page1 = client.get("/ans/directory?limit=2&offset=0").json()
    assert page1["total"] == 5
    assert page1["count"] == 2
    assert page1["limit"] == 2
    assert page1["offset"] == 0

    page2 = client.get("/ans/directory?limit=2&offset=2").json()
    assert page2["count"] == 2

    page3 = client.get("/ans/directory?limit=2&offset=4").json()
    assert page3["count"] == 1

    # No overlap across pages.
    seen = {i["ans_name"] for i in page1["items"]} | {i["ans_name"] for i in page2["items"]}
    assert all(i["ans_name"] not in seen for i in page3["items"])


def test_directory_sort_recent(client):
    register(client, "first-agent", owner_email="ai@acme.com")
    register(client, "second-agent", owner_email="ai@acme.com")
    items = client.get("/ans/directory?sort=recent").json()["items"]
    # Most recently certified first.
    assert items[0]["ans_name"] == "second-agent"
