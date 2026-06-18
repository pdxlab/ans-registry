"""
Health probe tests — /health/live, /health/ready, /health.
"""

from __future__ import annotations


def test_liveness_returns_ok(client):
    """Liveness never touches the DB; must always be 200."""
    resp = client.get("/health/live")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_readiness_ok_against_seeded_db(client):
    """Readiness performs SELECT 1; with an in-memory DB this must be 200."""
    resp = client.get("/health/ready")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ready"


def test_verbose_health_payload_shape(client):
    """The /health endpoint exposes service + DB info."""
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "ans-registry"
    assert body["status"] == "ok"
    assert body["database"]["ok"] is True
    assert body["database"]["reason"] is None
    assert "version" in body
    assert isinstance(body["uptime_seconds"], int)
    assert body["uptime_seconds"] >= 0


def test_readiness_503_when_db_unavailable(monkeypatch, client):
    """If the DB SELECT 1 raises, readiness must return 503."""
    from app import health

    def boom(self, *_args, **_kwargs):  # mimic Session.exec signature
        raise RuntimeError("simulated db outage")

    # Patch Session.exec so the readiness probe fails — covers the 503 branch.
    from sqlmodel import Session
    monkeypatch.setattr(Session, "exec", boom)

    resp = client.get("/health/ready")
    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "not-ready"
    assert body["reason"] == "database"
    assert body["detail"] == "RuntimeError"
