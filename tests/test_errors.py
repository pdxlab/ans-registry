"""
Tests for request-id middleware and JSON error envelope.
"""

from __future__ import annotations

from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.main import app
from app.database import get_session


def test_request_id_header_echoed_back(client):
    """Client-supplied X-Request-ID must be echoed back unchanged."""
    rid = "test-fixed-rid-1234"
    resp = client.get("/health/live", headers={"X-Request-ID": rid})
    assert resp.status_code == 200
    assert resp.headers["X-Request-ID"] == rid


def test_request_id_generated_when_absent(client):
    """When the client omits X-Request-ID, the server must generate one."""
    resp = client.get("/health/live")
    rid = resp.headers.get("X-Request-ID")
    assert rid
    assert len(rid) >= 16  # uuid4 hex


def test_http_exception_returns_envelope(client):
    """An HTTPException is wrapped in the structured error envelope."""
    resp = client.get("/admin/lookup/nope")  # 404 from registered route
    # /admin/lookup doesn't exist → FastAPI 404 → HTTPException handler
    assert resp.status_code == 404
    body = resp.json()
    assert "error" in body
    assert body["error"]["code"] == 404
    assert "request_id" in body["error"]


def test_unhandled_exception_returns_generic_500(session):
    """An unhandled exception in a route handler must produce a generic 500
    body — never leak the traceback to the client."""

    # Register a route that always raises a non-HTTPException.
    @app.get("/__boom_test__")
    def _boom():
        raise RuntimeError("don't show this to clients")

    def get_session_override():
        return session

    app.dependency_overrides[get_session] = get_session_override
    try:
        # raise_server_exceptions=False lets the handler catch & format the 500
        # instead of TestClient re-raising the original error.
        c = TestClient(app, raise_server_exceptions=False)
        resp = c.get("/__boom_test__")
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 500
    body = resp.json()
    assert body["error"]["code"] == 500
    assert body["error"]["message"] == "internal error"
    # Never leak the original message:
    assert "don't show this to clients" not in resp.text
