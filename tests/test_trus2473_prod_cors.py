"""
TRUS-2473 — Azure prod ANS rejected every browser preflight.

deploy-azure-prod.yml read ANS_CORS_ORIGINS from a repo variable that was
never created, so prod ran with ANS_CORS_ORIGINS="" -> an empty allowlist ->
Starlette answers the preflight 400 with no Access-Control-Allow-Origin, and
app.trustmodel.ai/app/ans fails on POST /ans/verify.

These tests drive the real CORSMiddleware with the config app/main.py builds,
so they assert what a browser actually sees, not just the parsed setting.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient

from app.config import Settings, settings
from app.main import app, cors_middleware_kwargs, warn_if_cors_allowlist_empty

PROD_ORIGIN = "https://app.trustmodel.ai"
WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/deploy-azure-prod.yml"


def _prod_settings(monkeypatch, cors_value: str) -> Settings:
    # Synthetic values only — non-dev Settings requires a DSN and a secret.
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.setenv("ANS_DATABASE_URL", "sqlite://")
    monkeypatch.setenv("ANS_SESSION_SECRET", "test-only-not-a-secret")
    monkeypatch.setenv("ANS_CORS_ORIGINS", cors_value)
    return Settings()


def _client(s: Settings) -> TestClient:
    probe = FastAPI()
    probe.add_middleware(CORSMiddleware, **cors_middleware_kwargs(s))

    @probe.post("/ans/verify")
    def _verify():
        return {"ok": True}

    return TestClient(probe)


def _preflight(client: TestClient, origin: str):
    return client.options(
        "/ans/verify",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )


def _workflow_cors_value() -> str:
    m = re.search(r'"ANS_CORS_ORIGINS=([^"]*)"', WORKFLOW.read_text())
    assert m, "ANS_CORS_ORIGINS not found in deploy-azure-prod.yml"
    return m.group(1)


# ── The value prod deploys ──────────────────────────────────────────────────

def test_prod_workflow_pins_cors_as_literal():
    """Fails on the pre-fix workflow, which read `${{ vars.ANS_CORS_ORIGINS_PROD }}`."""
    value = _workflow_cors_value()
    assert "${{" not in value, "ANS_CORS_ORIGINS must not depend on a repo variable"
    assert PROD_ORIGIN in [o.strip() for o in value.split(",")]


def test_prod_workflow_value_is_not_a_wildcard():
    assert "*" not in _workflow_cors_value()


def test_prod_workflow_value_passes_real_preflight(monkeypatch):
    s = _prod_settings(monkeypatch, _workflow_cors_value())
    r = _preflight(_client(s), PROD_ORIGIN)
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] == PROD_ORIGIN
    assert r.headers["access-control-allow-credentials"] == "true"


# ── Middleware behaviour ────────────────────────────────────────────────────

def test_app_uses_the_tested_cors_config():
    """The probe-app tests below only mean something if the real app is wired
    from the same helper. Fails if app.main hand-writes its CORS kwargs."""
    cors = [m for m in app.user_middleware if m.cls is CORSMiddleware]
    assert len(cors) == 1
    assert cors[0].kwargs == cors_middleware_kwargs(settings)


def test_empty_allowlist_rejects_preflight(monkeypatch):
    """Reproduces the prod bug: what ANS_CORS_ORIGINS="" did to the browser."""
    s = _prod_settings(monkeypatch, "")
    r = _preflight(_client(s), PROD_ORIGIN)
    assert r.status_code == 400
    assert "access-control-allow-origin" not in r.headers


@pytest.mark.parametrize(
    "origin",
    [
        "https://evil.example",
        "https://app.trustmodel.ai.evil.example",  # suffix trick
        "http://app.trustmodel.ai",                 # scheme downgrade
        "https://trustmodel.pdxqa.com",             # QA origin must not reach prod
        "null",
    ],
)
def test_unlisted_origins_are_rejected(monkeypatch, origin):
    s = _prod_settings(monkeypatch, PROD_ORIGIN)
    r = _preflight(_client(s), origin)
    assert r.status_code == 400
    assert "access-control-allow-origin" not in r.headers


def test_simple_request_from_unlisted_origin_gets_no_acao(monkeypatch):
    s = _prod_settings(monkeypatch, PROD_ORIGIN)
    r = _client(s).post("/ans/verify", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in r.headers


def test_disallowed_header_is_rejected(monkeypatch):
    s = _prod_settings(monkeypatch, PROD_ORIGIN)
    r = _client(s).options(
        "/ans/verify",
        headers={
            "Origin": PROD_ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "x-organization-id",
        },
    )
    assert r.status_code == 400


# ── Startup signal ──────────────────────────────────────────────────────────

def test_empty_allowlist_logs_error_outside_dev(monkeypatch, caplog):
    s = _prod_settings(monkeypatch, "")
    with caplog.at_level(logging.ERROR, logger="app.main"):
        warn_if_cors_allowlist_empty(s)
    assert any("ANS_CORS_ORIGINS is empty" in r.getMessage() for r in caplog.records)


def test_populated_allowlist_logs_nothing(monkeypatch, caplog):
    s = _prod_settings(monkeypatch, PROD_ORIGIN)
    with caplog.at_level(logging.ERROR, logger="app.main"):
        warn_if_cors_allowlist_empty(s)
    assert not caplog.records


def test_empty_allowlist_in_development_logs_nothing(monkeypatch, caplog):
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("ANS_CORS_ORIGINS", "")
    with caplog.at_level(logging.ERROR, logger="app.main"):
        warn_if_cors_allowlist_empty(Settings())
    assert not caplog.records
