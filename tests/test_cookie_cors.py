"""
CORS allowlist + secure-cookie tests.

Exercises only the runtime configuration knobs — the underlying middleware
behavior is FastAPI/Starlette's responsibility and is already tested upstream.
"""

from __future__ import annotations

from app.config import Settings


def test_cors_default_is_wildcard():
    s = Settings()
    assert s.cors_origin_list == ["*"]


def test_cors_allowlist_parsing(monkeypatch):
    monkeypatch.setenv(
        "ANS_CORS_ORIGINS",
        "https://admin.trustmodel.ai, https://ans.predixtions.com,",
    )
    s = Settings()
    assert s.cors_origin_list == [
        "https://admin.trustmodel.ai",
        "https://ans.predixtions.com",
    ]


def test_cors_credentials_disabled_when_wildcard(monkeypatch):
    monkeypatch.setenv("ANS_CORS_ORIGINS", "*")
    s = Settings()
    # Logic mirror of what app/main.py computes.
    allow_credentials = "*" not in s.cors_origin_list
    assert allow_credentials is False


def test_cors_credentials_enabled_when_allowlisted(monkeypatch):
    monkeypatch.setenv("ANS_CORS_ORIGINS", "https://admin.trustmodel.ai")
    s = Settings()
    allow_credentials = "*" not in s.cors_origin_list
    assert allow_credentials is True


def test_session_cookie_secure_defaults_false_in_dev():
    s = Settings()
    assert s.ans_session_cookie_secure is False  # default for local dev


def test_session_cookie_secure_when_set(monkeypatch):
    monkeypatch.setenv("ANS_SESSION_COOKIE_SECURE", "true")
    s = Settings()
    assert s.ans_session_cookie_secure is True
