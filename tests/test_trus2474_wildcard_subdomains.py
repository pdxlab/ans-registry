"""
TRUS-2474 — tenant subdomain origins for ANS.

TRUS-2473 pinned prod to the single exact origin https://app.trustmodel.ai and
left tenant subdomains out as a separate decision. Starlette compares
``allow_origins`` by exact string, so ``https://*.trustmodel.ai`` cannot simply
be added to the list — it needs ``allow_origin_regex``.

These tests drive the real CORSMiddleware through the same
``cors_middleware_kwargs`` the app ships with, so they assert what a browser
sees. The helpers come from the TRUS-2473 module rather than being copied.
"""

from __future__ import annotations

import logging
import re

import pytest

from app.config import Settings
from app.main import (
    cors_middleware_kwargs,
    warn_if_cors_allowlist_empty,
    warn_if_cors_wildcards_inert,
)
from tests.test_trus2473_prod_cors import (
    PROD_ORIGIN,
    _client,
    _preflight,
    _prod_settings,
    _workflow_cors_value,
)

WILDCARD = "https://*.trustmodel.ai"
STATIC_HOST = "https://stpdxprod23b578.z19.web.core.windows.net"
BOTH = f"{PROD_ORIGIN},{WILDCARD},{STATIC_HOST}"

# aurora-gateway settings/common.py tenant_origin_regexes(["trustmodel.ai"]).
# ANS must accept exactly the same hosts aurora does.
AURORA_REGEX = r"^https://[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.trustmodel\.ai$"


# ── The compiled pattern ────────────────────────────────────────────────────

def test_wildcard_compiles_to_auroras_regex(monkeypatch):
    s = _prod_settings(monkeypatch, WILDCARD)
    assert s.cors_origin_regex == AURORA_REGEX


def test_wildcard_entry_is_not_left_in_the_exact_list(monkeypatch):
    """A literal "https://*.trustmodel.ai" in allow_origins would never match."""
    s = _prod_settings(monkeypatch, BOTH)
    assert s.cors_origin_list == [PROD_ORIGIN, STATIC_HOST]


def test_no_wildcard_means_no_regex(monkeypatch):
    s = _prod_settings(monkeypatch, PROD_ORIGIN)
    assert s.cors_origin_regex is None


# ── Origins that must be allowed ────────────────────────────────────────────

@pytest.mark.parametrize(
    "origin",
    [
        "https://acme.trustmodel.ai",
        "https://app.trustmodel.ai",
        "https://a.trustmodel.ai",
        "https://tenant-with-hyphens.trustmodel.ai",
        "https://" + "a" * 63 + ".trustmodel.ai",
    ],
)
def test_tenant_subdomains_pass_preflight(monkeypatch, origin):
    s = _prod_settings(monkeypatch, BOTH)
    r = _preflight(_client(s), origin)
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] == origin


def test_exact_entries_still_work_alongside_the_wildcard(monkeypatch):
    """The Azure static host is not a trustmodel.ai subdomain, so it proves
    allow_origins and allow_origin_regex compose rather than replace."""
    s = _prod_settings(monkeypatch, BOTH)
    r = _preflight(_client(s), STATIC_HOST)
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] == STATIC_HOST


# ── Origins that must still be rejected ─────────────────────────────────────

@pytest.mark.parametrize(
    "origin",
    [
        "https://app.trustmodel.ai.evil.example",   # suffix trick
        "https://evil.example/app.trustmodel.ai",   # prefix trick
        "https://a.b.trustmodel.ai",                # nested label
        "https://trustmodel.ai",                    # apex is not a subdomain
        "http://acme.trustmodel.ai",                # scheme downgrade
        "https://-acme.trustmodel.ai",              # label cannot lead with -
        "https://acme-.trustmodel.ai",              # ...or end with one
        "https://acme.trustmodelXai",               # base must be escaped
        "https://acme.trustmodel.ai:8443",          # port is part of the origin
        "https://ACME.trustmodel.ai",               # regex is lowercase-only
        "https://evil.example",
        "null",
    ],
)
def test_lookalike_origins_are_rejected(monkeypatch, origin):
    s = _prod_settings(monkeypatch, WILDCARD)
    r = _preflight(_client(s), origin)
    assert r.status_code == 400
    assert "access-control-allow-origin" not in r.headers


def test_regex_is_anchored_at_both_ends(monkeypatch):
    """Starlette uses fullmatch today; the anchors keep this safe if that ever
    becomes match(), which would otherwise allow any suffix."""
    s = _prod_settings(monkeypatch, WILDCARD)
    pattern = re.compile(s.cors_origin_regex)
    assert pattern.match("https://acme.trustmodel.ai.evil.example") is None


# ── Interaction with the TRUS-2473 allow-all and empty-list rules ───────────

def test_bare_star_sets_no_regex_and_drops_credentials(monkeypatch):
    s = _prod_settings(monkeypatch, "*")
    kwargs = cors_middleware_kwargs(s)
    assert kwargs["allow_origin_regex"] is None
    assert kwargs["allow_credentials"] is False


def test_wildcard_only_allowlist_is_not_reported_as_empty(monkeypatch, caplog):
    """cors_origin_list is [] for a wildcard-only value, which must not trip
    the TRUS-2473 empty-allowlist error."""
    s = _prod_settings(monkeypatch, WILDCARD)
    with caplog.at_level(logging.ERROR):
        warn_if_cors_allowlist_empty(s)
    assert "ANS_CORS_ORIGINS is empty" not in caplog.text


def test_truly_empty_allowlist_still_logs(monkeypatch, caplog):
    s = _prod_settings(monkeypatch, "")
    with caplog.at_level(logging.ERROR):
        warn_if_cors_allowlist_empty(s)
    assert "ANS_CORS_ORIGINS is empty" in caplog.text


# ── What prod actually deploys ──────────────────────────────────────────────

def test_prod_workflow_ships_the_wildcard():
    assert WILDCARD in [o.strip() for o in _workflow_cors_value().split(",")]


def test_prod_workflow_value_allows_a_tenant_host(monkeypatch):
    s = _prod_settings(monkeypatch, _workflow_cors_value())
    r = _preflight(_client(s), "https://acme.trustmodel.ai")
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] == "https://acme.trustmodel.ai"


# ── Credentials stay off ────────────────────────────────────────────────────

def test_matched_tenant_origin_gets_no_credentials(monkeypatch):
    """The wildcard must not extend *credentialed* CORS to sibling subdomains.

    ANS admin authenticates with the ambient `ans_admin_session` cookie, and
    SameSite=Lax does not stop a same-site request — every `*.trustmodel.ai`
    host is the same site as ANS, so the browser attaches it. With credentials
    echoed back, any tenant page could read `/admin/*` as the logged-in admin.
    Without the header the browser discards the response, so a matched origin
    can read only what is already public.

    The admin writes themselves are now blocked by `require_same_origin`
    (TRUS-2475); this stays as the other half of the defence.
    """
    s = _prod_settings(monkeypatch, BOTH)
    r = _preflight(_client(s), "https://acme.trustmodel.ai")
    assert r.status_code == 200
    assert "access-control-allow-credentials" not in r.headers


@pytest.mark.parametrize("value", [PROD_ORIGIN, WILDCARD, BOTH, "*", ""])
def test_credentials_are_never_enabled(monkeypatch, value):
    s = _prod_settings(monkeypatch, value)
    assert cors_middleware_kwargs(s)["allow_credentials"] is False


# ── Wildcard entries that match nothing ─────────────────────────────────────

@pytest.mark.parametrize(
    "value",
    [
        "http://*.trustmodel.ai",   # https only
        "*.trustmodel.ai",          # no scheme
        "https://*trustmodel.ai",   # missing the dot
    ],
)
def test_inert_wildcards_are_detected(monkeypatch, value):
    s = _prod_settings(monkeypatch, value)
    assert s.cors_origin_regex is None
    assert s.cors_inert_wildcards == [value]


def test_inert_wildcard_is_logged(monkeypatch, caplog):
    s = _prod_settings(monkeypatch, f"{PROD_ORIGIN},http://*.trustmodel.ai")
    with caplog.at_level(logging.ERROR):
        warn_if_cors_wildcards_inert(s)
    assert "match nothing" in caplog.text
    assert "http://*.trustmodel.ai" in caplog.text


def test_supported_wildcard_is_not_flagged(monkeypatch, caplog):
    s = _prod_settings(monkeypatch, BOTH)
    assert s.cors_inert_wildcards == []
    with caplog.at_level(logging.ERROR):
        warn_if_cors_wildcards_inert(s)
    assert caplog.text == ""


def test_bare_star_is_not_flagged_as_inert(monkeypatch):
    """The bare "*" is the documented allow-all, not a typo."""
    s = _prod_settings(monkeypatch, "*")
    assert s.cors_inert_wildcards == []
