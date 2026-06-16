"""
Unit tests for the assurance module: tier computation, orphan risk, and
typosquat detection (TRUS-1257 / TRUS-1259).
"""

from datetime import datetime, timedelta

from app.assurance import (
    compute_assurance_tier,
    assess_orphan_risk,
    is_typosquat,
    find_typosquats,
    levenshtein,
    TIER_UNVERIFIED,
    TIER_DV,
    TIER_OV,
)


# ── Assurance tiers ──

def test_unverified_when_not_verified():
    assert compute_assurance_tier(False, "", False) == TIER_UNVERIFIED


def test_dv_on_domain_control():
    assert compute_assurance_tier(True, "dns_txt", False) == TIER_DV
    assert compute_assurance_tier(True, "email", False) == TIER_DV


def test_ov_requires_org_validation_on_top_of_dv():
    assert compute_assurance_tier(True, "dns_txt", True) == TIER_OV


def test_manual_method_without_domain_control_is_unverified():
    # 'manual' is not a domain-control method, so it can't earn DV by itself.
    assert compute_assurance_tier(True, "manual", False) == TIER_UNVERIFIED


# ── Orphan risk ──

def test_unverified_agent_is_at_least_medium_risk():
    now = datetime(2026, 6, 15)
    assert assess_orphan_risk(False, None, now, now=now) == "medium"


def test_unverified_and_stale_is_high_risk():
    now = datetime(2026, 6, 15)
    old = now - timedelta(days=400)
    assert assess_orphan_risk(False, None, old, now=now) == "high"


def test_recently_verified_is_no_risk():
    now = datetime(2026, 6, 15)
    recent = now - timedelta(days=10)
    assert assess_orphan_risk(True, recent, recent, now=now) == "none"


def test_verified_but_stale_attestation_decays():
    now = datetime(2026, 6, 15)
    assert assess_orphan_risk(True, now - timedelta(days=200), None, now=now) == "low"
    assert assess_orphan_risk(True, now - timedelta(days=400), None, now=now) == "high"


# ── Typosquat detection ──

def test_levenshtein_basic():
    assert levenshtein("acme", "acme") == 0
    assert levenshtein("acme", "acme-bot") == 4
    assert levenshtein("salesforce", "salesfource") == 1


def test_edit_distance_typosquat():
    assert is_typosquat("salesforce-bot", "salesforce-bot") is False  # identical
    assert is_typosquat("salesforce-bo", "salesforce-bot")  # one deletion
    assert is_typosquat("salesforce-bott", "salesforce-bot")  # one insertion


def test_homoglyph_typosquat():
    # zero-for-o and one-for-l lookalikes resolve to the same skeleton.
    assert is_typosquat("salesf0rce", "salesforce")
    assert is_typosquat("paypa1", "paypal")


def test_rn_to_m_homoglyph():
    assert is_typosquat("modern-bot".replace("m", "rn"), "modern-bot")


def test_not_a_typosquat_for_distinct_names():
    assert is_typosquat("weather-agent", "salesforce-bot") is False


def test_find_typosquats_returns_all_hits():
    registered = ["salesforce-bot", "weather-agent", "salesf0rce-bot"]
    hits = find_typosquats("salesforce-bot", registered)
    # both the homoglyph variant matches; the identical name is excluded
    assert "salesf0rce-bot" in hits
    assert "salesforce-bot" not in hits
    assert "weather-agent" not in hits
