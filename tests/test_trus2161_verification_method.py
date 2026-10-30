"""TRUS-2161 — /ans/verify says how a name was verified.

An email-verified name and a DNS-TXT-verified name both hold `assurance_tier`
DV, and the console labelled both "Domain Validated". Only the DNS path proves
domain control, so the console needs `verification_method` to label the email
path "Organization Verified". The tier code itself is unchanged.
"""

from unittest.mock import patch

from tests.conftest import register, verify_email


def _verify_dns(client, ans_name):
    with patch("app.main.check_dns_txt", return_value=True):
        return client.post("/ans/verify", json={"ans_name": ans_name, "method": "dns_txt"})


def test_email_verify_reports_email_method(client):
    register(client, "acme-agent")

    body = verify_email(client, "acme-agent").json()

    assert body["status"] == "verified"
    assert body["assurance_tier"] == "DV"
    assert body["verification_method"] == "email"


def test_dns_verify_reports_dns_method(client):
    register(client, "acme-agent")

    body = _verify_dns(client, "acme-agent").json()

    assert body["status"] == "verified"
    assert body["assurance_tier"] == "DV"
    assert body["verification_method"] == "dns_txt"


def test_already_verified_carries_tier_and_original_method(client):
    register(client, "acme-agent")
    verify_email(client, "acme-agent")

    # Re-verifying by another method must report how it was actually earned.
    body = _verify_dns(client, "acme-agent").json()

    assert body["status"] == "already_verified"
    assert body["assurance_tier"] == "DV"
    assert body["verification_method"] == "email"


def test_already_verified_ov_keeps_ov(client, admin_key):
    register(client, "acme-agent")
    verify_email(client, "acme-agent")
    client.post(
        "/ans/verify/org",
        json={"ans_name": "acme-agent"},
        headers={"X-ANS-Admin-Key": admin_key},
    )

    body = verify_email(client, "acme-agent").json()

    assert body["assurance_tier"] == "OV"
    assert body["verification_method"] == "email"


def test_failed_verify_carries_no_tier_or_method(client):
    register(client, "acme-agent", owner_email="someone@other.com", owner_domain="acme.com")

    body = verify_email(client, "acme-agent").json()

    assert body["status"] == "email_mismatch"
    assert "assurance_tier" not in body
    assert "verification_method" not in body


def test_whois_and_verify_agree_on_method(client):
    register(client, "acme-agent")
    verify_email(client, "acme-agent")

    whois = client.get("/ans/whois/acme-agent").json()

    assert whois["verification_method"] == "email"
    assert whois["assurance_tier"] == "DV"
