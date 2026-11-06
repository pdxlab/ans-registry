"""TRUS-2161 — /ans/verify says how a name was verified.

An email-verified name and a DNS-TXT-verified name both hold `assurance_tier`
DV, and the console labelled both "Domain Validated". Only the DNS path proves
domain control, so the console needs `verification_method` to label the email
path "Organization Verified". The tier code itself is unchanged.

Since TRUS-2286 email no longer verifies anything, so the email-verified names
here are ones verified before that (``verified_by_email_before``).
"""

from unittest.mock import patch

from tests.conftest import register, verified_by_email_before, verify_owner


def _verify_dns(client, ans_name):
    with patch("app.main.check_dns_txt", return_value=True):
        return client.post("/ans/verify", json={"ans_name": ans_name, "method": "dns_txt"})


def test_a_name_verified_by_email_reports_email_method(client, session):
    register(client, "acme-agent")
    verified_by_email_before(session, "acme-agent")

    body = client.post("/ans/verify", json={"ans_name": "acme-agent", "method": "email"}).json()

    assert body["status"] == "already_verified"
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
    _verify_dns(client, "acme-agent")

    # Asking again by another method reports how it was actually earned.
    body = client.post("/ans/verify", json={"ans_name": "acme-agent", "method": "email"}).json()

    assert body["status"] == "already_verified"
    assert body["assurance_tier"] == "DV"
    assert body["verification_method"] == "dns_txt"


def test_already_verified_ov_keeps_ov(client, admin_key):
    register(client, "acme-agent")
    verify_owner(client, "acme-agent")
    client.post(
        "/ans/verify/org",
        json={"ans_name": "acme-agent"},
        headers={"X-ANS-Admin-Key": admin_key},
    )

    body = verify_owner(client, "acme-agent").json()

    assert body["status"] == "already_verified"
    assert body["assurance_tier"] == "OV"
    assert body["verification_method"] == "dns_txt"


def test_failed_verify_carries_no_tier_or_method(client):
    register(client, "acme-agent", owner_email="someone@other.com", owner_domain="acme.com")

    for method in ("email", "dns_txt"):
        with patch("app.main.check_dns_txt", return_value=False):
            body = client.post("/ans/verify", json={"ans_name": "acme-agent", "method": method}).json()

        assert body["status"] in ("email_not_accepted", "dns_not_found"), method
        assert "assurance_tier" not in body
        assert "verification_method" not in body


def test_whois_and_verify_agree_on_method(client, session):
    register(client, "acme-agent")
    verified_by_email_before(session, "acme-agent")

    whois = client.get("/ans/whois/acme-agent").json()

    assert whois["verification_method"] == "email"
    assert whois["assurance_tier"] == "DV"
