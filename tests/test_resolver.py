"""Unit tests for ANS v2 resolution — pure parts (no DNS). TRUS-1545."""
import pytest

from app.resolver import build_resolution, parse_ans_v2


def test_parse_valid():
    assert parse_ans_v2("ans://v1.0.0.support.acme.com") == ("1.0.0", "support.acme.com")
    # trims + lowercases the host
    assert parse_ans_v2("  ans://v2.3.4.Bot.Example.CO.UK ") == ("2.3.4", "bot.example.co.uk")


@pytest.mark.parametrize(
    "bad",
    [
        "support.acme.com",  # no scheme
        "ans://support.acme.com",  # no version
        "ans://v1.0.support.acme.com",  # version not MAJOR.MINOR.PATCH
        "ans://v1.0.0.localhost",  # single-label host
        "ans://v1.0.0.",  # missing host
    ],
)
def test_parse_invalid(bad):
    with pytest.raises(ValueError):
        parse_ans_v2(bad)


def test_build_resolution_with_badge():
    r = build_resolution(
        ans_record="v=ans1; version=v1.0.0",
        badge="https://api.trustmodel.ai/v1/verify/ans%3A%2F%2Fv1.0.0.a.example.com/receipt/",
        tlsa={"present": True, "fingerprint": "ab" * 32},
        dnssec="secure",
    )
    assert r["dnssec"] == "secure"
    assert r["identity"]["present"] is True
    assert r["trust_index"]["badge_url"].endswith("/receipt/")
    assert r["trust_index"]["trustscore"] is None


def test_build_resolution_no_badge():
    r = build_resolution(ans_record=None, badge=None, tlsa={"present": False}, dnssec="insecure")
    assert r["trust_index"] is None
    assert r["ans_record"] is None
