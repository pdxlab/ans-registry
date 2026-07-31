"""Unit tests for ANS v2 resolution — pure parts (no DNS). TRUS-1545."""
import pytest

from app import resolver as resolver_mod
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


class _FakeResponse:
    def __init__(self, ad_flag: bool):
        # dns.flags.AD == 0x20 in dnspython. Mirroring the bit here keeps the
        # unit test independent of the dnspython constant value.
        self.flags = 0x20 if ad_flag else 0


def test_dnssec_resolvers_from_env(monkeypatch):
    monkeypatch.setenv("ANS_DNSSEC_RESOLVERS", "1.2.3.4, 5.6.7.8 ,")
    assert resolver_mod._dnssec_resolvers() == ["1.2.3.4", "5.6.7.8"]


def test_dnssec_resolvers_default(monkeypatch):
    monkeypatch.delenv("ANS_DNSSEC_RESOLVERS", raising=False)
    assert resolver_mod._dnssec_resolvers() == ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


def test_dnssec_status_falls_back_to_secondary(monkeypatch):
    """First resolver times out; second answers with AD set → secure."""
    calls = []

    def fake_udp(_query, resolver_ip, timeout):
        calls.append(resolver_ip)
        if resolver_ip == "1.1.1.1":
            raise TimeoutError("simulated timeout")
        return _FakeResponse(ad_flag=True)

    monkeypatch.setenv("ANS_DNSSEC_RESOLVERS", "1.1.1.1,8.8.8.8,9.9.9.9")
    monkeypatch.setattr(resolver_mod.dns.query, "udp", fake_udp)

    assert resolver_mod._dnssec_status("_ans.example.com") == "secure"
    # Stops at the first responsive resolver.
    assert calls == ["1.1.1.1", "8.8.8.8"]


def test_dnssec_status_unknown_when_all_fail(monkeypatch):
    def always_fail(_q, _r, timeout):
        raise TimeoutError("simulated")

    monkeypatch.setenv("ANS_DNSSEC_RESOLVERS", "1.1.1.1,8.8.8.8")
    monkeypatch.setattr(resolver_mod.dns.query, "udp", always_fail)

    assert resolver_mod._dnssec_status("_ans.example.com") == "unknown"


def test_dnssec_status_insecure_short_circuits(monkeypatch):
    """An answer without the AD flag is a substantive result — don't retry."""
    calls = []

    def fake_udp(_q, resolver_ip, timeout):
        calls.append(resolver_ip)
        return _FakeResponse(ad_flag=False)

    monkeypatch.setenv("ANS_DNSSEC_RESOLVERS", "1.1.1.1,8.8.8.8")
    monkeypatch.setattr(resolver_mod.dns.query, "udp", fake_udp)

    assert resolver_mod._dnssec_status("_ans.example.com") == "insecure"
    assert calls == ["1.1.1.1"]
