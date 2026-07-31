"""HTTP-level tests for GET /ans/resolve/{name}. TRUS-1545 fix pass.

Two behaviours we care about beyond the pure-resolver tests in
``test_resolver.py``:

1. Every successful resolution appends to ``LookupLog`` — same analytics
   stream as ``/ans/lookup`` and ``/ans/whois``. Regression guard against
   the endpoint being silently anonymous.
2. The endpoint carries a per-IP rate limit — the 61st call in one minute
   from the same IP returns HTTP 429. Guards against DNS-amplification via
   caller-controlled hostnames.
"""

from sqlmodel import select

from app import resolver as resolver_mod
from app.main import limiter
from app.models import LookupLog


_CANNED_RESOLUTION = {
    "dnssec": "secure",
    "ans_record": "v=ans1; version=v1.0.0",
    "identity": {"present": True, "fingerprint": "ab" * 32},
    "trust_index": None,
}


def _stub_resolver(monkeypatch):
    """Skip real DNS — the resolver internals are exercised in test_resolver.py."""
    monkeypatch.setattr(resolver_mod, "resolve_ans_v2", lambda name: _CANNED_RESOLUTION)


def _reset_limiter():
    """slowapi's default MemoryStorage is process-wide; other test files share it."""
    limiter.reset()


def test_resolve_writes_lookup_log(client, session, monkeypatch):
    _stub_resolver(monkeypatch)
    _reset_limiter()

    name = "ans://v1.0.0.support.acme.com"
    resp = client.get(f"/ans/resolve/{name}")
    assert resp.status_code == 200, resp.text
    assert resp.json()["dnssec"] == "secure"

    rows = session.exec(select(LookupLog).where(LookupLog.ans_name == name)).all()
    assert len(rows) == 1
    assert rows[0].requester_ip  # populated (testclient sends 'testclient')


def test_resolve_rate_limited_after_60_per_minute(client, monkeypatch):
    _stub_resolver(monkeypatch)
    _reset_limiter()

    name = "ans://v1.0.0.support.acme.com"
    # 60 allowed, 61st should hit the limiter.
    for _ in range(60):
        resp = client.get(f"/ans/resolve/{name}")
        assert resp.status_code == 200, resp.text
    resp = client.get(f"/ans/resolve/{name}")
    assert resp.status_code == 429, resp.text


def test_resolve_bad_name_returns_400(client, monkeypatch):
    """ValueError from the resolver still surfaces as 400 after the fix."""
    def _raise(_):
        raise ValueError("bad name")

    monkeypatch.setattr(resolver_mod, "resolve_ans_v2", _raise)
    _reset_limiter()

    resp = client.get("/ans/resolve/not-a-valid-ans-name")
    assert resp.status_code == 400
    assert "bad name" in resp.text
