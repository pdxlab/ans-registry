"""ANS v2 (DNS-anchored) resolution — TRUS-1545 backend.

Resolves a Linux Foundation ANS v2 name ``ans://v<semver>.<agentHost-FQDN>``
against DNS: reads the ``_ans`` / ``_ans-badge`` TXT records and the
``_ans-identity._tls`` TLSA record under the owner's host, and reports DNSSEC
status (the AD flag from a validating resolver). The Trust Index scores live at
the ``_ans-badge`` target (the agent's TrustModel receipt), so this resolver
returns the badge URL and leaves score enrichment to the caller.

Returns the shape the console's ``ansV2Service.resolveV2`` expects
(``Omit<ResolvedAnsV2, 'name' | 'resolved_at'>``):

    { dnssec, ans_record?, identity: {present, fingerprint?}, trust_index? }
"""
from __future__ import annotations

import re

import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver

_SCHEME = "ans://"
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_HOST_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)

# A DNSSEC-validating resolver used only to read the Authenticated Data flag.
_VALIDATING_RESOLVER = "1.1.1.1"


def parse_ans_v2(name: str) -> tuple[str, str]:
    """Parse ``ans://v<semver>.<host>`` → (version, host). Raises ``ValueError``."""
    s = (name or "").strip()
    if not s.lower().startswith(_SCHEME):
        raise ValueError(f'ANS v2 name must start with "{_SCHEME}": {name}')
    body = s[len(_SCHEME):]
    if body[:1].lower() != "v" or "." not in body:
        raise ValueError(f"invalid ANS v2 name (expected ans://v<version>.<host>): {name}")
    parts = body[1:].split(".")
    if len(parts) < 4:
        raise ValueError(f"invalid ANS v2 name (missing host after version): {name}")
    version = ".".join(parts[:3])
    host = ".".join(parts[3:]).lower()
    if not _VERSION_RE.match(version):
        raise ValueError(f'invalid ANS v2 version "{version}" (expected MAJOR.MINOR.PATCH)')
    if not _HOST_RE.match(host):
        raise ValueError(f'invalid ANS v2 host "{host}"')
    return version, host


def _txt(name: str) -> str | None:
    try:
        answers = dns.resolver.resolve(name, "TXT")
    except Exception:
        return None
    for rr in answers:
        parts = [s.decode("utf-8", "replace") if isinstance(s, bytes) else s for s in rr.strings]
        if parts:
            return "".join(parts)
    return None


def _tlsa(name: str) -> dict:
    try:
        answers = dns.resolver.resolve(name, "TLSA")
    except Exception:
        return {"present": False}
    rr = next(iter(answers), None)
    if rr is None:
        return {"present": False}
    data = getattr(rr, "cert", None)
    return {"present": True, "fingerprint": data.hex() if isinstance(data, (bytes, bytearray)) else None}


def _dnssec_status(qname: str) -> str:
    """Return 'secure' when a validating resolver marks the answer Authenticated."""
    try:
        query = dns.message.make_query(dns.name.from_text(qname), dns.rdatatype.TXT, want_dnssec=True)
        response = dns.query.udp(query, _VALIDATING_RESOLVER, timeout=5)
        return "secure" if (response.flags & dns.flags.AD) else "insecure"
    except Exception:
        return "unknown"


def build_resolution(*, ans_record: str | None, badge: str | None, tlsa: dict, dnssec: str) -> dict:
    """Assemble the resolution payload (pure — unit-testable without DNS)."""
    trust_index = {"trustscore": None, "badge_url": badge} if badge else None
    return {
        "dnssec": dnssec,
        "ans_record": ans_record,
        "identity": tlsa,
        "trust_index": trust_index,
    }


def resolve_ans_v2(ans_name: str) -> dict:
    """Resolve an ANS v2 name against DNS. Raises ``ValueError`` on a bad name."""
    _version, host = parse_ans_v2(ans_name)
    return build_resolution(
        ans_record=_txt(f"_ans.{host}"),
        badge=_txt(f"_ans-badge.{host}"),
        tlsa=_tlsa(f"_ans-identity._tls.{host}"),
        dnssec=_dnssec_status(f"_ans.{host}"),
    )
