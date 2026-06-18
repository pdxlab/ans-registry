"""
ANS assurance tiers + namespace integrity.

Two concerns live here:

1. Assurance tiers (TRUS-1257) — the DV/OV-style identity assurance that
   AgentCert builds on top of. Domain control (DNS TXT or matching email
   domain) earns DV; an additional manual org review earns OV.

2. Namespace integrity (TRUS-1259) — orphan detection (names whose owners
   have gone dark / can no longer prove control) and typosquat detection
   (lookalike names that target an existing registered name via small edit
   distance or homoglyph swaps).
"""

from datetime import datetime, timedelta
from typing import Optional

# ── Assurance tiers (TRUS-1257) ──

TIER_UNVERIFIED = "unverified"
TIER_DV = "DV"  # domain validated
TIER_OV = "OV"  # organization validated

# Methods that prove domain control and therefore earn at least DV.
DOMAIN_CONTROL_METHODS = {"dns_txt", "email"}


def compute_assurance_tier(verified: bool, verification_method: str,
                           org_validated: bool) -> str:
    """
    Derive the assurance tier from verification state.

      unverified — no proof of domain control
      DV         — domain control proven (DNS TXT or matching email domain)
      OV         — DV plus a confirmed legal organization (manual review)
    """
    if verified and verification_method in DOMAIN_CONTROL_METHODS:
        if org_validated:
            return TIER_OV
        return TIER_DV
    return TIER_UNVERIFIED


# ── Orphan detection (TRUS-1259) ──

# An agent is treated as at risk of being orphaned when it was never verified
# (no proven owner) or has not been re-attested for a long time. Mirrors the
# "abandoned domain" problem in DNS.
ORPHAN_STALE_AFTER = timedelta(days=365)
ORPHAN_WARN_AFTER = timedelta(days=180)


def assess_orphan_risk(verified: bool,
                       verified_at: Optional[datetime],
                       updated_at: Optional[datetime],
                       now: Optional[datetime] = None) -> str:
    """
    Classify orphan risk: none | low | medium | high.

    - Unverified agents are at least medium risk (no proven owner at all).
    - Verified agents decay toward orphan status if they go un-touched: an
      attestation older than ORPHAN_WARN_AFTER is low, older than
      ORPHAN_STALE_AFTER is high.
    """
    now = now or datetime.utcnow()

    if not verified:
        # Never proved ownership. If it's also gone stale, escalate.
        last_touch = updated_at or now
        if now - last_touch > ORPHAN_STALE_AFTER:
            return "high"
        return "medium"

    anchor = verified_at or updated_at
    if anchor is None:
        return "low"

    age = now - anchor
    if age > ORPHAN_STALE_AFTER:
        return "high"
    if age > ORPHAN_WARN_AFTER:
        return "low"
    return "none"


# ── Typosquat detection (TRUS-1259) ──

# Common homoglyph / lookalike substitutions used to mimic a registered name.
# Each maps a character to a set of characters it is commonly confused with.
_HOMOGLYPHS = {
    "0": {"o"}, "o": {"0"},
    "1": {"l", "i"}, "l": {"1", "i"}, "i": {"1", "l"},
    "5": {"s"}, "s": {"5"},
    "3": {"e"}, "e": {"3"},
    "rn": {"m"},  # handled separately below
}


def levenshtein(a: str, b: str) -> int:
    """Classic Levenshtein edit distance (insertions/deletions/substitutions)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            current.append(min(
                previous[j] + 1,       # deletion
                current[j - 1] + 1,    # insertion
                previous[j - 1] + cost  # substitution
            ))
        previous = current
    return previous[-1]


def _homoglyph_normalize(name: str) -> str:
    """
    Fold a name to a canonical form by collapsing common homoglyphs, so that
    e.g. 'salesf0rce' and 'salesforce' map to the same skeleton.
    """
    name = name.lower()
    # Multi-char confusable first: 'rn' -> 'm'.
    name = name.replace("rn", "m")
    out = []
    canon = {"0": "o", "1": "l", "i": "l", "5": "s", "3": "e"}
    for ch in name:
        out.append(canon.get(ch, ch))
    return "".join(out)


def is_typosquat(candidate: str, target: str, max_distance: int = 1) -> bool:
    """
    True if `candidate` looks like a typosquat of `target`.

    A name is flagged when it is not identical to the target but either:
      - within `max_distance` Levenshtein edits, or
      - identical after homoglyph normalization (lookalike-character swap).
    """
    candidate = candidate.lower().strip()
    target = target.lower().strip()
    if not candidate or not target or candidate == target:
        return False

    # Homoglyph skeleton match (e.g. salesf0rce vs salesforce).
    if _homoglyph_normalize(candidate) == _homoglyph_normalize(target):
        return True

    # Small edit distance, but only meaningful for names of comparable length
    # (avoid flagging short substrings of long names).
    if abs(len(candidate) - len(target)) <= max_distance:
        if levenshtein(candidate, target) <= max_distance:
            return True

    return False


def find_typosquats(candidate: str, registered_names, max_distance: int = 1):
    """
    Given a candidate name and an iterable of registered names, return the list
    of registered names that `candidate` appears to be squatting on.
    """
    hits = []
    for name in registered_names:
        if is_typosquat(candidate, name, max_distance=max_distance):
            hits.append(name)
    return hits
