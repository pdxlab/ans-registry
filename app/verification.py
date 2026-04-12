"""
Agent ownership verification — DNS TXT + email fallback.
"""

import dns.resolver
import logging
import secrets
import smtplib
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)


def generate_verification_token() -> str:
    """Generate a unique verification token."""
    return f"ans-verify-{secrets.token_hex(16)}"


def check_dns_txt(domain: str, expected_token: str) -> bool:
    """
    Check if a DNS TXT record contains the ANS verification token.

    The agent owner adds a TXT record to their domain:
      _ans-verify.salesforce.com  TXT  "ans-verify-abc123..."

    Similar to how Let's Encrypt verifies domain ownership.
    """
    try:
        record_name = f"_ans-verify.{domain}"
        answers = dns.resolver.resolve(record_name, "TXT")
        for rdata in answers:
            txt_value = rdata.to_text().strip('"')
            if txt_value == expected_token:
                return True
        return False
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return False
    except Exception as e:
        logger.error(f"DNS verification error for {domain}: {e}")
        return False


def verify_email_domain(email: str, claimed_domain: str) -> bool:
    """
    Simple check: does the email domain match the claimed org domain?
    e.g., ai-ops@salesforce.com matches salesforce.com
    """
    email_domain = email.split("@")[-1].lower()
    claimed = claimed_domain.lower()

    # Direct match
    if email_domain == claimed:
        return True

    # Subdomain match (e.g., engineering.salesforce.com)
    if email_domain.endswith(f".{claimed}"):
        return True

    return False


def calculate_trust_score(agent_type: str, verified: bool, capabilities: str,
                          source_url: str, description: str) -> tuple:
    """
    Calculate a basic TrustScore for a newly registered agent.
    Full evaluation requires the TrustModel evaluation engine (separate service).
    This is a lightweight estimate based on registration data.
    """
    score = 5.0  # base

    # Verification boost
    if verified:
        score += 1.5

    # Source code available
    if source_url and ("github.com" in source_url or "gitlab.com" in source_url):
        score += 1.0

    # Description quality
    if len(description) > 100:
        score += 0.5

    # Agent type risk adjustment
    type_adjustments = {
        "mcp_server": 0,
        "standalone": -0.5,
        "browser": -0.3,
        "api": 0.2,
    }
    score += type_adjustments.get(agent_type, 0)

    # Capability count (more tools = more risk)
    tool_count = len([c for c in capabilities.split(",") if c.strip()])
    if tool_count <= 3:
        score += 0.5
    elif tool_count > 10:
        score -= 0.5

    score = round(min(10.0, max(1.0, score)), 1)

    if score >= 8.0:
        tier = "Highly Trusted"
    elif score >= 6.0:
        tier = "Generally Safe"
    elif score >= 4.0:
        tier = "Use With Caution"
    else:
        tier = "High Risk"

    return score, tier
