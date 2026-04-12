"""
ANS Registry — Data Models
"""

import uuid
from datetime import datetime
from typing import Optional
from sqlmodel import SQLModel, Field


class Agent(SQLModel, table=True):
    """A registered AI agent in the ANS registry."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    ans_name: str = Field(unique=True, index=True, max_length=100)  # e.g. "salesforce-einstein-crm"
    display_name: str = Field(max_length=255)  # e.g. "Salesforce Einstein CRM Agent"

    # Owner
    owner_org: str = Field(max_length=255)  # e.g. "Salesforce, Inc."
    owner_email: str = Field(max_length=255)
    owner_domain: str = Field(default="", max_length=255)  # e.g. "salesforce.com"

    # Verification
    verified: bool = Field(default=False)
    verification_method: str = Field(default="")  # "dns_txt" | "email" | "manual"
    verification_token: str = Field(default_factory=lambda: f"ans-verify-{uuid.uuid4().hex[:16]}")
    verified_at: Optional[datetime] = None

    # Agent details
    agent_type: str = Field(default="mcp_server")  # mcp_server | standalone | browser | api
    description: str = Field(default="", max_length=1000)
    capabilities: str = Field(default="")  # comma-separated tool names
    model_used: str = Field(default="")  # e.g. "gpt-4o", "claude-3.5"
    data_access: str = Field(default="")  # e.g. "CRM read-write, Analytics read-only"
    source_url: str = Field(default="")  # GitHub repo or homepage

    # Trust
    trust_score: Optional[float] = None
    trust_tier: str = Field(default="Unscored")
    trust_evaluated_at: Optional[datetime] = None
    trust_cert_url: str = Field(default="")

    # Status
    status: str = Field(default="active")  # active | suspended | orphan | revoked
    orphan_risk: str = Field(default="none")  # none | low | medium | high

    # Metadata
    registered_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class Transfer(SQLModel, table=True):
    """Ownership transfer record."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    agent_id: str = Field(foreign_key="agent.id")
    ans_name: str

    # From
    from_org: str
    from_email: str

    # To
    to_org: str
    to_email: str
    to_domain: str = Field(default="")

    # Status
    status: str = Field(default="pending")  # pending | accepted | rejected | completed
    transfer_token: str = Field(default_factory=lambda: f"ans-xfer-{uuid.uuid4().hex[:16]}")

    initiated_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None


class LookupLog(SQLModel, table=True):
    """Log of ANS lookups (analytics)."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    ans_name: str
    requester_ip: str = Field(default="")
    looked_up_at: datetime = Field(default_factory=datetime.utcnow)
