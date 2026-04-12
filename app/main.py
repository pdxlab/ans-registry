"""
ANS Registry — Agent Naming Service API
========================================
DNS + SSL for AI Agents.

Endpoints:
  POST /ans/register         — Register a new agent
  GET  /ans/lookup/{name}    — Look up an agent (WHOIS for agents)
  POST /ans/verify           — Verify ownership via DNS or email
  POST /ans/transfer         — Initiate ownership transfer
  POST /ans/transfer/accept  — Accept a transfer
  GET  /ans/search           — Search agents
  GET  /ans/stats            — Registry statistics
  GET  /ans/cert/{name}      — View TrustScore certificate
"""

import re
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlmodel import Session, select

from .database import create_db, get_session
from .models import Agent, Transfer, LookupLog
from .verification import (
    generate_verification_token,
    check_dns_txt,
    verify_email_domain,
    calculate_trust_score,
)

app = FastAPI(
    title="ANS — Agent Naming Service",
    description="DNS + SSL for AI Agents. Register, verify, and certify AI agents.",
    version="1.0.0",
    docs_url="/docs",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    create_db()


# ── Request/Response Models ──


class RegisterRequest(BaseModel):
    ans_name: str  # unique agent name (lowercase, alphanumeric + hyphens)
    display_name: str
    owner_org: str
    owner_email: str
    owner_domain: Optional[str] = ""
    agent_type: str = "mcp_server"  # mcp_server | standalone | browser | api
    description: str = ""
    capabilities: str = ""  # comma-separated tool names
    model_used: str = ""
    data_access: str = ""
    source_url: str = ""


class RegisterResponse(BaseModel):
    ans_id: str
    ans_name: str
    verification_token: str
    verification_instructions: str
    trust_score: float
    trust_tier: str
    status: str


class VerifyRequest(BaseModel):
    ans_name: str
    method: str = "email"  # "dns_txt" | "email"


class TransferRequest(BaseModel):
    ans_name: str
    from_email: str  # current owner confirms
    to_org: str
    to_email: str
    to_domain: str = ""


class TransferAcceptRequest(BaseModel):
    transfer_token: str
    to_email: str  # new owner confirms


# ── Validation ──


def validate_ans_name(name: str) -> str:
    """Validate ANS name: lowercase, alphanumeric, hyphens, 3-63 chars."""
    name = name.lower().strip()
    if not re.match(r'^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$', name):
        raise HTTPException(
            status_code=400,
            detail="ANS name must be 3-63 characters, lowercase alphanumeric and hyphens only, "
                   "cannot start or end with a hyphen."
        )
    return name


# ── Endpoints ──


@app.post("/ans/register", response_model=RegisterResponse)
def register_agent(req: RegisterRequest, session: Session = Depends(get_session)):
    """Register a new AI agent in the ANS registry."""

    ans_name = validate_ans_name(req.ans_name)

    # Check uniqueness
    existing = session.exec(select(Agent).where(Agent.ans_name == ans_name)).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"ANS name '{ans_name}' is already registered.")

    # Calculate initial TrustScore
    score, tier = calculate_trust_score(
        req.agent_type, False, req.capabilities, req.source_url, req.description
    )

    # Create agent
    token = generate_verification_token()
    agent = Agent(
        ans_name=ans_name,
        display_name=req.display_name,
        owner_org=req.owner_org,
        owner_email=req.owner_email,
        owner_domain=req.owner_domain or req.owner_email.split("@")[-1],
        agent_type=req.agent_type,
        description=req.description,
        capabilities=req.capabilities,
        model_used=req.model_used,
        data_access=req.data_access,
        source_url=req.source_url,
        verification_token=token,
        trust_score=score,
        trust_tier=tier,
        trust_evaluated_at=datetime.utcnow(),
        trust_cert_url=f"https://trustmodel.ai/ans/cert/{ans_name}",
    )

    session.add(agent)
    session.commit()
    session.refresh(agent)

    domain = agent.owner_domain
    instructions = (
        f"To verify ownership, add this DNS TXT record:\n"
        f"  _ans-verify.{domain}  TXT  \"{token}\"\n\n"
        f"Or verify via email: call POST /ans/verify with method='email' "
        f"and we'll check that your email domain matches {domain}.\n\n"
        f"After verification, your TrustScore will increase and you'll "
        f"receive a 'Verified Owner' badge."
    )

    return RegisterResponse(
        ans_id=f"ans://{ans_name}.trustmodel.ai",
        ans_name=ans_name,
        verification_token=token,
        verification_instructions=instructions,
        trust_score=score,
        trust_tier=tier,
        status="registered",
    )


@app.get("/ans/lookup/{ans_name}")
def lookup_agent(ans_name: str, request: Request, session: Session = Depends(get_session)):
    """Look up an agent — WHOIS for AI agents. Free, no auth needed."""

    ans_name = ans_name.lower().strip()
    agent = session.exec(select(Agent).where(Agent.ans_name == ans_name)).first()

    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{ans_name}' not found in ANS registry.")

    # Log lookup
    log = LookupLog(ans_name=ans_name, requester_ip=request.client.host if request.client else "")
    session.add(log)
    session.commit()

    return {
        "ans_id": f"ans://{agent.ans_name}.trustmodel.ai",
        "name": agent.display_name,
        "ans_name": agent.ans_name,
        "owner": {
            "organization": agent.owner_org,
            "verified": agent.verified,
            "domain": agent.owner_domain,
            "verification_method": agent.verification_method if agent.verified else None,
            "registered": agent.registered_at.isoformat(),
        },
        "agent_type": agent.agent_type,
        "description": agent.description,
        "capabilities": [c.strip() for c in agent.capabilities.split(",") if c.strip()],
        "model": agent.model_used,
        "data_access": agent.data_access,
        "source_url": agent.source_url,
        "trust": {
            "score": agent.trust_score,
            "tier": agent.trust_tier,
            "evaluated_at": agent.trust_evaluated_at.isoformat() if agent.trust_evaluated_at else None,
            "certificate": agent.trust_cert_url,
            "badge_url": f"https://trustmodel.ai/badge/ans/{agent.ans_name}.svg",
        },
        "status": agent.status,
        "orphan_risk": agent.orphan_risk,
        "detailed_eval_url": "https://trustmodel.ai/developers",
    }


@app.post("/ans/verify")
def verify_agent(req: VerifyRequest, session: Session = Depends(get_session)):
    """Verify agent ownership via DNS TXT record or email domain match."""

    agent = session.exec(select(Agent).where(Agent.ans_name == req.ans_name.lower())).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found.")

    if agent.verified:
        return {"status": "already_verified", "message": "This agent is already verified."}

    verified = False

    if req.method == "dns_txt":
        verified = check_dns_txt(agent.owner_domain, agent.verification_token)
        if not verified:
            return {
                "status": "dns_not_found",
                "message": f"TXT record not found. Add this record and try again:",
                "record": f"_ans-verify.{agent.owner_domain}  TXT  \"{agent.verification_token}\"",
            }
    elif req.method == "email":
        verified = verify_email_domain(agent.owner_email, agent.owner_domain)
        if not verified:
            return {
                "status": "email_mismatch",
                "message": f"Email domain '{agent.owner_email.split('@')[-1]}' doesn't match claimed domain '{agent.owner_domain}'.",
            }

    if verified:
        agent.verified = True
        agent.verification_method = req.method
        agent.verified_at = datetime.utcnow()

        # Recalculate TrustScore with verification boost
        score, tier = calculate_trust_score(
            agent.agent_type, True, agent.capabilities, agent.source_url, agent.description
        )
        agent.trust_score = score
        agent.trust_tier = tier
        agent.trust_evaluated_at = datetime.utcnow()
        agent.updated_at = datetime.utcnow()

        session.add(agent)
        session.commit()

        return {
            "status": "verified",
            "message": f"Agent '{agent.ans_name}' is now verified. Owner: {agent.owner_org}",
            "trust_score": score,
            "trust_tier": tier,
            "badge_url": f"https://trustmodel.ai/badge/ans/{agent.ans_name}.svg",
        }

    return {"status": "failed", "message": "Verification failed."}


@app.post("/ans/transfer")
def initiate_transfer(req: TransferRequest, session: Session = Depends(get_session)):
    """Initiate ownership transfer — like a domain transfer."""

    agent = session.exec(select(Agent).where(Agent.ans_name == req.ans_name.lower())).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found.")

    if agent.owner_email.lower() != req.from_email.lower():
        raise HTTPException(status_code=403, detail="Only the current owner can initiate a transfer.")

    # Create transfer record
    transfer = Transfer(
        agent_id=agent.id,
        ans_name=agent.ans_name,
        from_org=agent.owner_org,
        from_email=agent.owner_email,
        to_org=req.to_org,
        to_email=req.to_email,
        to_domain=req.to_domain or req.to_email.split("@")[-1],
    )

    session.add(transfer)
    session.commit()
    session.refresh(transfer)

    return {
        "status": "pending",
        "transfer_id": transfer.id,
        "transfer_token": transfer.transfer_token,
        "message": f"Transfer initiated. The new owner ({req.to_email}) must accept by calling POST /ans/transfer/accept with the transfer_token.",
        "from": {"org": transfer.from_org, "email": transfer.from_email},
        "to": {"org": transfer.to_org, "email": transfer.to_email},
    }


@app.post("/ans/transfer/accept")
def accept_transfer(req: TransferAcceptRequest, session: Session = Depends(get_session)):
    """Accept an ownership transfer — new owner confirms."""

    transfer = session.exec(
        select(Transfer).where(
            Transfer.transfer_token == req.transfer_token,
            Transfer.status == "pending",
        )
    ).first()

    if not transfer:
        raise HTTPException(status_code=404, detail="Transfer not found or already completed.")

    if transfer.to_email.lower() != req.to_email.lower():
        raise HTTPException(status_code=403, detail="Email doesn't match the intended recipient.")

    # Update agent ownership
    agent = session.exec(select(Agent).where(Agent.id == transfer.agent_id)).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found.")

    agent.owner_org = transfer.to_org
    agent.owner_email = transfer.to_email
    agent.owner_domain = transfer.to_domain
    agent.verified = False  # New owner must re-verify
    agent.verification_token = generate_verification_token()
    agent.updated_at = datetime.utcnow()

    transfer.status = "completed"
    transfer.completed_at = datetime.utcnow()

    session.add(agent)
    session.add(transfer)
    session.commit()

    return {
        "status": "completed",
        "message": f"Ownership of '{agent.ans_name}' transferred to {transfer.to_org}.",
        "new_owner": {"org": transfer.to_org, "email": transfer.to_email},
        "note": "New owner should verify ownership via POST /ans/verify to restore verified status.",
        "verification_token": agent.verification_token,
    }


@app.get("/ans/search")
def search_agents(
    q: str = Query("", description="Search by name, org, or description"),
    agent_type: Optional[str] = None,
    verified_only: bool = False,
    min_score: float = 0,
    limit: int = 20,
    session: Session = Depends(get_session),
):
    """Search the ANS registry."""

    query = select(Agent).where(Agent.status == "active")

    if q:
        query = query.where(
            (Agent.ans_name.contains(q.lower())) |
            (Agent.display_name.contains(q)) |
            (Agent.owner_org.contains(q)) |
            (Agent.description.contains(q))
        )

    if agent_type:
        query = query.where(Agent.agent_type == agent_type)

    if verified_only:
        query = query.where(Agent.verified == True)

    if min_score > 0:
        query = query.where(Agent.trust_score >= min_score)

    query = query.limit(limit)
    agents = session.exec(query).all()

    return {
        "count": len(agents),
        "agents": [
            {
                "ans_id": f"ans://{a.ans_name}.trustmodel.ai",
                "name": a.display_name,
                "ans_name": a.ans_name,
                "owner": a.owner_org,
                "verified": a.verified,
                "type": a.agent_type,
                "trust_score": a.trust_score,
                "trust_tier": a.trust_tier,
            }
            for a in agents
        ],
    }


@app.get("/ans/stats")
def registry_stats(session: Session = Depends(get_session)):
    """Public registry statistics."""

    all_agents = session.exec(select(Agent)).all()
    verified = [a for a in all_agents if a.verified]
    scored = [a for a in all_agents if a.trust_score]
    avg_score = sum(a.trust_score for a in scored) / len(scored) if scored else 0

    return {
        "total_registered": len(all_agents),
        "verified": len(verified),
        "average_trust_score": round(avg_score, 1),
        "by_type": {
            t: len([a for a in all_agents if a.agent_type == t])
            for t in set(a.agent_type for a in all_agents)
        },
        "by_tier": {
            t: len([a for a in all_agents if a.trust_tier == t])
            for t in ["Highly Trusted", "Generally Safe", "Use With Caution", "High Risk"]
        },
    }


@app.get("/ans/cert/{ans_name}")
def view_certificate(ans_name: str, session: Session = Depends(get_session)):
    """View the TrustScore certificate for an agent."""

    agent = session.exec(select(Agent).where(Agent.ans_name == ans_name.lower())).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found.")

    return {
        "certificate": {
            "ans_id": f"ans://{agent.ans_name}.trustmodel.ai",
            "agent": agent.display_name,
            "owner": agent.owner_org,
            "verified": agent.verified,
            "trust_score": agent.trust_score,
            "trust_tier": agent.trust_tier,
            "evaluated_at": agent.trust_evaluated_at.isoformat() if agent.trust_evaluated_at else None,
            "valid_until": "90 days from evaluation",
            "badge_url": f"https://trustmodel.ai/badge/ans/{agent.ans_name}.svg",
            "badge_markdown": f"[![ANS Verified](https://trustmodel.ai/badge/ans/{agent.ans_name}.svg)](https://trustmodel.ai/ans/cert/{agent.ans_name})",
        },
        "detailed_evaluation": "https://trustmodel.ai/developers",
        "methodology": "https://trustmodel.ai/terms-of-service",
    }


@app.get("/")
def root():
    return {
        "service": "ANS — Agent Naming Service",
        "description": "DNS + SSL for AI Agents",
        "version": "1.0.0",
        "endpoints": {
            "register": "POST /ans/register",
            "lookup": "GET /ans/lookup/{agent-name}",
            "verify": "POST /ans/verify",
            "transfer": "POST /ans/transfer",
            "accept_transfer": "POST /ans/transfer/accept",
            "search": "GET /ans/search?q=...",
            "stats": "GET /ans/stats",
            "certificate": "GET /ans/cert/{agent-name}",
        },
        "website": "https://trustmodel.ai/ans",
        "docs": "/docs",
    }
