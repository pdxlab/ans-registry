"""
ANS Registry — Agent Naming Service API
========================================
DNS + SSL for AI Agents.

Endpoints:
  POST /ans/register         — Register a new agent (with org/domain assurance)
  GET  /ans/lookup/{name}    — Look up an agent (WHOIS for agents)
  GET  /ans/whois/{name}     — WHOIS-for-agents record (owner/tier/cert status)
  POST /ans/verify           — Verify ownership via DNS or email
  POST /ans/verify/org       — Org-validate (OV tier) — admin only
  POST /ans/a2a/verify       — Agent-to-agent verification
  GET  /ans/typosquats/{name}— Typosquat candidates targeting a name
  GET  /ans/orphans          — Orphaned / orphan-risk names
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

from .admin import router as admin_router
from .admin_auth import router as auth_router
from .auth import seed_superadmin, AdminUser, require_admin
from .database import create_db, get_session, engine
from .models import Agent, Transfer, LookupLog, A2AVerificationLog
from .verification import (
    generate_verification_token,
    check_dns_txt,
    verify_email_domain,
    calculate_trust_score,
)
from .assurance import (
    compute_assurance_tier,
    assess_orphan_risk,
    find_typosquats,
    TIER_DV,
    TIER_OV,
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


app.include_router(admin_router)
app.include_router(auth_router)

@app.on_event("startup")
def on_startup():
    create_db()
    # Seed Karl as superadmin on first startup
    from sqlmodel import Session
    with Session(engine) as session:
        seed_superadmin(session)


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
    assurance_tier: str
    status: str
    typosquat_warning: Optional[str] = None  # set if name resembles a registered one


class OrgValidateRequest(BaseModel):
    ans_name: str


class A2AVerifyRequest(BaseModel):
    target_ans_name: str  # the agent being verified
    caller_ans_name: str = ""  # the agent making the request (optional)
    min_assurance: str = "DV"  # "unverified" | "DV" | "OV"


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

    # Flag (but don't block) names that resemble existing registered names —
    # protects established orgs against lookalike squatting at registration time.
    registered_names = session.exec(select(Agent.ans_name)).all()
    squat_hits = find_typosquats(ans_name, registered_names)
    typosquat_warning = None
    if squat_hits:
        typosquat_warning = (
            f"'{ans_name}' closely resembles existing registered name(s): "
            f"{', '.join(squat_hits)}. Flagged for review."
        )

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
        assurance_tier=compute_assurance_tier(False, "", False),  # unverified at registration
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
        assurance_tier=agent.assurance_tier,
        status="registered",
        typosquat_warning=typosquat_warning,
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
            "assurance_tier": agent.assurance_tier,
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


@app.get("/ans/whois/{ans_name}")
def whois_agent(ans_name: str, request: Request, session: Session = Depends(get_session)):
    """
    WHOIS-for-agents — TRUS-1258.

    A compact, registry-style record resolving an agent name to its owning org,
    registration date, verification/assurance tier, and AgentCert status.
    Public, no auth — the agent equivalent of a `whois` query.
    """
    ans_name = ans_name.lower().strip()
    agent = session.exec(select(Agent).where(Agent.ans_name == ans_name)).first()

    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{ans_name}' not found in ANS registry.")

    # Log the lookup (same analytics stream as /ans/lookup).
    log = LookupLog(ans_name=ans_name, requester_ip=request.client.host if request.client else "")
    session.add(log)
    session.commit()

    # AgentCert status is derived from assurance tier + a current TrustScore cert.
    has_cert = agent.trust_score is not None and agent.trust_evaluated_at is not None
    if agent.assurance_tier in (TIER_DV, TIER_OV) and has_cert:
        agentcert_status = f"certified ({agent.assurance_tier})"
    elif has_cert:
        agentcert_status = "scored (unverified)"
    else:
        agentcert_status = "none"

    return {
        "ans_name": agent.ans_name,
        "ans_id": f"ans://{agent.ans_name}.trustmodel.ai",
        "display_name": agent.display_name,
        "registrant_org": agent.owner_org,
        "registrant_domain": agent.owner_domain,
        "registrant_email": agent.owner_email,
        "verified": agent.verified,
        "assurance_tier": agent.assurance_tier,  # unverified | DV | OV
        "verification_method": agent.verification_method if agent.verified else None,
        "registered_at": agent.registered_at.isoformat(),
        "updated_at": agent.updated_at.isoformat(),
        "verified_at": agent.verified_at.isoformat() if agent.verified_at else None,
        "status": agent.status,
        "orphan_risk": agent.orphan_risk,
        "agentcert": {
            "status": agentcert_status,
            "trust_score": agent.trust_score,
            "trust_tier": agent.trust_tier,
            "evaluated_at": agent.trust_evaluated_at.isoformat() if agent.trust_evaluated_at else None,
            "certificate_url": agent.trust_cert_url,
        },
        "registry": "ANS — Agent Naming Service",
    }


@app.post("/ans/a2a/verify")
def a2a_verify(req: A2AVerifyRequest, request: Request, session: Session = Depends(get_session)):
    """
    Agent-to-agent verification — TRUS-1259.

    One agent asks ANS whether another agent is who it claims to be, and
    whether it meets a minimum assurance bar before connecting. Returns a
    clear pass/fail plus the target's record and any typosquat warning.
    """
    target_name = req.target_ans_name.lower().strip()
    tier_rank = {"unverified": 0, TIER_DV: 1, TIER_OV: 2}
    required = tier_rank.get(req.min_assurance, 1)

    agent = session.exec(select(Agent).where(Agent.ans_name == target_name)).first()

    requester_ip = request.client.host if request.client else ""

    if not agent:
        # Unknown name — surface whether it looks like a squat on a real name,
        # which is a strong "do not connect" signal for the caller.
        registered_names = session.exec(select(Agent.ans_name)).all()
        squat_hits = find_typosquats(target_name, registered_names)
        result = "typosquat_warning" if squat_hits else "not_found"
        session.add(A2AVerificationLog(
            caller_ans_name=req.caller_ans_name.lower().strip(),
            target_ans_name=target_name,
            result=result,
            requester_ip=requester_ip,
        ))
        session.commit()
        return {
            "verified": False,
            "result": result,
            "target_ans_name": target_name,
            "message": (
                f"'{target_name}' is not registered but resembles: {', '.join(squat_hits)}. "
                f"Do not connect."
                if squat_hits else
                f"'{target_name}' is not registered in ANS."
            ),
            "resembles": squat_hits or None,
        }

    actual = tier_rank.get(agent.assurance_tier, 0)
    meets_bar = agent.verified and actual >= required
    result = "verified" if meets_bar else "unverified"

    session.add(A2AVerificationLog(
        caller_ans_name=req.caller_ans_name.lower().strip(),
        target_ans_name=target_name,
        result=result,
        requester_ip=requester_ip,
    ))
    session.commit()

    return {
        "verified": meets_bar,
        "result": result,
        "target_ans_name": agent.ans_name,
        "ans_id": f"ans://{agent.ans_name}.trustmodel.ai",
        "owner_org": agent.owner_org,
        "owner_domain": agent.owner_domain,
        "assurance_tier": agent.assurance_tier,
        "min_assurance": req.min_assurance,
        "trust_score": agent.trust_score,
        "trust_tier": agent.trust_tier,
        "status": agent.status,
        "message": (
            f"'{agent.ans_name}' is {agent.assurance_tier}-verified to {agent.owner_org}."
            if meets_bar else
            f"'{agent.ans_name}' does not meet the required assurance bar "
            f"({agent.assurance_tier} < {req.min_assurance})."
        ),
    }


@app.get("/ans/typosquats/{ans_name}")
def typosquats_for_name(
    ans_name: str,
    max_distance: int = Query(1, ge=1, le=2),
    session: Session = Depends(get_session),
):
    """
    Typosquat detection — TRUS-1259.

    Return registered names that appear to be squatting on `ans_name` (or that
    `ans_name` would squat on), via small edit distance or homoglyph swaps.
    Useful for a brand owner to monitor lookalikes of their agent name.
    """
    target = ans_name.lower().strip()
    registered_names = session.exec(select(Agent.ans_name)).all()
    # Candidates are every registered name other than the target itself.
    others = [n for n in registered_names if n != target]
    hits = find_typosquats(target, others, max_distance=max_distance)

    return {
        "ans_name": target,
        "registered": target in registered_names,
        "max_distance": max_distance,
        "typosquat_count": len(hits),
        "typosquats": hits,
    }


@app.get("/ans/orphans")
def list_orphans(
    min_risk: str = Query("low", description="low | medium | high"),
    limit: int = Query(50, ge=1, le=500),
    session: Session = Depends(get_session),
):
    """
    Orphan detection — TRUS-1259.

    Recompute orphan risk across the namespace and return names at or above
    `min_risk`. Orphans are names with no proven/active owner — abandoned or
    never-verified registrations, the agent analog of a lapsed domain.
    """
    risk_rank = {"none": 0, "low": 1, "medium": 2, "high": 3}
    threshold = risk_rank.get(min_risk, 1)

    agents = session.exec(select(Agent)).all()
    results = []
    for a in agents:
        risk = assess_orphan_risk(a.verified, a.verified_at, a.updated_at)
        # Persist the freshly-computed risk so lookup/admin stay consistent.
        if a.orphan_risk != risk:
            a.orphan_risk = risk
            session.add(a)
        if risk_rank.get(risk, 0) >= threshold:
            results.append({
                "ans_name": a.ans_name,
                "owner_org": a.owner_org,
                "verified": a.verified,
                "assurance_tier": a.assurance_tier,
                "orphan_risk": risk,
                "last_verified": a.verified_at.isoformat() if a.verified_at else None,
                "registered_at": a.registered_at.isoformat(),
            })
    session.commit()

    results.sort(key=lambda r: risk_rank.get(r["orphan_risk"], 0), reverse=True)
    return {"min_risk": min_risk, "count": len(results), "orphans": results[:limit]}


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

        # Domain control proven → at least DV. OV is preserved if already granted.
        agent.assurance_tier = compute_assurance_tier(
            True, req.method, agent.org_validated
        )

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
            "assurance_tier": agent.assurance_tier,
            "trust_score": score,
            "trust_tier": tier,
            "badge_url": f"https://trustmodel.ai/badge/ans/{agent.ans_name}.svg",
        }

    return {"status": "failed", "message": "Verification failed."}


@app.post("/ans/verify/org")
def org_validate_agent(
    req: OrgValidateRequest,
    admin: AdminUser = Depends(require_admin),
    session: Session = Depends(get_session),
):
    """
    Org-validate an agent (OV tier) — TRUS-1257.

    OV layers a confirmed legal organization on top of domain control (DV).
    It's a manual review step, so it's admin-gated. The agent must already be
    domain-verified (DV) before it can be promoted to OV.
    """
    agent = session.exec(select(Agent).where(Agent.ans_name == req.ans_name.lower())).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found.")

    if not agent.verified or agent.assurance_tier == "unverified":
        raise HTTPException(
            status_code=409,
            detail="Agent must be domain-verified (DV) before it can be org-validated (OV).",
        )

    agent.org_validated = True
    agent.org_validated_by = admin.email
    agent.assurance_tier = compute_assurance_tier(
        agent.verified, agent.verification_method, True
    )
    agent.updated_at = datetime.utcnow()

    session.add(agent)
    session.commit()

    return {
        "status": "org_validated",
        "ans_name": agent.ans_name,
        "assurance_tier": agent.assurance_tier,
        "org_validated_by": admin.email,
        "message": f"'{agent.ans_name}' promoted to OV — organization '{agent.owner_org}' confirmed.",
    }


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
        "by_assurance": {
            t: len([a for a in all_agents if a.assurance_tier == t])
            for t in ["unverified", "DV", "OV"]
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
            "whois": "GET /ans/whois/{agent-name}",
            "verify": "POST /ans/verify",
            "org_validate": "POST /ans/verify/org",
            "a2a_verify": "POST /ans/a2a/verify",
            "typosquats": "GET /ans/typosquats/{agent-name}",
            "orphans": "GET /ans/orphans",
            "transfer": "POST /ans/transfer",
            "accept_transfer": "POST /ans/transfer/accept",
            "search": "GET /ans/search?q=...",
            "stats": "GET /ans/stats",
            "certificate": "GET /ans/cert/{agent-name}",
        },
        "website": "https://trustmodel.ai/ans",
        "docs": "/docs",
    }
