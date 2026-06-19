# ANS — Agent Naming Service

**DNS + SSL for AI Agents.** The identity, verification, and ownership layer for the agent economy.

## What ANS Does

| Web Equivalent | ANS Equivalent | What It Does |
|---|---|---|
| DNS | ANS Registry | Maps agent name → owner + capabilities |
| WHOIS | ANS Lookup | Who owns this agent? Verified? |
| SSL Certificate | TrustScore Cert | Is this agent safe to connect to? |
| Certificate Authority | TrustModel | Issues TrustScore + verification |
| Domain Transfer | Agent Transfer | Transfer ownership between orgs |

## Quick Start

```bash
# Install
pip install -r requirements.txt

# Run
uvicorn app.main:app --reload --port 8080

# Open docs
open http://localhost:8080/docs
```

## API Endpoints

```bash
# Register an agent
curl -X POST http://localhost:8080/ans/register \
  -H "Content-Type: application/json" \
  -d '{
    "ans_name": "my-sales-agent",
    "display_name": "My Sales Agent",
    "owner_org": "Acme Inc.",
    "owner_email": "ai@acme.com",
    "agent_type": "mcp_server",
    "capabilities": "query_leads, update_contact",
    "description": "CRM automation agent"
  }'

# Look up an agent (full record)
curl http://localhost:8080/ans/lookup/my-sales-agent

# WHOIS-for-agents — compact registry record (owner, tier, AgentCert status)
curl http://localhost:8080/ans/whois/my-sales-agent

# Verify ownership — DNS TXT or email domain match earns the DV assurance tier
curl -X POST http://localhost:8080/ans/verify \
  -d '{"ans_name": "my-sales-agent", "method": "email"}'

# Org-validate (OV tier) — admin only; requires DV first
curl -X POST http://localhost:8080/ans/verify/org \
  -H "X-ANS-Admin-Key: ans-..." \
  -d '{"ans_name": "my-sales-agent"}'

# Agent-to-agent verify — does the target meet a minimum assurance bar?
curl -X POST http://localhost:8080/ans/a2a/verify \
  -d '{"target_ans_name": "my-sales-agent", "caller_ans_name": "buyer-bot", "min_assurance": "DV"}'

# Typosquats targeting a name (edit-distance / homoglyph lookalikes)
curl http://localhost:8080/ans/typosquats/my-sales-agent

# Orphaned / orphan-risk names across the namespace
curl http://localhost:8080/ans/orphans?min_risk=medium

# Transfer ownership
curl -X POST http://localhost:8080/ans/transfer \
  -d '{"ans_name": "my-sales-agent", "from_email": "ai@acme.com", "to_org": "NewCo", "to_email": "ai@newco.com"}'

# Search registry
curl http://localhost:8080/ans/search?q=sales&verified_only=true

# Public AgentCert directory — every agent holding an AgentCert
# (name, org, DV/OV tier, 0-100 TrustScore, cert status, timestamps)
#   q         — search by agent name or org (substring)
#   sort      — score (desc, default) | recent
#   min_score — minimum TrustScore (0-100)
#   limit / offset — pagination (limit capped at 100)
curl "http://localhost:8080/ans/directory?q=sales&sort=score&min_score=50&limit=20&offset=0"

# View certificate
curl http://localhost:8080/ans/cert/my-sales-agent
```

## Assurance Tiers

AgentCert builds on DV/OV-style identity assurance, mirroring SSL certificates:

| Tier | Meaning | How to earn |
|---|---|---|
| `unverified` | Registered, owner unproven | Default on registration |
| `DV` | Domain validated | DNS TXT challenge or matching email domain (`POST /ans/verify`) |
| `OV` | Organization validated | DV + admin org review (`POST /ans/verify/org`) |

`POST /ans/a2a/verify` lets one agent check another against a minimum tier
before connecting. The registry continuously flags **typosquats** (edit-distance
/ homoglyph lookalikes) and **orphans** (names with no proven/active owner).

## Tests

```bash
pip install -r requirements.txt
pytest
```

## Deploy

```bash
# Docker
docker build -t ans-registry .
docker run -p 8080:8080 ans-registry

# Google Cloud Run
gcloud run deploy ans-registry --source . --region us-central1 --allow-unauthenticated
```

## Website
https://trustmodel.ai/ans

## License
MIT
