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

# Look up an agent (WHOIS for agents)
curl http://localhost:8080/ans/lookup/my-sales-agent

# Verify ownership
curl -X POST http://localhost:8080/ans/verify \
  -d '{"ans_name": "my-sales-agent", "method": "email"}'

# Transfer ownership
curl -X POST http://localhost:8080/ans/transfer \
  -d '{"ans_name": "my-sales-agent", "from_email": "ai@acme.com", "to_org": "NewCo", "to_email": "ai@newco.com"}'

# Search registry
curl http://localhost:8080/ans/search?q=sales&verified_only=true

# View certificate
curl http://localhost:8080/ans/cert/my-sales-agent
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
