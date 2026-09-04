# Repo Conventions — ans-registry

> Argus enforces these as the local standard. A violation is at least `minor`; a
> **security** convention violation is `major`+.
>
> **These are SEEDS**, derived from the repo layout, CLAUDE.md and the shared
> backend rules — not from a full audit. Curate them via PR as the team learns;
> a wrong convention is worse than no convention. Argus proposes additions as
> "📝 Memory suggestion" in its reviews; a human merges them.

## What this service is
- FastAPI + SQLAlchemy/Alembic agent-name registry. `resolver.py` answers "what
  is this name", `verification.py` / `assurance.py` decide how much that answer
  can be trusted, `admin_auth.py` gates the admin surface.

## Registry rules
- **Name resolution is a security decision, not a lookup.** A change that lets an
  unverified record resolve as verified, or widens what a claimant may register,
  is `major`+.
- Registration is check-then-act by nature: `if not exists(): create()` must be
  backed by a unique constraint, or two concurrent registrations win the same name.
- Every FastAPI route declares its dependency-injected auth explicitly. A route
  added without one is a finding — there is no global default to fall back on.
- `app/config.py` is the single source for environment config; don't read env
  vars ad hoc at call sites.

## Migrations
- Alembic revisions must survive a rolling deploy (old code against new DB), and
  must have exactly one head — check `down_revision` for a fork before merge.

## Errors, logging, secrets (org-wide)
- Never `except: pass` — log with context (ids, not PII) and a correlation id.
- Never log or return tokens, passwords, bulk emails, or full request bodies.
- No secrets in code, tests, or fixtures — automatic `blocker`.
- PHI/ePHI and credentials never reach logs, tickets, PR bodies, or test data.
  Use synthetic or properly de-identified test data.

## Authorization (org-wide)
- Authentication is not authorization. Validate the whole chain:
  User → Organization → Permission → Resource → Action, server-side.
- Never trust a client-supplied organization, tenant, or resource id as proof of
  access. Cross-tenant exposure is a `blocker`.
