# Repo Conventions — ans-registry

> Argus enforces these as the local standard. A violation is at least `minor`; a
> **security** convention violation is `major`+.
>
> Rewritten 2026-09-08 against `main` after review. The first draft was seeded from
> an aurora/Django template and asserted things this repo does not do — which would
> have made Argus flag *conforming* code. Everything below was checked against the
> actual source.

## What this service is
- **FastAPI + SQLModel + Alembic** (`sqlmodel==0.0.22` — not plain SQLAlchemy).
- The agent-name registry: register a name, look it up, prove who owns it.
- `app/main.py` holds the public ANS API. `app/resolver.py` is the ANS-v2 /
  DNS-style resolution path behind `GET /ans/resolve/{ans_name:path}`; the plain
  lookup is `GET /ans/lookup/{ans_name}` in `main.py`. Don't conflate the two.

## The API is public by design — do NOT flag missing auth on it
- Of the routes in `app/main.py`, **only `POST /ans/verify/org` takes an auth
  dependency** (`Depends(require_admin)`). Everything else — `register`, `lookup`,
  `resolve`, `whois`, `search`, `directory`, `stats`, `cert`, `typosquats`,
  `orphans`, `a2a/verify`, `verify`, `transfer` — is **intentionally
  unauthenticated**, because a public registry has to be readable and registrable
  by anyone.
- A new route with no auth dependency is therefore **not** a finding on its own.
  It is a finding only if it exposes admin data, mutates another owner's record,
  or leaks something the public routes don't already expose.

## The admin surface is the exception
- Admin authn/authz lives in **`app/auth.py`**, not `admin_auth.py`:
  `AdminUser` / `AdminSession` SQLModel tables, a cookie session
  (`ans_admin_session`, 24h), and the `get_current_admin` / `require_admin` /
  `require_superadmin` dependencies.
- `app/admin_auth.py` holds the admin **UI routes** (login page, logout, admin-user
  management) and *consumes* those dependencies. Don't describe it as the gate.
- Password hashing has a legacy-hash upgrade path (`is_legacy_hash`,
  `upgrade_hash_if_legacy`). A change that verifies a password without preserving
  that upgrade, or that weakens the hash, is `major`+.
- Admin-user management is `require_superadmin`, not `require_admin`. Widening a
  superadmin route to plain admin is a finding.

## Ownership is asserted, not proven — the real invariant
- Mutations authorise by **comparing an email supplied in the request body** to the
  stored owner, in-handler: `agent.owner_email.lower() != req.from_email.lower()`
  → 403 (see `initiate_transfer`). That is a *claim*, not proof of identity.
- Any new mutation on an existing record **must at minimum replicate that owner
  check** — omitting it is a `blocker`, since it would let anyone edit any name.
- Proposing to strengthen this (signed proof, emailed confirmation token) is a
  legitimate `major` finding, not a false positive. Say so as a recommendation
  rather than asserting the current code is broken.

## Registry-specific rules
- Names go through `validate_ans_name` before use. A new path that accepts a name
  without it is a finding.
- Uniqueness is enforced by an explicit pre-check plus a 409. Registration is
  check-then-act, so a new create path needs a unique constraint or it will race —
  two concurrent registrations can win the same name.
- **Typosquat detection flags, it does not block.** `find_typosquats` attaches a
  warning at registration and the request still succeeds. Don't "fix" that into a
  rejection; it's deliberate.

## Config
- `app/config.py` is the intended home for settings, but it is **not** the single
  source today — `app/resolver.py` reads `os.getenv` directly. Moving a new read
  into `config.py` is a fair `nit`; asserting that config is centralised is wrong.

## Migrations
- Alembic revisions must survive a rolling deploy (old code against new DB) and
  must not fork the head — check `down_revision` for a second leaf before merge.

## Errors, logging, secrets
- Never `except: pass` — log with context (ids, not PII).
- Never log or return admin session cookies, password hashes, or owner emails in bulk.
- No secrets in code, tests, or fixtures — automatic `blocker`.
- There is no `CLAUDE.md` in this repo; don't reference one.
