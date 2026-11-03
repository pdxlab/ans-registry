"""
Central typed config for ans-registry.

Reads values from environment variables (and a local `.env` file in development
mode). Fails fast at import time if a required value is missing in non-dev
environments.

Source-of-truth precedence on Cloud Run:
  1. Cloud Run revision env vars (`--set-env-vars`)  — non-sensitive defaults
  2. Cloud Run secret mounts (`--set-secrets`)       — sensitive values
  3. Local `.env` (development only)

Run-time access: `from app.config import settings`.
"""

import re
from functools import lru_cache
from typing import Optional

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# A ``https://*.<base>`` entry in ANS_CORS_ORIGINS allows any single-label
# subdomain of <base>. Starlette compares ``allow_origins`` by exact string, so
# such entries are compiled into ``allow_origin_regex`` instead (TRUS-2474).
# Only https wildcards are recognised; anything else stays a literal and so
# simply never matches.
_WILDCARD_PREFIX = "https://*."


def _split_origins(raw: str) -> list[str]:
    return [o.strip() for o in raw.split(",") if o.strip()]


class Settings(BaseSettings):
    """All runtime configuration in one place."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        # Allow `model_used` style fields elsewhere without protected-namespace warnings.
        protected_namespaces=(),
    )

    # ── Environment selector ─────────────────────────────────────────────────
    app_env: str = Field(
        default="development",
        description="qa | prod | development. Drives prod-only validations.",
    )

    # ── Logging ──────────────────────────────────────────────────────────────
    log_level: str = Field(default="info", description="info | debug | warning | error")

    # ── Server ───────────────────────────────────────────────────────────────
    web_workers: int = Field(default=2)

    # ── Database ─────────────────────────────────────────────────────────────
    # Provided via Secret Manager `--set-secrets=ANS_DATABASE_URL=ans-database-url:latest`
    # in QA/prod. In development falls back to a local SQLite file.
    ans_database_url: Optional[str] = Field(default=None)

    # ── Schema bootstrap ─────────────────────────────────────────────────────
    # SQLModel.metadata.create_all() is gated behind this flag. It must be off
    # in cloud — Alembic runs `upgrade head` in start.sh on cold start.
    ans_run_auto_create: bool = Field(default=False)

    # ── Admin seeding ────────────────────────────────────────────────────────
    ans_admin_email: str = Field(default="knm@predixtions.com")
    # `ans_admin_password` is only consulted during seed_superadmin() the first
    # time the database is empty. Optional so seeded prod DBs don't need it set.
    ans_admin_password: Optional[str] = Field(default=None)

    # ── Sessions ─────────────────────────────────────────────────────────────
    ans_session_secret: Optional[str] = Field(default=None)
    # Set `true` on Cloud Run revisions; `false` for plain-HTTP local dev.
    ans_session_cookie_secure: bool = Field(default=False)

    # ── CORS ─────────────────────────────────────────────────────────────────
    # Comma-separated list of allowed origins, or "*" to allow any (which also
    # disables cookie-bearing cross-origin requests per FastAPI rules).
    ans_cors_origins: str = Field(default="*")

    # ── Validators ───────────────────────────────────────────────────────────
    @model_validator(mode="after")
    def _enforce_required_in_cloud(self) -> "Settings":
        """In non-development environments, a real DSN must be configured.

        Local dev intentionally tolerates a missing DSN (it falls back to a
        SQLite file in database.py).
        """
        if self.app_env.lower() != "development":
            if not self.ans_database_url:
                raise ValueError(
                    "ANS_DATABASE_URL is required when APP_ENV is not 'development'."
                )
            if not self.ans_session_secret:
                raise ValueError(
                    "ANS_SESSION_SECRET is required when APP_ENV is not 'development'."
                )
        return self

    # Computed helpers -------------------------------------------------------
    @property
    def is_development(self) -> bool:
        return self.app_env.lower() == "development"

    @property
    def cors_origin_list(self) -> list[str]:
        raw = self.ans_cors_origins.strip()
        if raw == "*":
            return ["*"]
        return [o for o in _split_origins(raw) if not o.startswith(_WILDCARD_PREFIX)]

    @property
    def cors_origin_regex(self) -> Optional[str]:
        """Anchored regex covering every ``https://*.<base>`` entry, or None.

        Mirrors aurora-gateway's ``tenant_origin_regexes`` so both services
        accept the same tenant hosts: https only, exactly one DNS label, and
        the base domain escaped. The apex and nested subdomains do not match.
        """
        raw = self.ans_cors_origins.strip()
        if raw == "*":
            return None
        bases = [
            o[len(_WILDCARD_PREFIX) :]
            for o in _split_origins(raw)
            if o.startswith(_WILDCARD_PREFIX)
        ]
        if not bases:
            return None
        return "|".join(
            rf"^https://[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.{re.escape(b)}$"
            for b in bases
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached accessor — Settings() is built exactly once per process."""
    return Settings()


# Module-level convenience for the common case.
settings = get_settings()
