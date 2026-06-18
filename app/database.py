"""
Database setup.

Production target (QA/prod): Postgres over private IP in VPC `pdx-us-dev-01`.
Connection comes from Secret Manager as `ANS_DATABASE_URL` (mounted via
Cloud Run `--set-secrets`). Driver is psycopg v3 (sync) — matches the verified
org pattern and works with existing sync SQLModel handlers.

Local development falls back to a SQLite file so `pytest` and `uvicorn
--reload` keep working without a Postgres install.
"""

import logging
import os

from sqlmodel import Session, SQLModel, create_engine

from .config import settings

logger = logging.getLogger(__name__)


def _resolve_database_url() -> str:
    """Return the DSN to hand to SQLAlchemy.

    Order of precedence:
      1. ANS_DATABASE_URL (Settings) — canonical, used in QA/prod.
      2. Legacy DATABASE_URL env var — kept for backward compatibility with
         older local dev setups; emit a deprecation log when picked up.
      3. SQLite file fallback — development convenience only.
    """
    if settings.ans_database_url:
        return settings.ans_database_url

    legacy = os.environ.get("DATABASE_URL")
    if legacy:
        logger.warning(
            "DATABASE_URL is deprecated; rename to ANS_DATABASE_URL "
            "to match the platform secret-mount convention."
        )
        return legacy

    if not settings.is_development:
        # The Settings validator already catches this in cloud, but if
        # someone bypasses validation we still refuse to fall back to SQLite
        # in QA/prod.
        raise RuntimeError(
            "ANS_DATABASE_URL is unset in a non-development environment. "
            "Refusing to fall back to SQLite."
        )

    return "sqlite:///./ans_registry.db"


DATABASE_URL = _resolve_database_url()


# pool_pre_ping=True validates connections from the pool before use — cheap
# guard against stale Postgres connections after Cloud SQL maintenance.
# For SQLite the kwarg is a harmless no-op.
_engine_kwargs: dict = {"echo": False, "pool_pre_ping": True}

# SQLite needs `check_same_thread=False` to be used from FastAPI's
# threadpool. psycopg/Postgres needs nothing extra.
if DATABASE_URL.startswith("sqlite"):
    _engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, **_engine_kwargs)


def create_db() -> None:
    """Create tables from SQLModel metadata.

    Gated behind ANS_RUN_AUTO_CREATE so that Cloud Run cold starts do **not**
    race concurrent revisions. In QA/prod, schema is managed by Alembic
    (`alembic upgrade head` in start.sh). Local dev sets this flag for
    convenience.
    """
    if not settings.ans_run_auto_create:
        logger.info(
            "create_db skipped (ANS_RUN_AUTO_CREATE=false). "
            "Schema is managed by Alembic."
        )
        return

    SQLModel.metadata.create_all(engine)
    logger.info("create_db completed (ANS_RUN_AUTO_CREATE=true).")


def get_session():
    """FastAPI dependency that yields a SQLModel Session."""
    with Session(engine) as session:
        yield session
