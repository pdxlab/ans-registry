"""
Alembic environment for ans-registry.

Reads the DSN from app.config.Settings (ANS_DATABASE_URL) so migrations
hit exactly the database the application connects to. Imports app.models
so SQLModel.metadata is complete before autogenerate runs.
"""

import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool
from sqlmodel import SQLModel

# Make `app/` importable when alembic is run from the repo root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import all model modules so SQLModel.metadata is populated for autogenerate.
from app import auth  # noqa: F401  — registers AdminUser, AdminSession
from app import models  # noqa: F401  — registers Agent, Transfer, LookupLog, A2A...
from app.config import settings as app_settings
from app.database import _resolve_database_url


config = context.config

# Honor alembic.ini's logging config if present.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Inject the runtime DSN so neither alembic.ini nor env vars need to repeat it.
config.set_main_option("sqlalchemy.url", _resolve_database_url())

target_metadata = SQLModel.metadata


def run_migrations_offline() -> None:
    """Run migrations against just a URL (no live connection)."""
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live database connection."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            # Detect column type changes; SQLModel relies on a few non-trivial
            # column types (str max_length → VARCHAR(n)) we want flagged.
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
