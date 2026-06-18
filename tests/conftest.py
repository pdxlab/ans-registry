"""
Shared pytest fixtures for the ANS registry test suite.

Each test gets a fresh in-memory SQLite database, wired into the FastAPI app by
overriding the `get_session` dependency. The admin-gated endpoints are exercised
through a seeded superadmin and its API key header.
"""

import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel, Session, create_engine
from sqlmodel.pool import StaticPool

from app.main import app
from app.database import get_session
from app.auth import AdminUser, hash_password


@pytest.fixture(name="session")
def session_fixture():
    """Fresh in-memory DB shared by all connections within a test."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


@pytest.fixture(name="client")
def client_fixture(session):
    """TestClient with get_session overridden to the in-memory DB."""
    def get_session_override():
        return session

    app.dependency_overrides[get_session] = get_session_override
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


@pytest.fixture(name="admin_key")
def admin_key_fixture(session):
    """Seed a superadmin (argon2 hash) and return its API key for
    admin-gated endpoints."""
    admin = AdminUser(
        email="admin@predixtions.com",
        name="Test Admin",
        password_hash=hash_password("pw"),
        salt="",  # argon2 embeds its own salt
        role="superadmin",
    )
    session.add(admin)
    session.commit()
    session.refresh(admin)
    return admin.api_key


def register(client, ans_name, owner_email="ai@acme.com", owner_org="Acme Inc.", **kw):
    """Helper: register an agent and return the response JSON."""
    body = {
        "ans_name": ans_name,
        "display_name": kw.get("display_name", ans_name),
        "owner_org": owner_org,
        "owner_email": owner_email,
    }
    body.update({k: v for k, v in kw.items() if k != "display_name"})
    resp = client.post("/ans/register", json=body)
    return resp


def verify_email(client, ans_name):
    """Helper: verify an agent via email-domain match (earns DV)."""
    return client.post("/ans/verify", json={"ans_name": ans_name, "method": "email"})
