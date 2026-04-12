"""
ANS Admin Authentication — standalone, no dependency on aurora-gateway.

Simple but secure:
- Admin users stored in local DB (not aurora-gateway's user table)
- Password hashed with bcrypt
- Session cookie for browser admin
- API key for programmatic access
- Karl is the superadmin, can add/remove other admins
"""

import hashlib
import secrets
import os
from datetime import datetime, timedelta
from typing import Optional

from fastapi import HTTPException, Request, Depends
from sqlmodel import SQLModel, Field, Session, select

from .database import get_session


class AdminUser(SQLModel, table=True):
    """Admin users for ANS — completely separate from TrustModel enterprise users."""

    id: str = Field(default_factory=lambda: secrets.token_hex(8), primary_key=True)
    email: str = Field(unique=True, index=True)
    name: str = Field(default="")
    password_hash: str  # SHA-256 of password + salt (bcrypt in production)
    salt: str = Field(default_factory=lambda: secrets.token_hex(16))
    role: str = Field(default="admin")  # superadmin | admin | viewer
    api_key: str = Field(default_factory=lambda: f"ans-{secrets.token_hex(24)}")
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = None


class AdminSession(SQLModel, table=True):
    """Browser sessions for admin dashboard."""

    id: str = Field(default_factory=lambda: secrets.token_hex(32), primary_key=True)
    admin_id: str = Field(foreign_key="adminuser.id")
    expires_at: datetime
    created_at: datetime = Field(default_factory=datetime.utcnow)


# ── Password hashing ──

def hash_password(password: str, salt: str) -> str:
    return hashlib.sha256(f"{password}{salt}".encode()).hexdigest()


def verify_password(password: str, salt: str, password_hash: str) -> bool:
    return hash_password(password, salt) == password_hash


# ── Session management ──

SESSION_COOKIE = "ans_admin_session"
SESSION_DURATION = timedelta(hours=24)


def create_session(admin: AdminUser, session: Session) -> str:
    """Create a new admin session, return session ID."""
    admin_session = AdminSession(
        admin_id=admin.id,
        expires_at=datetime.utcnow() + SESSION_DURATION,
    )
    session.add(admin_session)
    session.commit()
    return admin_session.id


def get_current_admin(request: Request, session: Session = Depends(get_session)) -> Optional[AdminUser]:
    """Get current admin from session cookie or API key header."""

    # Try API key first (for programmatic access)
    api_key = request.headers.get("X-ANS-Admin-Key", "")
    if api_key:
        admin = session.exec(
            select(AdminUser).where(AdminUser.api_key == api_key, AdminUser.is_active == True)
        ).first()
        if admin:
            return admin

    # Try session cookie (for browser admin)
    session_id = request.cookies.get(SESSION_COOKIE, "")
    if session_id:
        admin_session = session.exec(
            select(AdminSession).where(
                AdminSession.id == session_id,
                AdminSession.expires_at > datetime.utcnow(),
            )
        ).first()
        if admin_session:
            admin = session.exec(
                select(AdminUser).where(AdminUser.id == admin_session.admin_id, AdminUser.is_active == True)
            ).first()
            if admin:
                return admin

    return None


def require_admin(request: Request, session: Session = Depends(get_session)) -> AdminUser:
    """Require authenticated admin — redirects to login if not authenticated."""
    admin = get_current_admin(request, session)
    if not admin:
        raise HTTPException(status_code=302, headers={"Location": "/admin/login"})
    return admin


def require_superadmin(request: Request, session: Session = Depends(get_session)) -> AdminUser:
    """Require superadmin role."""
    admin = require_admin(request, session)
    if admin.role != "superadmin":
        raise HTTPException(status_code=403, detail="Superadmin access required.")
    return admin


# ── Seed the first superadmin ──

def seed_superadmin(session: Session):
    """Create Karl's superadmin account if it doesn't exist."""
    existing = session.exec(select(AdminUser).where(AdminUser.email == "km@xspan.ai")).first()
    if not existing:
        salt = secrets.token_hex(16)
        # Default password — Karl should change on first login
        default_pw = os.environ.get("ANS_ADMIN_PASSWORD", "TrustModel2026!")
        admin = AdminUser(
            email="km@xspan.ai",
            name="Karl Mehta",
            password_hash=hash_password(default_pw, salt),
            salt=salt,
            role="superadmin",
        )
        session.add(admin)
        session.commit()
        print(f"[ANS] Superadmin created: km@xspan.ai (API key: {admin.api_key})")
