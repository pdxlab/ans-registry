"""
ANS Admin Authentication — standalone, no dependency on aurora-gateway.

Storage:
- Admin users live in the local DB (not aurora-gateway's user table).
- Passwords are hashed with argon2 via passlib. Legacy SHA-256+salt rows
  from earlier releases are recognized and transparently upgraded to argon2
  on the next successful login.
- Session cookie for browser admin, API key for programmatic access.
- Karl is the superadmin, can add/remove other admins.
"""

import hashlib
import logging
import secrets
import os
from datetime import datetime, timedelta
from typing import Optional

from fastapi import HTTPException, Request, Depends
from passlib.context import CryptContext
from sqlmodel import SQLModel, Field, Session, select

from .database import get_session

logger = logging.getLogger(__name__)


# Passlib config:
#   - argon2 is the only `default` scheme (all new hashes are argon2)
#   - `ans_sha256` is a CustomHandler stand-in below; we identify legacy
#     hashes by their length and verify them manually in verify_password.
_pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

# SHA-256 hex digest length, used to detect legacy `password_hash` rows.
_LEGACY_SHA256_HEX_LEN = 64


class AdminUser(SQLModel, table=True):
    """Admin users for ANS — completely separate from TrustModel enterprise users."""

    id: str = Field(default_factory=lambda: secrets.token_hex(8), primary_key=True)
    email: str = Field(unique=True, index=True)
    name: str = Field(default="")
    # argon2-encoded hash (passlib format) for new rows.
    # Legacy rows carry a SHA-256 hex digest of `password + salt`; the
    # 64-character length is the marker — see verify_password / is_legacy_hash.
    password_hash: str
    # Salt is only meaningful for legacy SHA-256 rows. argon2 embeds its own
    # salt in the hash, so this field is unused for new accounts.
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

def is_legacy_hash(password_hash: str) -> bool:
    """Heuristic: legacy hashes are a 64-char hex digest. argon2 strings
    start with '$argon2'."""
    return (
        len(password_hash) == _LEGACY_SHA256_HEX_LEN
        and not password_hash.startswith("$argon2")
    )


def hash_password(password: str, salt: str = "") -> str:
    """Hash a password with argon2.

    The `salt` parameter is accepted for backward compatibility with the
    legacy SHA-256+salt flow used by older test fixtures. argon2 embeds
    its own salt; the value passed in is intentionally ignored for new
    hashes. Pass `salt` only when constructing a legacy row deliberately
    (i.e., not in production code).
    """
    return _pwd_context.hash(password)


def _legacy_hash(password: str, salt: str) -> str:
    """The old SHA-256(password + salt) scheme. Only used to verify
    historical rows; never used to write new hashes."""
    return hashlib.sha256(f"{password}{salt}".encode()).hexdigest()


def verify_password(password: str, salt: str, password_hash: str) -> bool:
    """Verify `password` against the stored hash.

    Handles both schemes:
    - argon2 (new): delegated to passlib.
    - legacy SHA-256+salt: recomputed locally.
    """
    if is_legacy_hash(password_hash):
        return _legacy_hash(password, salt) == password_hash
    try:
        return _pwd_context.verify(password, password_hash)
    except Exception:  # noqa: BLE001 — malformed hash row → reject
        logger.warning("verify_password: malformed argon2 hash, rejecting")
        return False


def upgrade_hash_if_legacy(
    admin: AdminUser, password: str, session: Session
) -> None:
    """If the stored hash is legacy SHA-256, rehash to argon2 and persist.

    Call this only after `verify_password` returns True — we already know
    the cleartext password is correct.
    """
    if not is_legacy_hash(admin.password_hash):
        return
    admin.password_hash = hash_password(password)
    admin.salt = ""  # argon2 embeds its own salt; legacy value no longer applies
    session.add(admin)
    session.commit()
    logger.info(
        "admin password upgraded to argon2",
        extra={"admin_id": admin.id, "admin_email": admin.email},
    )


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
    existing = session.exec(select(AdminUser).where(AdminUser.email == "knm@predixtions.com")).first()
    if not existing:
        default_pw = os.environ.get("ANS_ADMIN_PASSWORD")
        if not default_pw:
            logger.warning(
                "Superadmin not seeded: ANS_ADMIN_PASSWORD is unset. "
                "Set it via Secret Manager and restart to seed."
            )
            return
        admin = AdminUser(
            email="knm@predixtions.com",
            name="Karl Mehta",
            password_hash=hash_password(default_pw),
            salt="",  # argon2 embeds its own salt
            role="superadmin",
        )
        session.add(admin)
        session.commit()
        logger.info(
            "Superadmin seeded",
            extra={"admin_email": admin.email, "admin_id": admin.id},
        )
