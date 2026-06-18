"""
Health endpoints — matches agp-control-plane's three-probe convention.

  GET /health/live   →  200 always; cheap; never touches the DB.
                        Use for Kubernetes livenessProbe equivalent.
  GET /health/ready  →  200 when the DB roundtrip succeeds;
                        503 with a reason when it doesn't.
                        Use for load-balancer / readiness gating.
  GET /health        →  200 with service-info JSON (version, db, uptime).
                        Operator-only — heavier than live/ready;
                        do NOT use as a probe.
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlmodel import Session

from .database import get_session

router = APIRouter(tags=["health"])

# Captured at import time so /health can report uptime cheaply.
_PROCESS_STARTED_AT = time.time()
_SERVICE_VERSION = "1.0.0"  # mirrors FastAPI app version


def _db_ok(session: Session) -> tuple[bool, str | None]:
    """SELECT 1 against the live engine. Returns (ok, error-detail)."""
    try:
        session.exec(text("SELECT 1"))
        return True, None
    except Exception as exc:  # noqa: BLE001
        return False, exc.__class__.__name__


@router.get("/health/live")
def liveness() -> dict[str, str]:
    """Process is up and serving requests."""
    return {"status": "ok"}


@router.get("/health/ready")
def readiness(session: Session = Depends(get_session)) -> JSONResponse:
    """DB roundtrip succeeded."""
    ok, reason = _db_ok(session)
    if ok:
        return JSONResponse(status_code=200, content={"status": "ready"})
    return JSONResponse(
        status_code=503,
        content={"status": "not-ready", "reason": "database", "detail": reason},
    )


@router.get("/health")
def verbose_health(session: Session = Depends(get_session)) -> dict[str, Any]:
    """Service-info: version, DB status, uptime."""
    db_ok, db_reason = _db_ok(session)
    return {
        "status": "ok" if db_ok else "degraded",
        "service": "ans-registry",
        "version": _SERVICE_VERSION,
        "uptime_seconds": int(time.time() - _PROCESS_STARTED_AT),
        "database": {
            "ok": db_ok,
            "reason": db_reason,
        },
    }
