"""
Centralized error handling for FastAPI.

  - Every request gets an `X-Request-ID` (either passed in by the client or
    generated). The id is stored on `request.state.request_id` and echoed
    in the response header.
  - All log records emitted during a request carry the same `request_id`
    via a contextvar that the JSON formatter already picks up from `extra=`.
  - HTTPException → `{"error":{"code":<int>, "message":<str>, "request_id":...}}`
  - Anything else → log a structured ERROR record with traceback and return
    a generic 500 body — never echo internals to the client.
"""

from __future__ import annotations

import logging
import uuid
from contextvars import ContextVar

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

# Read by code paths that want the current request id without depending on
# a FastAPI dependency (e.g., background tasks, library code).
request_id_ctx: ContextVar[str | None] = ContextVar("request_id", default=None)


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Stamp every request with an id and echo it back in the response."""

    HEADER = "X-Request-ID"

    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get(self.HEADER) or uuid.uuid4().hex
        request.state.request_id = rid
        token = request_id_ctx.set(rid)
        try:
            response = await call_next(request)
        finally:
            request_id_ctx.reset(token)
        response.headers[self.HEADER] = rid
        return response


def _payload(code: int, message: str, request_id: str | None) -> dict:
    body: dict = {"error": {"code": code, "message": message}}
    if request_id:
        body["error"]["request_id"] = request_id
    return body


async def http_exception_handler(
    request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    rid = getattr(request.state, "request_id", None)
    # Preserve any headers the route set (e.g., Location for 302 redirects).
    return JSONResponse(
        status_code=exc.status_code,
        content=_payload(exc.status_code, str(exc.detail), rid),
        headers=exc.headers,
    )


async def unhandled_exception_handler(
    request: Request, exc: Exception
) -> JSONResponse:
    rid = getattr(request.state, "request_id", None)
    logger.exception(
        "unhandled exception",
        extra={
            "request_id": rid,
            "path": request.url.path,
            "method": request.method,
        },
    )
    return JSONResponse(
        status_code=500,
        content=_payload(500, "internal error", rid),
    )


def install(app: FastAPI) -> None:
    """Register middleware + handlers on the FastAPI app."""
    app.add_middleware(RequestIDMiddleware)
    # Register on the Starlette base class so both Starlette's automatic
    # 404 (no route match) and FastAPI's `HTTPException` (a subclass) are
    # caught.
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)
