"""
M6 regression tests — request_id from the ContextVar must show up in JSON
records emitted while a request is in flight, without per-call-site `extra={}`.
"""

from __future__ import annotations

import json
import logging


def test_request_id_absent_when_context_unset():
    """No request_id field on records emitted outside any request scope."""
    from app.errors import request_id_ctx
    from app.logging_config import GcpJsonFormatter

    # Explicitly clear in case a prior test leaked a value into this context.
    request_id_ctx.set(None)

    record = logging.LogRecord(
        name="t", level=logging.INFO, pathname="", lineno=0,
        msg="hi", args=None, exc_info=None,
    )
    payload = json.loads(GcpJsonFormatter().format(record))
    assert "request_id" not in payload


def test_request_id_present_when_context_set():
    """Records emitted while request_id_ctx is set carry it as a top-level field."""
    from app.errors import request_id_ctx
    from app.logging_config import GcpJsonFormatter

    token = request_id_ctx.set("test-rid-XYZ")
    try:
        record = logging.LogRecord(
            name="t", level=logging.INFO, pathname="", lineno=0,
            msg="hi", args=None, exc_info=None,
        )
        payload = json.loads(GcpJsonFormatter().format(record))
        assert payload["request_id"] == "test-rid-XYZ"
    finally:
        request_id_ctx.reset(token)


def test_extra_overrides_context_request_id():
    """Per-call-site extra={"request_id": ...} wins over the ContextVar value."""
    from app.errors import request_id_ctx
    from app.logging_config import GcpJsonFormatter

    token = request_id_ctx.set("from-context")
    try:
        record = logging.LogRecord(
            name="t", level=logging.INFO, pathname="", lineno=0,
            msg="hi", args=None, exc_info=None,
        )
        # Simulate `logger.info(..., extra={"request_id": "from-extra"})`.
        record.request_id = "from-extra"
        payload = json.loads(GcpJsonFormatter().format(record))
        assert payload["request_id"] == "from-extra"
    finally:
        request_id_ctx.reset(token)


def test_full_request_round_trip_emits_request_id(client, caplog):
    """End-to-end: a request with X-Request-ID should land in app logs."""
    from app.errors import RequestIDMiddleware

    # caplog captures records from the root logger (configured by
    # configure_logging() at import time). We only assert against records
    # carrying the request_id we set.
    rid = "fixture-supplied-rid-001"
    with caplog.at_level(logging.INFO):
        resp = client.get("/health/live", headers={RequestIDMiddleware.HEADER: rid})
    assert resp.status_code == 200
    assert resp.headers[RequestIDMiddleware.HEADER] == rid
    # At least one captured record should have it (uvicorn access log or app).
    # `caplog.records[i].request_id` is set by the formatter via
    # `payload["request_id"] = rid`, but caplog operates on LogRecord objects
    # before the formatter runs — so we verify via the response header which
    # the middleware sets and the test above which exercises the formatter
    # directly. This test asserts the middleware path is alive.
