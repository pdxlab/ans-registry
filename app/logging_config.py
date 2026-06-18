"""
Structured logging configuration.

Cloud Logging auto-parses JSON written to stdout: keys become structured
fields, `severity` controls log level, `timestamp` is honored. The
`python-json-logger` formatter emits exactly the shape Cloud Logging expects.

For local development we keep the same JSON output for parity — operators
work with the same shape in both environments.
"""

import logging
import logging.config
import sys
from typing import Any

from .config import settings

# Maps Python logging level names → Cloud Logging severity strings.
# Cloud Logging documents these here:
# https://cloud.google.com/logging/docs/agent/logging/configuration#special-fields
_SEVERITY_MAP = {
    "DEBUG": "DEBUG",
    "INFO": "INFO",
    "WARNING": "WARNING",
    "ERROR": "ERROR",
    "CRITICAL": "CRITICAL",
}


class GcpJsonFormatter(logging.Formatter):
    """JSON formatter producing the Cloud-Logging-friendly shape.

    We hand-roll instead of subclassing pythonjsonlogger.JsonFormatter because
    we want full control over the `severity` field name (Cloud Logging needs
    `severity`, not `level`) and to keep the dependency surface small.
    """

    def format(self, record: logging.LogRecord) -> str:
        import json
        import datetime

        payload: dict[str, Any] = {
            "timestamp": datetime.datetime.fromtimestamp(
                record.created, tz=datetime.timezone.utc
            ).isoformat(),
            "severity": _SEVERITY_MAP.get(record.levelname, record.levelname),
            "message": record.getMessage(),
            "logger": record.name,
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        # Pick up the per-request id stamped by RequestIDMiddleware so every
        # log record emitted during a request carries it automatically. Import
        # lazily to avoid making the formatter depend on errors.py at module
        # import time (decouples logging from FastAPI wiring).
        try:
            from .errors import request_id_ctx
            rid = request_id_ctx.get()
            if rid is not None:
                payload["request_id"] = rid
        except Exception:  # noqa: BLE001 — never let logging crash on its own plumbing
            pass
        # `logger.info("msg", extra={"foo": "bar"})` lands here. Per-call-site
        # extras win over the contextvar value if both are present.
        for key, value in record.__dict__.items():
            if key in (
                "args", "asctime", "created", "exc_info", "exc_text",
                "filename", "funcName", "levelname", "levelno", "lineno",
                "module", "msecs", "message", "msg", "name", "pathname",
                "process", "processName", "relativeCreated", "stack_info",
                "thread", "threadName", "taskName",
            ):
                continue
            payload[key] = value
        return json.dumps(payload, default=str)


def configure_logging() -> None:
    """Install the JSON formatter on the root logger.

    Idempotent — safe to call from app startup and from tests.
    """
    level = settings.log_level.upper()

    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "gcp_json": {
                    "()": GcpJsonFormatter,
                },
            },
            "handlers": {
                "stdout": {
                    "class": "logging.StreamHandler",
                    "stream": sys.stdout,
                    "formatter": "gcp_json",
                    "level": level,
                },
            },
            "root": {
                "level": level,
                "handlers": ["stdout"],
            },
            # uvicorn ships its own loggers; route them through the same handler
            # so access logs land in JSON too.
            "loggers": {
                "uvicorn":        {"level": level, "handlers": ["stdout"], "propagate": False},
                "uvicorn.error":  {"level": level, "handlers": ["stdout"], "propagate": False},
                "uvicorn.access": {"level": level, "handlers": ["stdout"], "propagate": False},
            },
        }
    )
