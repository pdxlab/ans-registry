"""TRUS-2497: search terms stay out of ans-registry's logs.

Search terms (``/ans/search?q=``) can name a person. The access-line tests run
the real uvicorn server in-process, so the record has exactly the shape
uvicorn logs, through the logger config ``configure_logging()`` installs.
Synthetic values only.
"""

from __future__ import annotations

import json
import logging
import socket
import threading
import time
import urllib.request

import uvicorn

from app.logging_config import DropQueryString, GcpJsonFormatter, configure_logging
from app.main import app

QUERY = "q=alice%40acme-2497.example&limit=5"


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines: list[str] = []
        self.setFormatter(GcpJsonFormatter())

    def emit(self, record):
        self.lines.append(self.format(record))


def _access_lines(path: str, *, keep_filters: bool = True) -> list[str]:
    configure_logging()  # what app.main runs at import; idempotent
    access = logging.getLogger("uvicorn.access")
    saved_filters = list(access.filters)
    if not keep_filters:
        access.filters.clear()
    capture = _Capture()
    access.addHandler(capture)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, lifespan="off", log_config=None, access_log=True))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started:
            assert time.monotonic() < deadline, "uvicorn did not start"
            time.sleep(0.05)
        urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5).read()
    finally:
        server.should_exit = True
        thread.join(10)
        access.removeHandler(capture)
        access.filters[:] = saved_filters
        sock.close()
    return capture.lines


def test_the_access_line_has_the_path_without_the_query():
    lines = _access_lines(f"/health/live?{QUERY}")
    assert len(lines) == 1, lines
    assert json.loads(lines[0])["message"].endswith(' - "GET /health/live HTTP/1.1" 200')
    assert "alice" not in lines[0] and "limit=5" not in lines[0]


def test_without_the_filter_uvicorn_does_write_it():
    # The defect this fixes, pinned so the test above can't pass vacuously.
    lines = _access_lines(f"/health/live?{QUERY}", keep_filters=False)
    assert any("alice" in line for line in lines), lines


def test_a_failed_query_does_not_carry_its_parameters():
    # A DB error during /ans/search is logged with its traceback, whose text
    # lists the statement's bound parameters unless the engine hides them.
    from sqlalchemy import create_engine, text
    from sqlalchemy.exc import OperationalError

    from app import database

    assert database.engine.hide_parameters is True
    probe = create_engine("sqlite://", **database._engine_kwargs)
    with probe.connect() as conn:
        try:
            conn.execute(text("SELECT * FROM no_such_table_2497 WHERE x = :q"), {"q": "alice@acme-2497.example"})
        except OperationalError as exc:
            assert "alice" not in str(exc), str(exc)
        else:
            raise AssertionError("expected the query to fail")


def test_other_records_pass_through_unchanged():
    record = logging.LogRecord("uvicorn.access", logging.INFO, "", 0, "%s?%s", ("a", "b"), None)
    assert DropQueryString().filter(record) is True
    assert record.getMessage() == "a?b"
