#!/bin/bash
# ans-registry container entrypoint.
#
# Cloud Run runs this on every cold start of an instance:
#   1. Apply pending Alembic migrations against ANS_DATABASE_URL.
#   2. Hand off to uvicorn, binding to the PORT Cloud Run injects.
#
# Migrations are idempotent (alembic short-circuits when already at head),
# so this is safe to run on every revision boot. For a multi-revision
# rolling deploy, the first revision wins the race and subsequent ones
# no-op — the schema is forward-compatible per migration discipline.

set -euo pipefail

PORT="${PORT:-8000}"
WORKERS="${WEB_WORKERS:-2}"
LOG_LEVEL="${LOG_LEVEL:-info}"

echo "ans-registry starting (port=${PORT}, workers=${WORKERS}, log_level=${LOG_LEVEL})"

echo "Running alembic migrations..."
alembic upgrade head
echo "✓ migrations applied"

echo "Starting uvicorn..."
# `exec` so uvicorn becomes PID 1 — Cloud Run's SIGTERM goes straight to
# uvicorn, which drains in-flight requests cleanly before exiting.
exec uvicorn app.main:app \
    --host 0.0.0.0 \
    --port "${PORT}" \
    --workers "${WORKERS}" \
    --log-level "${LOG_LEVEL}" \
    --proxy-headers \
    --forwarded-allow-ips='*' \
    --no-use-colors
