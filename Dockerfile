# syntax=docker/dockerfile:1.7
# ─────────────────────────────────────────────────────────────────────────────
# ans-registry — production image (Cloud Run target).
#
# Mirrors the verified agp-control-plane build shape:
#   - Two stages: builder installs into /opt/venv, runtime copies the venv.
#   - Final stage carries only libpq5 + tini + the app — no compiler, no apt
#     headers, no Poetry, no GitHub credentials.
#   - Non-root user (uid 1001).
#   - PORT honored at runtime; uvicorn becomes PID 1 via `exec` in start.sh.
#
# Build:
#   docker build -t ans-registry:local .
#
# Local run (sqlite fallback, dev-only):
#   docker run --rm -p 8000:8000 \
#     -e APP_ENV=development \
#     -e ANS_RUN_AUTO_CREATE=1 \
#     -e ANS_ADMIN_PASSWORD=devpw \
#     -e ANS_SESSION_SECRET=dev-secret \
#     ans-registry:local
# ─────────────────────────────────────────────────────────────────────────────

# ─── builder stage ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VENV=/opt/venv

# Build deps only — runtime image doesn't carry these.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        gcc \
        build-essential \
        libpq-dev \
 && rm -rf /var/lib/apt/lists/*

# Standalone venv so the runtime stage can copy it verbatim.
RUN python -m venv "$VENV"
ENV PATH="$VENV/bin:$PATH"

RUN pip install --upgrade pip setuptools wheel

# Copy requirements first so the install layer is cached as long as deps
# don't change.
COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt


# ─── runtime stage ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    VENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH" \
    PORT=8000

# psycopg + alembic only need libpq5 at runtime. tini gives us a real PID 1
# so SIGTERM from Cloud Run reaches the app cleanly.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        libpq5 \
        tini \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system app \
 && useradd --system --gid app --uid 1001 --create-home --shell /usr/sbin/nologin app

# Bring over the fully-populated venv from the builder stage.
COPY --from=builder $VENV $VENV

# Create WORKDIR as app-owned so anything the container writes there (e.g.,
# the SQLite dev fallback file) can be created without elevated perms.
RUN mkdir -p /app && chown -R app:app /app
WORKDIR /app

# App code + alembic config — copy last so app-only edits don't bust the
# heavier dep layers above.
COPY --chown=app:app app/         /app/app/
COPY --chown=app:app alembic/     /app/alembic/
COPY --chown=app:app alembic.ini  /app/alembic.ini
COPY --chown=app:app start.sh     /app/start.sh
RUN chmod +x /app/start.sh

USER app

EXPOSE 8000

# Local-Docker convenience only — Cloud Run probes the port directly and
# ignores this directive.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,os,sys; \
        sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','8000')+'/health/live',timeout=3).status==200 else 1)"

# tini reaps zombies and forwards SIGTERM cleanly to start.sh → uvicorn.
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/app/start.sh"]
