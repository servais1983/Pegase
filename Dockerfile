# syntax=docker/dockerfile:1.6
FROM python:3.12-slim-bookworm AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        nmap \
        whois \
        ca-certificates \
        curl \
        tini \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# --- builder stage ---
FROM base AS builder
COPY pyproject.toml ./
COPY pegase ./pegase
COPY alembic ./alembic
COPY alembic.ini ./
RUN pip install --upgrade pip build \
 && pip install .

# --- runtime stage ---
FROM base AS runtime

RUN groupadd --system pegase \
 && useradd  --system --gid pegase --home /var/lib/pegase --create-home pegase \
 && mkdir -p /var/lib/pegase/artifacts \
 && chown -R pegase:pegase /var/lib/pegase

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

COPY pegase ./pegase
COPY alembic ./alembic
COPY alembic.ini ./
COPY frontend ./frontend
COPY scripts ./scripts

USER pegase

ENV PEGASE_AUDIT_LOG_PATH=/var/lib/pegase/audit.log \
    PEGASE_ARTIFACT_DIR=/var/lib/pegase/artifacts

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS http://localhost:8000/healthz || exit 1

ENTRYPOINT ["tini", "--"]
CMD ["pegase-api"]
