#!/usr/bin/env bash
# Bring up the documented compose stack plus the lab target, then run the
# live HTTP test. Generates a local .env when one is absent. Does not print
# the admin password.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if docker info >/dev/null 2>&1; then
  DOCKER=(docker)
else
  DOCKER=(sudo docker)
fi

COMPOSE=("${DOCKER[@]}" compose -f docker-compose.yml -f docker-compose.e2e.yml)

if [[ ! -f .env ]]; then
  SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(64))')"
  umask 077
  cat > .env <<EOF
PEGASE_ENVIRONMENT=production
PEGASE_SECRET_KEY=${SECRET}
PEGASE_DB_PASSWORD=pegase
PEGASE_LOG_LEVEL=INFO
PEGASE_AI_PROVIDER=offline
EOF
  echo "wrote .env (gitignored) with a generated PEGASE_SECRET_KEY"
fi

"${COMPOSE[@]}" up -d --build --wait

echo "waiting for API readiness"
for _ in $(seq 1 60); do
  if curl -fsS http://127.0.0.1/readyz >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
curl -fsS http://127.0.0.1/readyz >/dev/null

echo "waiting for the celery worker"
for _ in $(seq 1 30); do
  if "${COMPOSE[@]}" exec -T worker celery -A pegase.tasks.celery_app inspect ping >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
"${COMPOSE[@]}" exec -T worker celery -A pegase.tasks.celery_app inspect ping

STATE="$ROOT/.e2e-lab.env"
if [[ -z "${PEGASE_E2E_PASSWORD:-}" && -f "$STATE" ]]; then
  # shellcheck disable=SC1090
  source "$STATE"
fi
USER_NAME="${PEGASE_E2E_USERNAME:-labadmin}"
EMAIL="${PEGASE_E2E_EMAIL:-labadmin@example.org}"
if [[ -z "${PEGASE_E2E_PASSWORD:-}" ]]; then
  PEGASE_E2E_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
  umask 077
  cat > "$STATE" <<EOF
PEGASE_E2E_USERNAME=${USER_NAME}
PEGASE_E2E_PASSWORD=${PEGASE_E2E_PASSWORD}
EOF
fi

"${COMPOSE[@]}" exec -T \
  -e PEGASE_ADMIN_USERNAME="$USER_NAME" \
  -e PEGASE_ADMIN_EMAIL="$EMAIL" \
  -e PEGASE_ADMIN_PASSWORD="$PEGASE_E2E_PASSWORD" \
  api python -m scripts.bootstrap_admin

export PEGASE_E2E_BASE_URL="${PEGASE_E2E_BASE_URL:-http://127.0.0.1}"
export PEGASE_E2E_USERNAME="$USER_NAME"
export PEGASE_E2E_PASSWORD
export PEGASE_E2E_REDIS_URL="${PEGASE_E2E_REDIS_URL:-redis://127.0.0.1:6379/0}"

python3 -m pytest -m e2e tests/e2e -ra --tb=short
