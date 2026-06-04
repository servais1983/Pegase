# Installation

## Quick start (Docker Compose)

```bash
git clone https://github.com/servais1983/Pegase.git
cd Pegase
cp .env.example .env
# Generate a strong secret and write it into .env
python -c 'import secrets;print("PEGASE_SECRET_KEY="+secrets.token_urlsafe(64))' >> .env
docker compose up -d --build
```

The stack starts:

| service    | port  | description                              |
|------------|-------|------------------------------------------|
| postgres   | 5432  | persistent storage                       |
| redis      | 6379  | Celery broker + result backend           |
| api        | 8000  | FastAPI app + dashboard at `/`           |
| worker     | -     | Celery worker executing mission tasks    |

A migration container runs `alembic upgrade head` before the API starts.

### Bootstrap the first admin user

```bash
docker compose exec api python -m scripts.bootstrap_admin \
    PEGASE_ADMIN_USERNAME=admin \
    PEGASE_ADMIN_EMAIL=admin@example.org \
    PEGASE_ADMIN_PASSWORD='ChangeMeNow!'
```

(or, equivalently, pass them as environment variables to the container.)

Login at <http://localhost:8000>, or use the API directly:

```bash
curl -s -X POST http://localhost:8000/api/v1/auth/token \
    -d 'username=admin&password=ChangeMeNow!'
```

## Local development

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Postgres + Redis - the compose stack also exposes them on localhost.
docker compose up -d postgres redis

export PEGASE_DATABASE_SYNC_URL=postgresql+psycopg2://pegase:pegase@localhost:5432/pegase
export PEGASE_DATABASE_URL=postgresql+asyncpg://pegase:pegase@localhost:5432/pegase
export PEGASE_SECRET_KEY=dev-secret

alembic upgrade head
make run-api          # in one terminal
make run-worker       # in another
```

## Kubernetes (Helm)

A chart is provided in `helm/pegase/`. It deploys the API + worker, runs the
Alembic migration as a post-install hook, and (optionally) an audit-shipping
CronJob.

```bash
# 1) Create the secret out-of-band (NEVER commit secret values).
kubectl create secret generic pegase-secrets \
  --from-literal=PEGASE_SECRET_KEY="$(python -c 'import secrets;print(secrets.token_urlsafe(64))')" \
  --from-literal=PEGASE_DATABASE_URL="postgresql+asyncpg://user:pass@db:5432/pegase" \
  --from-literal=PEGASE_DATABASE_SYNC_URL="postgresql+psycopg2://user:pass@db:5432/pegase" \
  --from-literal=PEGASE_REDIS_URL="redis://redis:6379/0" \
  --from-literal=PEGASE_CELERY_BROKER_URL="redis://redis:6379/1" \
  --from-literal=PEGASE_CELERY_RESULT_BACKEND="redis://redis:6379/2"

# 2) Install
helm install pegase ./helm/pegase \
  --set image.tag=0.1.0 \
  --set api.ingress.enabled=true \
  --set api.ingress.host=pegase.example.com
```

Managed Postgres/Redis are recommended in production (`postgresql.external`
and `redis.external` default to `true`). Enable TLS at the Ingress with
`api.ingress.tls.enabled=true` + a cert-manager-issued secret.

## System requirements

* Python 3.11+
* PostgreSQL 14+
* Redis 6+
* `nmap` binary on PATH for the NetAssault module
* `whois` binary for WHOIS lookups (optional)

## Production hardening checklist

* set `PEGASE_ENVIRONMENT=production`
* set `PEGASE_SECRET_KEY` to a 64-byte URL-safe random value
* terminate TLS in front of the API (nginx, Traefik, AWS ALB ...)
* run Postgres + Redis behind a private network
* mount `/var/lib/pegase` on a persistent volume
* forward `/var/lib/pegase/audit.log` to immutable storage (e.g. S3 Object Lock, append-only WORM)
* keep `PEGASE_REQUIRE_AUTHORIZATION_TOKEN=true` (the default)
* configure `PEGASE_CORS_ORIGINS` to your dashboard origin only
* periodically run `pegase audit` to verify the hash chain
