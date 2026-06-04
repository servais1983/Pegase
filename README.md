![PEGASE](pgase.png)

# PEGASE — Penetration Engagement for Global Attack Simulation & Evasion

<div align="center">
  <img src="docs/images/pentest-badge.svg" alt="Pentest">
  <img src="docs/images/security-badge.svg" alt="Security">
  <img src="docs/images/license-badge.svg" alt="AGPL v3">
</div>

PEGASE is a **multi-vector legal pentest orchestration platform**. It
coordinates passive, active and (opt-in) exploit modules against a clearly
scoped engagement, with built-in Rules-of-Engagement enforcement, an immutable
hash-chained audit log, and a REST API + CLI.

> No demo mode. Every module talks to real targets. Every action is
> authorization-gated and audit-logged.

---

## What is in the box (v0.1.0)

| Layer        | Implementation                                                                                                    |
|--------------|-------------------------------------------------------------------------------------------------------------------|
| Core         | Mission orchestrator, async runtime, JWT auth, hash-chained audit log, RoE / scope guard.                          |
| Modules      | `recon` (DNS + WHOIS + CT-logs), `netassault` (nmap), `webbreacher` (HTTP surface), `vulnmatrix` (correlation + opt-in NVD). |
| Storage      | PostgreSQL via SQLAlchemy 2 (async) + Alembic migrations.                                                          |
| Async work   | Celery workers backed by Redis.                                                                                    |
| API / UI     | FastAPI REST (`/api/v1/...`), OpenAPI at `/docs`, dashboard at `/`.                                                |
| CLI          | `pegase` (click + rich) - scan, modules, audit verify, user management.                                            |
| Reporting    | JSON and stand-alone HTML reports per mission.                                                                     |
| Observability| `/healthz`, `/readyz`, `/metrics` (Prometheus), structured JSON logs (`structlog`).                                 |
| Deployment   | Multi-stage Dockerfile, non-root runtime, healthchecks; `docker compose up` brings up the full stack.              |
| CI           | GitHub Actions: ruff, pytest + coverage against real Postgres/Redis, Docker build, CodeQL.                          |

---

## Quick start

```bash
git clone https://github.com/servais1983/Pegase.git
cd Pegase
cp .env.example .env
python -c 'import secrets;print("PEGASE_SECRET_KEY="+secrets.token_urlsafe(64))' >> .env

docker compose up -d --build

# Create the first admin user
docker compose exec api python -m scripts.bootstrap_admin \
  PEGASE_ADMIN_USERNAME=admin \
  PEGASE_ADMIN_EMAIL=admin@example.org \
  PEGASE_ADMIN_PASSWORD='ChangeMeNow!'

# Open http://localhost:8000  -> dashboard
# Open http://localhost:8000/docs -> OpenAPI
```

Local development without Docker is covered in [docs/installation/installation.md](docs/installation/installation.md).

---

## Run a real mission

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/token \
  -d 'username=admin&password=ChangeMeNow!' | jq -r .access_token)

# 1) declare the engagement (scope + authorization token)
MISSION=$(curl -s -X POST http://localhost:8000/api/v1/missions \
  -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "name": "scanme-test",
    "client": "Nmap.org public lab",
    "targets": ["scanme.nmap.org"],
    "scope_rules": [{"pattern": "scanme.nmap.org"}],
    "allowed_actions": ["passive", "active"],
    "authorization_token": "ROE-public-scanme.nmap.org"
  }' | jq -r .id)

# 2) launch
curl -X POST http://localhost:8000/api/v1/missions/$MISSION/run \
  -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"modules": ["recon", "netassault", "webbreacher", "vulnmatrix"]}'

# 3) read the report
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/reports/$MISSION.html > report.html
```

Same thing from the CLI (no API needed):

```bash
pegase scan \
  --target scanme.nmap.org \
  --module recon --module webbreacher \
  --authorization "ROE-public-scanme.nmap.org" \
  --allow-active \
  --output report.json
```

---

## Architecture

```
            ┌──────────────────────────────────┐
            │           FastAPI API            │
            │  /api/v1/{auth,missions,...}     │
            │  /docs   /metrics  /healthz      │
            └──────────────┬───────────────────┘
                           │
                  enqueues │ Celery task
                           ▼
            ┌──────────────────────────────────┐
            │          Celery worker           │
            │  ┌────────────────────────────┐  │
            │  │       Orchestrator         │  │
            │  │   (asyncio + semaphore)    │  │
            │  └─────────────┬──────────────┘  │
            │                │                 │
            │  ┌─────────────▼──────────────┐  │
            │  │        ScopeGuard          │  │
            │  │  RoE + authorization +     │  │
            │  │  time window + CIDR/host   │  │
            │  └─────────────┬──────────────┘  │
            │                │                 │
            │   recon  netassault  webbreacher │
            │   vulnmatrix                     │
            └──────────────┬───────────────────┘
                           │
   ┌───────────────┐       │      ┌────────────────────┐
   │   PostgreSQL  │◀──────┼─────▶│  Audit log (hash   │
   │ missions +    │       │      │  chain, append-only)│
   │ findings +    │       │      └────────────────────┘
   │ users         │       │
   └───────────────┘       ▼
                    Redis (broker + result)
```

Detailed design notes live in [`docs/architecture/architecture_globale.md`](docs/architecture/architecture_globale.md).

---

## Modules

| name          | type     | what it actually does                                                                |
|---------------|----------|--------------------------------------------------------------------------------------|
| `recon`       | passive  | A/AAAA/MX/NS/TXT/CNAME/SOA via `dnspython`, WHOIS via `python-whois`, subdomain harvesting from <https://crt.sh>. |
| `netassault`  | active   | Wraps `nmap` via `python-nmap`. Default profile: `-sT -sV -Pn -T3 1-1024`. Tunable via mission parameters. |
| `webbreacher` | active   | HTTP fingerprinting, OWASP-secure-headers audit, probes for a short list of common sensitive paths (`.env`, `.git/config`, `server-status`, ...). |
| `vulnmatrix`  | passive  | Correlates banners/fingerprints from upstream findings against a curated list of known-vulnerable versions; optional NVD CVE lookup when an API key is supplied. |

Modules conform to a single ABC (`pegase.modules.base.Module`) so adding a new
one is a single file + an entry in `available_modules()`.

---

## Safety model

* `PEGASE_REQUIRE_AUTHORIZATION_TOKEN=true` (default) — no mission can leave
  `draft` state without an authorization token, and the worker rejects runs
  that lose the token at the last second.
* `ScopeGuard` re-validates **every** target/action pair against the mission's
  rules at call time. Out-of-scope hits raise `ScopeViolation`, are logged to
  the audit chain and surfaced as `403 scope_violation` over the API.
* Audit log (`/var/lib/pegase/audit.log`) is append-only and hash-chained.
  `pegase audit` verifies the chain end-to-end.
* The container runs as a non-root user; the default compose binds Postgres
  and Redis to `127.0.0.1` only.
* Reporting and findings retain raw evidence — operators decide what to share
  with the client.

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure process.

---

## Testing

```bash
pip install -e ".[dev]"
ruff check pegase tests
pytest                      # unit tests
pytest -m integration       # needs Postgres + Redis on localhost
```

CI runs the same matrix on every push (see [.github/workflows/ci.yml](.github/workflows/ci.yml)).

---

## Roadmap

The v0.1.0 foundation is wired end-to-end and production-deployable. The
following are the next concrete chunks of work — they extend, but do not
break, the public API/CLI:

* **SocialMatrix** — phishing campaign simulator with consent ledger.
* **CloudStrike** — IAM posture checks (AWS/GCP/Azure) via read-only roles.
* **MobileHunter** / **WirelessPhantom** — pluggable adapters once we have a
  ToolForge wrapper.
* **PostXploit** — gated, explicit-consent post-exploit graph builder.
* **Web UI** — replace the minimal Jinja dashboard with the planned Vue.js +
  D3.js attack-graph view.
* **Distributed mode** — Temporal.io workflow engine + multi-tenant
  segregation, replacing the single-Celery deployment for large engagements.

---

## License

[AGPL-3.0-or-later](LICENSE). PEGASE is a legal pentest tool. Using it against
systems you do not own or are not explicitly authorized to test is illegal and
unethical.
