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
| Modules      | 11 modules: `recon`, `netassault`, `webbreacher`, `socialmatrix`, `cloudstrike`, `mobilehunter`, `wirelessphantom`, `physicalvector`, `toolforge`, `vulnmatrix`, `postxploit`. |
| Scenarios    | ThreatSim engine: named multi-stage kill-chains (`recon-and-enumerate`, `external-apt`, `cloud-review`) + custom YAML. |
| Auth         | JWT access + refresh tokens, `/auth/refresh`, `/auth/logout` with Redis-backed revocation (jti blocklist). |
| Storage      | PostgreSQL via SQLAlchemy 2 (async) + Alembic migrations.                                                          |
| Async work   | Celery workers backed by Redis.                                                                                    |
| API / UI     | FastAPI REST (`/api/v1/...`), OpenAPI at `/docs`, dashboard at `/`.                                                |
| CLI          | `pegase` (click + rich) - scan, modules, audit verify, user management.                                            |
| Reporting    | JSON and stand-alone HTML reports per mission.                                                                     |
| Observability| `/healthz`, `/readyz`, `/metrics` (Prometheus), structured JSON logs (`structlog`).                                 |
| Deployment   | Multi-stage Dockerfile, non-root runtime, healthchecks; `docker compose up` brings up the full stack (postgres + redis + api + worker + nginx reverse proxy). Helm chart in `helm/pegase/` for Kubernetes. |
| CI           | GitHub Actions: ruff, mypy, pytest + coverage against real Postgres/Redis, Docker build, CodeQL. Pre-commit config bundled.                          |
| Hardening    | Per-IP rate limiting via SlowAPI, nginx reverse proxy with security headers, CronJob shipping audit log to S3 Object Lock for 7-year compliance retention. |

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
| `socialmatrix`| passive  | Phishing-simulation kit generator: per-recipient landing page + tracking token + consent-ledger entry in the audit log. **Does not send mail** - delivery is operator-controlled and out-of-band. Click events captured by the public `/track/{token}` endpoint. |
| `cloudstrike` | active   | Read-only AWS posture assessment via boto3: public S3 buckets, weak IAM password policy, users without MFA, stale access keys, security groups exposing sensitive ports to `0.0.0.0/0`. Use an `SecurityAudit` read-only role. |
| `mobilehunter`| passive  | Static Android APK analysis (built-in binary-manifest parser, no external deps): dangerous permissions, exported components without guards, debuggable/allowBackup/cleartext flags, embedded-secret heuristics. |
| `wirelessphantom`| passive | Analyzes airodump-ng CSV surveys: open/WEP/WPA1 networks, hidden SSIDs, clients probing for known networks (evil-twin exposure). Radio capture stays operator-side. |
| `physicalvector`| passive | Generates a structured physical-security assessment checklist (perimeter, badge access, server room, USB drop, ...) with operator-fillable observed/exploited status. |
| `toolforge`   | active   | Runs **allowlisted** third-party CLI tools (nuclei, nikto, whatweb, testssl, ...) with `{target}` substitution and `shell=False` - no command-injection surface. Every target is scope-checked. |
| `vulnmatrix`  | passive  | Correlates banners/fingerprints from upstream findings against a curated list of known-vulnerable versions; optional NVD CVE lookup. Runs **after** producers (`needs_upstream_findings`). |
| `postxploit`  | passive  | Consumer module that synthesises all findings into an attack-path graph (assets + pivot edges), rendered with D3 at `/graph` and served by `/api/v1/reports/{id}/graph.json`. |

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
pytest                      # 44 unit tests (scope, audit, auth+refresh+revocation,
                            #   orchestrator chaining, all modules, scenarios,
                            #   API routes + worker pipeline on in-memory SQLite)
pytest -m integration       # needs Postgres + Redis on localhost
```

The full Docker stack (postgres + redis + api + worker + nginx) has been
validated end-to-end: login → create mission → Celery worker runs real
recon/web modules → findings persisted → report + attack-graph served →
audit hash-chain verified (`pegase audit`).

CI runs the same matrix on every push (see [.github/workflows/ci.yml](.github/workflows/ci.yml)).

---

## Roadmap

The v0.1.0 platform now implements all the modules from the original concept
plus the attack-graph view. Delivered:

* ✅ SocialMatrix — phishing simulator with consent ledger.
* ✅ CloudStrike — read-only AWS posture checks.
* ✅ MobileHunter — static APK analysis.
* ✅ WirelessPhantom — airodump survey analysis.
* ✅ PhysicalVector — physical-security assessment scaffolding.
* ✅ ToolForge — allowlisted third-party tool integration.
* ✅ PostXploit — attack-path graph builder + D3 visualization.
* ✅ ThreatSim — multi-stage scenario engine.

Still on the horizon:

* **GCP / Azure** posture providers for CloudStrike (AWS is implemented today).
* **Richer Web UI** — a full SPA build (the current dashboard + D3 graph are
  dependency-free server-rendered pages).
* **Distributed mode** — Temporal.io workflow engine + multi-tenant
  segregation, replacing the single-Celery deployment for large engagements.
* **boto3 / androguard** are optional extras; install them to enable
  CloudStrike and the richer APK parse respectively.

---

## License

[AGPL-3.0-or-later](LICENSE). PEGASE is a legal pentest tool. Using it against
systems you do not own or are not explicitly authorized to test is illegal and
unethical.
