# User guide

## Concepts

* **Mission** - a scoped engagement. Owns targets, RoE/scope rules, time window
  and an authorization token signed by the client.
* **Module** - an executable unit (`recon`, `netassault`, `webbreacher`,
  `vulnmatrix`). Each module declares its `action_type`
  (`passive`/`active`/`exploit`).
* **ScopeGuard** - sits between every module and every target. Refuses anything
  the mission has not authorized.
* **Finding** - persistent result with severity, evidence and references.
* **Audit log** - append-only, hash-chained file at
  `/var/lib/pegase/audit.log`. Every mission action goes through it.

## Lifecycle of a mission

```
draft -> authorized -> running -> completed | failed
```

A mission may only move into `running` once it has both targets and an
`authorization_token`. The transition is performed by `POST /api/v1/missions/{id}/run`.

## CLI

```bash
pegase modules
pegase user create --username admin --email a@x.io --role admin
pegase audit                     # verify the chain
pegase scan \
    --target scanme.nmap.org \
    --module recon \
    --authorization "ROE-2026-001"
```

Add `--allow-active` to also run active modules (e.g. `netassault`,
`webbreacher`). `--allow-exploit` is reserved for explicit exploit modules and
must be tied to an out-of-band approval.

## REST API

OpenAPI is served at `/docs`. The high-level flow:

```bash
# 1. login
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/token \
     -d 'username=admin&password=...' | jq -r .access_token)
H="Authorization: Bearer $TOKEN"

# 2. create a mission
MISSION=$(curl -s -X POST http://localhost:8000/api/v1/missions \
     -H "$H" -H 'content-type: application/json' \
     -d '{
       "name": "Customer-X-Q2",
       "client": "Customer X",
       "targets": ["app.customer-x.example"],
       "scope_rules": [{"pattern": "*.customer-x.example"}],
       "allowed_actions": ["passive", "active"],
       "authorization_token": "ROE-2026-001"
     }' | jq -r .id)

# 3. queue a run
curl -X POST http://localhost:8000/api/v1/missions/$MISSION/run \
     -H "$H" -H 'content-type: application/json' \
     -d '{"modules": ["recon", "webbreacher"]}'

# 4. read findings / report
curl -H "$H" http://localhost:8000/api/v1/findings?mission_id=$MISSION
curl -H "$H" http://localhost:8000/api/v1/reports/$MISSION.html > report.html
```

## Modules

| module        | type     | summary                                                  |
|---------------|----------|----------------------------------------------------------|
| `recon`       | passive  | DNS (A/AAAA/MX/NS/TXT/CNAME/SOA), WHOIS, CT-log subs.    |
| `netassault`  | active   | `nmap` TCP scan with service/version detection.          |
| `webbreacher` | active   | HTTP headers, fingerprint, common sensitive paths.       |
| `socialmatrix`| passive  | Phishing-sim kit generator: landing page + tracking token + consent ledger. Never sends mail. |
| `vulnmatrix`  | passive  | Correlates banners against known-vulnerable versions and (opt-in) the NVD CVE feed. Runs after producers. |

`netassault` defaults to `-sT` (TCP connect) so it works unprivileged. Run the
container with `--cap-add=NET_RAW` to enable `-sS` (SYN scan).

## Module chaining

The orchestrator runs in two phases. "Producer" modules (`recon`,
`netassault`, `webbreacher`, `socialmatrix`) run concurrently. Any module that
declares `needs_upstream_findings = True` (currently `vulnmatrix`) runs
afterwards and receives the consolidated finding list via
`parameters["<module>"]["findings"]`. So a mission with
`["netassault", "vulnmatrix"]` automatically feeds nmap banners into the CVE
correlator - no manual wiring needed.

## Mission templates

Ready-to-edit YAML templates live in `missions/templates/`:

| template                  | purpose                                            |
|---------------------------|----------------------------------------------------|
| `standard.yaml`           | external-perimeter baseline (recon + net + web)    |
| `full-stack.yaml`         | full chain incl. vulnmatrix correlation            |
| `phishing-awareness.yaml` | SocialMatrix campaign (delivery stays operator-side)|

Validate one before use:

```bash
pegase template missions/templates/standard.yaml
```

## SocialMatrix & phishing simulation

SocialMatrix **never sends email**. It generates, per recipient:

* a landing page (with a visible "this is a simulation" banner),
* a unique tracking token,
* a `socialmatrix.consent_recorded` entry in the immutable audit log,
  carrying a SHA-256 of the recipient address and the `consent_proof`
  reference to the signed RoE clause.

It refuses to run without a `consent_proof` parameter and re-checks that every
recipient's email domain is in scope. Delivery is performed out-of-band by the
operator using the generated `campaign.json` manifest. Click-throughs are
captured by the public `POST/GET /track/{token}` endpoint, which stores only
the opaque token, a hashed source IP and the user-agent - no recipient PII.

## Audit log shipping (compliance)

For long-term, tamper-evident retention, ship rotated audit segments to S3
Object Lock:

```bash
PEGASE_AUDIT_S3_BUCKET=my-audit-bucket \
PEGASE_AUDIT_RETENTION_DAYS=2555 \
python -m scripts.ship_audit_to_s3
```

The script verifies the chain before rotating, then uploads with
`ObjectLockMode=COMPLIANCE`. In Kubernetes this runs as the
`audit-ship` CronJob (enable it in `helm/pegase/values.yaml`).
