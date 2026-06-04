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
| `vulnmatrix`  | passive  | Correlates banners against known-vulnerable versions and (opt-in) the NVD CVE feed. |

`netassault` defaults to `-sT` (TCP connect) so it works unprivileged. Run the
container with `--cap-add=NET_RAW` to enable `-sS` (SYN scan).
