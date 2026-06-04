# Security Policy

## Reporting a vulnerability

Email `security@pegase-pentest.org` (PGP key on request) with:
* a clear description of the issue,
* a minimal proof of concept,
* affected versions and configurations.

We aim to acknowledge reports within **72 hours** and to publish a fix or
mitigation within **30 days** for high/critical issues.

Do **not** open public GitHub issues for security reports.

## Acceptable use

PEGASE is a legal pentesting framework. By using it you commit to running
it **only against systems for which you have explicit, written authorization**.
Every mission carries an authorization token; the runtime refuses any module
execution without one (`PEGASE_REQUIRE_AUTHORIZATION_TOKEN=true`, default).

The platform produces an immutable, hash-chained audit trail of every action
- including refusals - to support forensic review and legal compliance.

## Hardening summary

* TLS termination is left to the operator (reverse proxy in front of the API).
* Secrets (`PEGASE_SECRET_KEY`, DB password) must come from a secret manager,
  not from the image or VCS.
* The container runs as a non-root user.
* Postgres and Redis MUST NOT be exposed publicly. The default compose file
  binds them to `127.0.0.1` only.
* Audit logs SHOULD be streamed off-host to immutable storage.
