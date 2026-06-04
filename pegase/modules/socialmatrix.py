"""SocialMatrix - phishing simulation with consent ledger.

This module **does not send email**. Sending is intentionally outside its
scope, because reliable, ethical phishing simulation requires an out-of-band
delivery channel that the operator controls (corporate SMTP relay, dedicated
domain, DKIM/DMARC alignment with the customer's records).

What SocialMatrix produces:

* a templated landing page (HTML + tracker), copied into the mission's
  artifact directory,
* a per-recipient unique tracking token,
* a "consent ledger" entry in the immutable audit log for every targeted
  recipient, so a third-party auditor can prove that authorization existed
  before any communication was sent.

The accompanying API exposes a public ``/track/{token}`` endpoint that
records the click event in the database without leaking who clicked back to
a third party.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from pathlib import Path
from typing import Any

from jinja2 import Environment, select_autoescape

from pegase.core.audit import get_audit_log
from pegase.core.config import get_settings
from pegase.core.logging import get_logger
from pegase.core.scope import ActionType, ScopeGuard
from pegase.modules.base import Finding, Module, ModuleResult

log = get_logger(__name__)

_TEMPLATES: dict[str, str] = {
    "generic-login": """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>{{ brand }} sign-in</title>
<style>body{font-family:-apple-system,Segoe UI,sans-serif;background:#f4f5f7;
display:flex;justify-content:center;padding:80px}
.card{background:#fff;padding:32px;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.08);width:360px}
.warn{background:#fff3cd;border:1px solid #ffeeba;padding:10px;border-radius:4px;
color:#856404;font-size:12px;margin-bottom:16px}
input{width:100%;padding:10px;margin:6px 0;border:1px solid #ccc;border-radius:4px}
button{width:100%;padding:10px;background:#0366d6;color:#fff;border:0;border-radius:4px}
</style></head><body><div class="card">
<div class="warn">⚠ Security awareness simulation - this is not a real login page.
Reference: {{ campaign }}</div>
<h2>{{ brand }}</h2>
<form action="/track/{{ token }}" method="POST">
  <input name="username" placeholder="username" autocomplete="off">
  <input name="password" type="password" placeholder="password" autocomplete="off">
  <button type="submit">Sign in</button>
</form></div></body></html>""",
}


class SocialMatrix(Module):
    name = "socialmatrix"
    description = (
        "Phishing-simulation kit generator with consent ledger. "
        "Produces artifacts only; sending is out-of-band and operator-controlled."
    )
    action_type = ActionType.PASSIVE

    async def run(
        self,
        *,
        targets: list[str],
        guard: ScopeGuard,
        parameters: dict[str, Any] | None = None,
    ) -> ModuleResult:
        params = parameters or {}
        recipients: list[dict[str, str]] = params.get("recipients", [])
        brand: str = params.get("brand", "Acme Corp")
        template_name: str = params.get("template", "generic-login")
        campaign_id: str = params.get("campaign_id") or secrets.token_urlsafe(8)
        consent_proof: str | None = params.get("consent_proof")

        if not recipients:
            raise ValueError(
                "socialmatrix requires a non-empty 'recipients' parameter."
            )
        if not consent_proof:
            raise ValueError(
                "socialmatrix requires a 'consent_proof' parameter "
                "(reference to the signed RoE clause that covers phishing simulation)."
            )
        if template_name not in _TEMPLATES:
            raise ValueError(
                f"unknown template '{template_name}'. "
                f"available: {sorted(_TEMPLATES)}"
            )

        env = Environment(autoescape=select_autoescape())
        tmpl = env.from_string(_TEMPLATES[template_name])

        settings = get_settings()
        artifact_root = Path(settings.artifact_dir) / "socialmatrix" / campaign_id
        artifact_root.mkdir(parents=True, exist_ok=True)

        audit = get_audit_log()
        result = ModuleResult(module=self.name)
        result.raw["campaign_id"] = campaign_id
        result.raw["template"] = template_name
        result.raw["consent_proof"] = consent_proof
        result.raw["recipients"] = []

        for rec in recipients:
            email = rec.get("email")
            display_name = rec.get("name", "")
            if not email:
                continue
            # Re-check scope: the recipient's email-domain MUST be in scope.
            domain = email.split("@", 1)[1] if "@" in email else email
            guard.check(domain, self.action_type)

            token = secrets.token_urlsafe(24)
            page_html = tmpl.render(
                brand=brand, campaign=campaign_id, token=token
            )
            page_path = artifact_root / f"{token}.html"
            page_path.write_text(page_html, encoding="utf-8")

            consent_record = {
                "campaign": campaign_id,
                "recipient_email_hash": hashlib.sha256(
                    email.encode("utf-8")
                ).hexdigest(),
                "display_name": display_name,
                "consent_proof": consent_proof,
                "template": template_name,
                "token": token,
            }
            audit.append(
                action="socialmatrix.consent_recorded",
                actor=params.get("operator", "system"),
                mission=params.get("mission_id", "system"),
                target=domain,
                meta=consent_record,
            )
            result.raw["recipients"].append(
                {
                    "email_hash": consent_record["recipient_email_hash"],
                    "token": token,
                    "artifact": str(page_path),
                }
            )

        # Index file for the operator
        index_path = artifact_root / "campaign.json"
        index_path.write_text(
            json.dumps(
                {
                    "campaign_id": campaign_id,
                    "brand": brand,
                    "template": template_name,
                    "consent_proof": consent_proof,
                    "recipients": result.raw["recipients"],
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        result.findings.append(
            Finding(
                module=self.name,
                target=brand,
                title=f"Phishing-sim campaign prepared ({len(result.raw['recipients'])} recipients)",
                description=(
                    f"Generated landing pages and consent records for campaign "
                    f"{campaign_id}. Artifacts in {artifact_root}. Sending is "
                    "out-of-band and gated by the operator."
                ),
                severity="info",
                evidence={"campaign_id": campaign_id, "artifact_dir": str(artifact_root)},
                references=[
                    "https://www.cisa.gov/news-events/news/avoiding-social-engineering-and-phishing-attacks",
                ],
            )
        )
        return result
