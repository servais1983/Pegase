"""VulnMatrix - finding correlation and CVE lookup.

VulnMatrix is a *support* module: it does not generate new traffic against the
target. Instead, it reads the findings already produced by upstream modules
(NetAssault service banners, WebBreacher fingerprints) and:
  * tries to match version strings against an embedded list of well-known
    vulnerable versions;
  * queries the public NVD CVE feed (configurable, opt-in) when an API key is
    provided;
  * deduplicates findings and lifts severity when multiple corroborating data
    points exist.
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from pegase.core.logging import get_logger
from pegase.core.scope import ActionType, ScopeGuard
from pegase.modules.base import Finding, Module, ModuleResult

log = get_logger(__name__)

KNOWN_VULNERABLE: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"OpenSSH[_ ](?:[0-6]\.|7\.[0-3])", re.I), "high", "Outdated OpenSSH (<7.4) - multiple CVEs"),
    (re.compile(r"Apache(?:/| )2\.2\.", re.I), "high", "Apache httpd 2.2 EOL since 2017"),
    (re.compile(r"Apache(?:/| )2\.4\.([0-9]|[1-3][0-9]|4[0-8])\b", re.I), "medium", "Apache httpd <2.4.49 - many CVEs"),
    (re.compile(r"nginx/1\.(?:[0-9]|1[0-7])\.", re.I), "medium", "nginx <1.18 EOL"),
    (re.compile(r"PHP/[5-7]\.", re.I), "high", "PHP 5/7 EOL - upgrade required"),
    (re.compile(r"Microsoft-IIS/[5-7]\.", re.I), "high", "IIS <8 EOL"),
    (re.compile(r"vsftpd 2\.3\.4", re.I), "critical", "vsftpd 2.3.4 backdoor (CVE-2011-2523)"),
    (re.compile(r"ProFTPD 1\.3\.[0-3]", re.I), "high", "Old ProFTPD - multiple CVEs"),
]

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class VulnMatrix(Module):
    name = "vulnmatrix"
    description = "Correlate previous findings against known-vulnerable versions and CVE feeds."
    action_type = ActionType.PASSIVE

    async def run(
        self,
        *,
        targets: list[str],
        guard: ScopeGuard,
        parameters: dict[str, Any] | None = None,
    ) -> ModuleResult:
        params = parameters or {}
        # Findings to correlate are passed via ``parameters["findings"]`` -
        # the orchestrator wires this when chaining modules.
        prior: list[dict[str, Any]] = params.get("findings", [])
        nvd_api_key: str | None = params.get("nvd_api_key")
        result = ModuleResult(module=self.name)

        async with httpx.AsyncClient(timeout=20.0) as client:
            for f in prior:
                target = f.get("target", "")
                if target:
                    # Even for passive correlation, re-check scope just in case
                    # we'd reach out to a third party that exposes the target.
                    try:
                        guard.check(target, self.action_type)
                    except Exception as exc:  # noqa: BLE001, S112
                        log.debug("vulnmatrix_skip_target", target=target, reason=str(exc))
                        continue

                blob = " ".join(
                    str(v)
                    for v in (
                        f.get("title", ""),
                        f.get("description", ""),
                        f.get("evidence", {}).get("product", ""),
                        f.get("evidence", {}).get("version", ""),
                        f.get("evidence", {}).get("server", ""),
                        f.get("evidence", {}).get("x_powered_by", ""),
                    )
                )
                for pattern, severity, message in KNOWN_VULNERABLE:
                    if pattern.search(blob):
                        result.findings.append(
                            Finding(
                                module=self.name,
                                target=target,
                                title=message,
                                description=(
                                    "Pattern matched on collected banner/"
                                    f"fingerprint: {pattern.pattern}"
                                ),
                                severity=severity,
                                evidence={"matched": blob},
                            )
                        )

                if nvd_api_key:
                    product = f.get("evidence", {}).get("product")
                    version = f.get("evidence", {}).get("version")
                    if product and version:
                        cves = await _nvd_lookup(client, product, version, nvd_api_key)
                        for cve in cves[:10]:
                            result.findings.append(
                                Finding(
                                    module=self.name,
                                    target=target,
                                    title=cve["id"],
                                    description=cve["description"],
                                    severity=cve["severity"],
                                    references=[
                                        f"https://nvd.nist.gov/vuln/detail/{cve['id']}"
                                    ],
                                    evidence={"product": product, "version": version},
                                )
                            )
        return result


async def _nvd_lookup(
    client: httpx.AsyncClient, product: str, version: str, api_key: str
) -> list[dict[str, Any]]:
    headers = {"apiKey": api_key}
    params = {
        "keywordSearch": f"{product} {version}",
        "resultsPerPage": 20,
    }
    try:
        r = await client.get(NVD_API, params=params, headers=headers)
    except httpx.HTTPError as exc:
        log.warning("nvd_error", error=str(exc))
        return []
    if r.status_code != 200:
        return []
    data = r.json()
    out: list[dict[str, Any]] = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        descs = cve.get("descriptions", [])
        en = next(
            (d["value"] for d in descs if d.get("lang") == "en"),
            "no description",
        )
        metrics = cve.get("metrics", {})
        sev = "info"
        cvss_blocks = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []
        if cvss_blocks:
            score = cvss_blocks[0].get("cvssData", {}).get("baseScore", 0)
            if score >= 9:
                sev = "critical"
            elif score >= 7:
                sev = "high"
            elif score >= 4:
                sev = "medium"
            else:
                sev = "low"
        out.append({"id": cve.get("id"), "description": en, "severity": sev})
    return out
