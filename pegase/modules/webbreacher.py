"""WebBreacher - HTTP application surface scanner.

For each target URL we:
  * fetch ``/`` and inspect security-relevant headers,
  * try a small list of well-known sensitive paths (robots.txt, .env, etc.),
  * fingerprint the server based on ``Server`` / ``X-Powered-By`` headers.

The implementation deliberately stays read-only (HTTP GET / HEAD only) - it is
NOT a fuzzer, an exploit framework, or a credential-stuffing tool. Anything
heavier belongs in dedicated, opt-in modules.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import httpx

from pegase.core.logging import get_logger
from pegase.core.scope import ActionType, ScopeGuard
from pegase.modules.base import Finding, Module, ModuleResult

log = get_logger(__name__)

SECURITY_HEADERS: dict[str, str] = {
    "strict-transport-security": "HSTS not enforced",
    "content-security-policy": "No Content-Security-Policy",
    "x-content-type-options": "Missing X-Content-Type-Options: nosniff",
    "x-frame-options": "Clickjacking protection missing (X-Frame-Options)",
    "referrer-policy": "Referrer-Policy not set",
    "permissions-policy": "Permissions-Policy not set",
}

SENSITIVE_PATHS: list[tuple[str, str]] = [
    ("/.env", "high"),
    ("/.git/config", "high"),
    ("/.DS_Store", "medium"),
    ("/server-status", "medium"),
    ("/phpinfo.php", "high"),
    ("/admin", "low"),
    ("/wp-admin/", "low"),
    ("/robots.txt", "info"),
    ("/sitemap.xml", "info"),
    ("/swagger.json", "low"),
    ("/openapi.json", "low"),
]


class WebBreacher(Module):
    name = "webbreacher"
    description = "HTTP surface scanner: security headers, sensitive endpoints, fingerprint."
    action_type = ActionType.ACTIVE

    async def run(
        self,
        *,
        targets: list[str],
        guard: ScopeGuard,
        parameters: dict[str, Any] | None = None,
    ) -> ModuleResult:
        params = parameters or {}
        timeout = float(params.get("timeout", 10.0))
        check_paths = bool(params.get("check_paths", True))
        user_agent = params.get("user_agent", "PEGASE/0.1 (+pentest)")

        result = ModuleResult(module=self.name)
        headers = {"User-Agent": user_agent}

        # verify=False is deliberate: this module is a pentest probe and must
        # not refuse to enumerate targets that have misconfigured or self-signed
        # certificates - those are findings we want to report on.
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            headers=headers,
            verify=False,  # noqa: S501 - intentional, see comment above
        ) as client:
            for target in targets:
                url = _ensure_url(target)
                guard.check(url, self.action_type)
                log.info("web_scan", url=url)
                try:
                    resp = await client.get(url)
                except httpx.HTTPError as exc:
                    result.findings.append(
                        Finding(
                            module=self.name,
                            target=url,
                            title="HTTP request failed",
                            description=str(exc),
                            severity="info",
                        )
                    )
                    continue

                lower_headers = {k.lower(): v for k, v in resp.headers.items()}
                result.raw.setdefault(url, {})["headers"] = dict(resp.headers)
                result.raw[url]["status"] = resp.status_code

                # Fingerprint
                server = lower_headers.get("server")
                powered = lower_headers.get("x-powered-by")
                if server or powered:
                    result.findings.append(
                        Finding(
                            module=self.name,
                            target=url,
                            title="Server fingerprint",
                            description=(
                                f"Server={server!r}, X-Powered-By={powered!r}"
                            ),
                            severity="low",
                            evidence={"server": server, "x_powered_by": powered},
                        )
                    )

                # Missing security headers
                for header, message in SECURITY_HEADERS.items():
                    if header in lower_headers:
                        continue
                    if header == "strict-transport-security" and not url.startswith(
                        "https://"
                    ):
                        continue
                    result.findings.append(
                        Finding(
                            module=self.name,
                            target=url,
                            title=message,
                            description=(
                                f"Recommended HTTP response header '{header}' is "
                                "absent. This weakens the browser-side hardening."
                            ),
                            severity="low",
                            references=[
                                "https://owasp.org/www-project-secure-headers/"
                            ],
                        )
                    )

                # Sensitive paths
                if check_paths:
                    base = _normalize_base(url)
                    for path, severity in SENSITIVE_PATHS:
                        probe = base.rstrip("/") + path
                        try:
                            r = await client.get(probe)
                        except httpx.HTTPError:
                            continue
                        if r.status_code < 400 and len(r.content) > 0:
                            result.findings.append(
                                Finding(
                                    module=self.name,
                                    target=probe,
                                    title=f"Sensitive path exposed: {path}",
                                    description=(
                                        f"Path {path} returned HTTP {r.status_code} "
                                        f"({len(r.content)} bytes). Confirm whether "
                                        "exposure is intentional."
                                    ),
                                    severity=severity,
                                    evidence={
                                        "status": r.status_code,
                                        "length": len(r.content),
                                        "content_type": r.headers.get("content-type"),
                                    },
                                )
                            )
        return result


def _ensure_url(target: str) -> str:
    if "://" in target:
        return target
    return f"https://{target}"


def _normalize_base(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"
