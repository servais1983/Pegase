"""ReconSphere - passive reconnaissance.

Performs DNS lookups (A, AAAA, MX, NS, TXT), WHOIS, and TLS certificate
metadata gathering via crt.sh. All operations are passive: the target itself
is never touched. Even so, every action passes through the ``ScopeGuard``
because authorization to perform recon is still required by most engagement
rules.
"""

from __future__ import annotations

import asyncio
import socket
from typing import Any

import dns.asyncresolver
import dns.exception
import httpx

try:
    import whois  # python-whois
except ImportError:  # pragma: no cover
    whois = None  # type: ignore[assignment]

from pegase.core.logging import get_logger
from pegase.core.scope import ActionType, ScopeGuard
from pegase.modules.base import Finding, Module, ModuleResult

log = get_logger(__name__)

_DNS_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")


class ReconSphere(Module):
    name = "recon"
    description = "Passive reconnaissance (DNS, WHOIS, certificate transparency)."
    action_type = ActionType.PASSIVE

    async def run(
        self,
        *,
        targets: list[str],
        guard: ScopeGuard,
        parameters: dict[str, Any] | None = None,
    ) -> ModuleResult:
        params = parameters or {}
        include_ct = bool(params.get("ct_logs", True))
        include_whois = bool(params.get("whois", True))
        result = ModuleResult(module=self.name)

        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            for target in targets:
                guard.check(target, self.action_type)
                host = _host_only(target)
                log.info("recon_target", target=host)

                dns_info = await _resolve_all(host)
                result.raw.setdefault("dns", {})[host] = dns_info

                if dns_info.get("error"):
                    result.findings.append(
                        Finding(
                            module=self.name,
                            target=host,
                            title="DNS resolution failed",
                            description=dns_info["error"],
                            severity="info",
                            evidence=dns_info,
                        )
                    )
                else:
                    result.findings.append(
                        Finding(
                            module=self.name,
                            target=host,
                            title="DNS records collected",
                            description=(
                                f"Collected DNS records for {host}: "
                                f"{sorted(dns_info.get('records', {}).keys())}"
                            ),
                            severity="info",
                            evidence=dns_info,
                        )
                    )

                if include_whois:
                    w = await asyncio.to_thread(_whois_lookup, host)
                    result.raw.setdefault("whois", {})[host] = w
                    if w:
                        result.findings.append(
                            Finding(
                                module=self.name,
                                target=host,
                                title="WHOIS metadata",
                                description=(
                                    f"Registrar={w.get('registrar')}, "
                                    f"creation={w.get('creation_date')}"
                                ),
                                severity="info",
                                evidence=w,
                            )
                        )

                if include_ct:
                    subs = await _crtsh_subdomains(client, host)
                    result.raw.setdefault("ct", {})[host] = subs
                    if subs:
                        result.findings.append(
                            Finding(
                                module=self.name,
                                target=host,
                                title=f"{len(subs)} subdomains from CT logs",
                                description=(
                                    "Subdomains discovered via certificate "
                                    "transparency: " + ", ".join(sorted(subs)[:20])
                                    + (" ..." if len(subs) > 20 else "")
                                ),
                                severity="info",
                                evidence={"subdomains": sorted(subs)},
                                references=[f"https://crt.sh/?q=%25.{host}"],
                            )
                        )
        return result


# ---------------------------------------------------------------------------


def _host_only(target: str) -> str:
    if "://" in target:
        from urllib.parse import urlparse

        return (urlparse(target).hostname or target).lower()
    return target.lower()


async def _resolve_all(host: str) -> dict[str, Any]:
    try:
        # Skip DNS records when target is literal IP
        socket.inet_pton(socket.AF_INET, host)
        return {"records": {"A": [host]}, "ip_literal": True}
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return {"records": {"AAAA": [host]}, "ip_literal": True}
    except OSError:
        pass

    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 10.0
    records: dict[str, list[str]] = {}
    for rrtype in _DNS_TYPES:
        try:
            answer = await resolver.resolve(host, rrtype)
            records[rrtype] = [r.to_text() for r in answer]
        except (dns.exception.DNSException, OSError):
            continue
    if not records:
        return {"error": f"no DNS records for {host}"}
    return {"records": records}


def _whois_lookup(host: str) -> dict[str, Any]:
    if whois is None:
        return {}
    try:
        w = whois.whois(host)
    except Exception as exc:  # noqa: BLE001 - whois lib raises wide
        return {"error": str(exc)}
    return {
        "registrar": _stringify(w.get("registrar")),
        "creation_date": _stringify(w.get("creation_date")),
        "expiration_date": _stringify(w.get("expiration_date")),
        "name_servers": _stringify(w.get("name_servers")),
        "org": _stringify(w.get("org")),
        "country": _stringify(w.get("country")),
    }


def _stringify(v: Any) -> Any:
    if isinstance(v, list):
        return [str(x) for x in v]
    if v is None:
        return None
    return str(v)


async def _crtsh_subdomains(client: httpx.AsyncClient, host: str) -> list[str]:
    try:
        resp = await client.get(
            "https://crt.sh/",
            params={"q": f"%.{host}", "output": "json"},
        )
    except httpx.HTTPError as exc:
        log.warning("crtsh_error", host=host, error=str(exc))
        return []
    if resp.status_code != 200:
        return []
    try:
        data = resp.json()
    except ValueError:
        return []
    subs: set[str] = set()
    for entry in data:
        name = entry.get("name_value", "")
        for part in name.split("\n"):
            part = part.strip().lower()
            if part and host in part and "*" not in part:
                subs.add(part)
    return sorted(subs)
