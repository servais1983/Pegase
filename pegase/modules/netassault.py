"""NetAssault - network-layer scanning.

Wraps the system ``nmap`` binary via python-nmap. By default we run a polite
TCP-SYN scan against the top-1000 ports with service/version detection. The
profile can be tuned through module parameters (``ports``, ``arguments``,
``timing``). Each invocation is gated by the ``ScopeGuard``.
"""

from __future__ import annotations

import asyncio
import shutil
from typing import Any

import nmap  # python-nmap

from pegase.core.logging import get_logger
from pegase.core.scope import ActionType, ScopeGuard
from pegase.modules.base import Finding, Module, ModuleResult

log = get_logger(__name__)

_DEFAULT_PORTS = "1-1024"
_SEVERITY_BY_PORT: dict[int, str] = {
    21: "medium",   # FTP
    23: "high",     # Telnet
    25: "low",      # SMTP
    111: "medium",  # rpcbind
    135: "medium",  # MS RPC
    139: "high",    # NetBIOS
    445: "high",    # SMB
    1433: "high",   # MSSQL
    1521: "high",   # Oracle
    2049: "high",   # NFS
    3306: "medium", # MySQL
    3389: "high",   # RDP
    5432: "medium", # PostgreSQL
    5900: "high",   # VNC
    6379: "high",   # Redis (often no auth)
    27017: "high",  # MongoDB (often no auth)
}


class NetAssault(Module):
    name = "netassault"
    description = "TCP port discovery and service fingerprinting via nmap."
    action_type = ActionType.ACTIVE

    async def run(
        self,
        *,
        targets: list[str],
        guard: ScopeGuard,
        parameters: dict[str, Any] | None = None,
    ) -> ModuleResult:
        params = parameters or {}
        ports = params.get("ports", _DEFAULT_PORTS)
        timing = int(params.get("timing", 3))
        extra = params.get("arguments", "")
        # -sS requires root; fall back to -sT when unprivileged.
        scan_type = params.get("scan_type", "-sT")
        arguments = f"{scan_type} -sV -Pn -T{timing} {extra}".strip()

        if not shutil.which("nmap"):
            raise RuntimeError(
                "nmap binary not found on PATH; install nmap to use NetAssault."
            )

        result = ModuleResult(module=self.name)
        for target in targets:
            guard.check(target, self.action_type)
            log.info("nmap_scan", target=target, ports=ports, arguments=arguments)
            scan = await asyncio.to_thread(_run_nmap, target, ports, arguments)
            result.raw[target] = scan
            for host, host_data in scan.get("scan", {}).items():
                tcp = host_data.get("tcp", {}) or {}
                open_ports = [p for p, info in tcp.items() if info.get("state") == "open"]
                if not open_ports:
                    continue
                for port in open_ports:
                    info = tcp[port]
                    service = info.get("name") or "unknown"
                    product = info.get("product") or ""
                    version = info.get("version") or ""
                    severity = _SEVERITY_BY_PORT.get(port, "info")
                    result.findings.append(
                        Finding(
                            module=self.name,
                            target=f"{host}:{port}",
                            title=f"Open port {port}/tcp ({service})",
                            description=(
                                f"Service '{service}' "
                                + (f"({product} {version})" if product else "")
                                + " is reachable."
                            ).strip(),
                            severity=severity,
                            evidence={
                                "port": port,
                                "service": service,
                                "product": product,
                                "version": version,
                                "extra": info,
                            },
                        )
                    )
        return result


def _run_nmap(target: str, ports: str, arguments: str) -> dict[str, Any]:
    scanner = nmap.PortScanner()
    scanner.scan(hosts=target, ports=ports, arguments=arguments)
    return scanner.analyse_nmap_xml_scan(nmap_xml_output=scanner.get_nmap_last_output())
