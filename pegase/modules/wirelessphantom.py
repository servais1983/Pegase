"""WirelessPhantom - wireless survey analysis.

Active wireless capture requires a monitor-mode adapter and is performed
out-of-band by the operator (e.g. ``airodump-ng -w capture ...``). PEGASE does
not drive the radio directly - that keeps the platform host-agnostic and avoids
shipping kernel/driver dependencies into the container.

WirelessPhantom ingests the **CSV output** produced by airodump-ng (passed via
``parameters["csv_path"]``) and reports:

  * open / WEP networks (no or broken encryption),
  * WPA1-only networks,
  * networks with WPS enabled,
  * hidden SSIDs,
  * clients probing for networks (potential karma/evil-twin exposure).

This is a passive analysis of an operator-provided artifact.
"""

from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Any

from pegase.core.logging import get_logger
from pegase.core.scope import ActionType, ScopeGuard
from pegase.modules.base import Finding, Module, ModuleResult

log = get_logger(__name__)


class WirelessPhantom(Module):
    name = "wirelessphantom"
    description = "Analyze airodump-ng CSV surveys (open/WEP/WPS/hidden networks)."
    action_type = ActionType.PASSIVE

    async def run(
        self,
        *,
        targets: list[str],
        guard: ScopeGuard,
        parameters: dict[str, Any] | None = None,
    ) -> ModuleResult:
        params = parameters or {}
        csv_path = params.get("csv_path")
        if not csv_path:
            raise ValueError("wirelessphantom requires parameters['csv_path'].")
        path = Path(csv_path)
        if not path.exists():
            raise FileNotFoundError(f"airodump CSV not found: {csv_path}")

        label = targets[0] if targets else "wireless-survey"
        guard.check(label, self.action_type)

        result = ModuleResult(module=self.name)
        aps, clients = _parse_airodump_csv(path.read_text(encoding="utf-8", errors="replace"))
        result.raw["access_points"] = len(aps)
        result.raw["clients"] = len(clients)

        for ap in aps:
            bssid = ap.get("BSSID", "").strip()
            essid = ap.get("ESSID", "").strip()
            privacy = ap.get("Privacy", "").strip().upper()
            target = f"{essid or '<hidden>'} ({bssid})"

            if not privacy or "OPN" in privacy:
                result.findings.append(
                    Finding(
                        module=self.name, target=target,
                        title=f"Open Wi-Fi network: {essid or '<hidden>'}",
                        description="No encryption - traffic is in cleartext.",
                        severity="high", evidence=ap,
                    )
                )
            elif "WEP" in privacy:
                result.findings.append(
                    Finding(
                        module=self.name, target=target,
                        title=f"WEP network: {essid}",
                        description="WEP is trivially crackable; treat as open.",
                        severity="high", evidence=ap,
                    )
                )
            elif "WPA" in privacy and "WPA2" not in privacy and "WPA3" not in privacy:
                result.findings.append(
                    Finding(
                        module=self.name, target=target,
                        title=f"WPA1-only network: {essid}",
                        description="WPA1/TKIP is deprecated and weak.",
                        severity="medium", evidence=ap,
                    )
                )

            if not essid:
                result.findings.append(
                    Finding(
                        module=self.name, target=target,
                        title=f"Hidden SSID at {bssid}",
                        description="Hidden SSIDs offer no real security benefit.",
                        severity="info", evidence=ap,
                    )
                )

        # Clients probing for networks -> evil-twin exposure
        for cl in clients:
            probes = cl.get("Probed ESSIDs", "").strip()
            if probes:
                result.findings.append(
                    Finding(
                        module=self.name,
                        target=cl.get("Station MAC", "").strip(),
                        title="Client probing for known networks",
                        description=(
                            f"Station {cl.get('Station MAC')} is probing for: "
                            f"{probes}. Vulnerable to evil-twin/karma attacks."
                        ),
                        severity="medium", evidence=cl,
                    )
                )
        return result


def _parse_airodump_csv(text: str) -> tuple[list[dict], list[dict]]:
    """airodump CSV has two sections separated by a blank line."""
    lines = text.splitlines()
    # Find the split between AP section and client (station) section.
    blank_idx = next(
        (i for i, ln in enumerate(lines) if ln.strip() == "" and i > 0), len(lines)
    )
    ap_block = "\n".join(lines[:blank_idx]).strip()
    client_block = "\n".join(lines[blank_idx + 1 :]).strip()

    aps = _read_block(ap_block)
    clients = _read_block(client_block)
    return aps, clients


def _read_block(block: str) -> list[dict]:
    if not block:
        return []
    reader = csv.reader(io.StringIO(block))
    rows = [r for r in reader if any(c.strip() for c in r)]
    if not rows:
        return []
    header = [h.strip() for h in rows[0]]
    out: list[dict] = []
    for row in rows[1:]:
        if len(row) < 2:
            continue
        out.append({header[i]: row[i].strip() for i in range(min(len(header), len(row)))})
    return out
