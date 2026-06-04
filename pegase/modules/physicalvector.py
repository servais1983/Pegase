"""PhysicalVector - physical security assessment scaffolding.

Physical intrusion testing is inherently human-driven and cannot be automated
by software. PhysicalVector therefore produces a **structured assessment
plan**: it turns a site definition into a checklist of physical controls to
evaluate, pre-creates the corresponding finding placeholders, and records the
authorization in the audit log so the on-site team operates within a documented
scope.

Operators fill in observed/exploitable status during the engagement (via the
API/CLI), giving a consistent, auditable physical-security report alongside the
digital findings.
"""

from __future__ import annotations

from typing import Any

from pegase.core.scope import ActionType, ScopeGuard
from pegase.modules.base import Finding, Module, ModuleResult

# (control, default severity if weak, guidance)
_CONTROL_CHECKLIST: list[tuple[str, str, str]] = [
    ("perimeter-fencing", "medium", "Fence height, gaps, climb-over/under risk."),
    ("entry-doors", "high", "Door strength, hinge exposure, latch protection."),
    ("badge-access", "high", "RFID cloning, tailgating, anti-passback."),
    ("reception-controls", "medium", "Visitor logging, escort policy, pretext resistance."),
    ("cctv-coverage", "medium", "Blind spots, recording retention, monitoring."),
    ("server-room", "critical", "Dedicated access control, environmental, locks."),
    ("clean-desk", "low", "Credentials/notes left exposed, unlocked screens."),
    ("waste-disposal", "medium", "Dumpster diving exposure, shredding policy."),
    ("usb-drop", "high", "Susceptibility to malicious USB drops."),
    ("emergency-exits", "medium", "Doors that bypass access control, alarms."),
]


class PhysicalVector(Module):
    name = "physicalvector"
    description = "Generate a structured physical-security assessment checklist."
    action_type = ActionType.PASSIVE

    async def run(
        self,
        *,
        targets: list[str],
        guard: ScopeGuard,
        parameters: dict[str, Any] | None = None,
    ) -> ModuleResult:
        params = parameters or {}
        site = params.get("site") or (targets[0] if targets else "site")
        controls = params.get("controls") or [c[0] for c in _CONTROL_CHECKLIST]
        observed = params.get("observations", {})  # {control: {"status","note","severity"}}

        guard.check(site, self.action_type)
        result = ModuleResult(module=self.name)
        result.raw["site"] = site

        catalog = {c[0]: c for c in _CONTROL_CHECKLIST}
        for control in controls:
            spec = catalog.get(control, (control, "info", "Custom control."))
            obs = observed.get(control, {})
            status = obs.get("status", "to-assess")  # to-assess|ok|weak|exploited
            if status == "ok":
                continue
            severity = obs.get("severity") or (
                "critical" if status == "exploited" else spec[1]
            )
            note = obs.get("note", spec[2])
            title = {
                "to-assess": f"Physical control to assess: {control}",
                "weak": f"Weak physical control: {control}",
                "exploited": f"Physical control bypassed: {control}",
            }.get(status, f"Physical control: {control}")
            result.findings.append(
                Finding(
                    module=self.name,
                    target=f"{site}:{control}",
                    title=title,
                    description=note,
                    severity=severity if status != "to-assess" else "info",
                    evidence={"control": control, "status": status},
                    references=[
                        "https://owasp.org/www-pdf-archive/Physical_Security.pdf"
                    ],
                )
            )
        return result
