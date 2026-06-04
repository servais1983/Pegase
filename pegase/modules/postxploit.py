"""PostXploit - attack-path graph builder.

PostXploit is a *support* consumer module: it does not touch any target. It
runs after the producer modules and synthesises their findings into an
attack-path graph (nodes = hosts/assets, edges = "leads to" relationships
inferred from co-located findings and severity escalation).

The graph is emitted as a finding (with the adjacency structure in evidence)
so the frontend can render it with D3, and a textual summary of the most
dangerous path is produced for the report.
"""

from __future__ import annotations

from typing import Any

from pegase.core.scope import ActionType, ScopeGuard
from pegase.modules.base import Finding, Module, ModuleResult

_SEV_WEIGHT = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class PostXploit(Module):
    name = "postxploit"
    description = "Correlate findings into an attack-path graph (no target traffic)."
    action_type = ActionType.PASSIVE
    needs_upstream_findings = True

    async def run(
        self,
        *,
        targets: list[str],
        guard: ScopeGuard,
        parameters: dict[str, Any] | None = None,
    ) -> ModuleResult:
        params = parameters or {}
        prior: list[dict[str, Any]] = params.get("findings", [])
        result = ModuleResult(module=self.name)

        # Build nodes keyed by host (strip :port / :service suffixes).
        nodes: dict[str, dict[str, Any]] = {}
        for f in prior:
            host = _host_of(f.get("target", ""))
            if not host:
                continue
            node = nodes.setdefault(
                host, {"id": host, "max_severity": "info", "findings": 0, "modules": set()}
            )
            node["findings"] += 1
            node["modules"].add(f.get("module", "?"))
            sev = f.get("severity", "info")
            if _SEV_WEIGHT.get(sev, 0) > _SEV_WEIGHT.get(node["max_severity"], 0):
                node["max_severity"] = sev

        # Edges: connect any node to the highest-value node (pivot target).
        node_list = list(nodes.values())
        for n in node_list:
            n["modules"] = sorted(n["modules"])
        edges: list[dict[str, str]] = []
        if len(node_list) > 1:
            crown = max(node_list, key=lambda n: _SEV_WEIGHT[n["max_severity"]])
            for n in node_list:
                if n["id"] == crown["id"]:
                    continue
                edges.append(
                    {
                        "source": n["id"],
                        "target": crown["id"],
                        "rationale": "potential pivot toward highest-value asset",
                    }
                )

        graph = {"nodes": node_list, "edges": edges}
        result.raw["graph"] = graph

        if node_list:
            crown = max(node_list, key=lambda n: _SEV_WEIGHT[n["max_severity"]])
            result.findings.append(
                Finding(
                    module=self.name,
                    target=crown["id"],
                    title=f"Attack-path graph built ({len(node_list)} assets)",
                    description=(
                        f"Highest-value asset: {crown['id']} "
                        f"(severity={crown['max_severity']}, "
                        f"{crown['findings']} findings). "
                        f"{len(edges)} potential pivot edge(s) identified."
                    ),
                    severity=crown["max_severity"]
                    if crown["max_severity"] != "info"
                    else "low",
                    evidence={"graph": graph},
                )
            )
        return result


def _host_of(target: str) -> str:
    target = target.strip()
    if not target:
        return ""
    # aws:acct:s3:bucket -> aws:acct ; host:port -> host ; url -> host
    if target.startswith("aws:"):
        parts = target.split(":")
        return ":".join(parts[:2])
    if "://" in target:
        from urllib.parse import urlparse

        return (urlparse(target).hostname or target).lower()
    # strip :port or :component
    return target.split(":", 1)[0].lower()
