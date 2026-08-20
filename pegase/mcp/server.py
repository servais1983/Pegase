"""PEGASE MCP server — publishes the governed toolkit over MCP.

Run it as a stdio MCP server (the transport Claude Desktop / Claude Code and
most agent runtimes speak):

    pegase-mcp                 # console script
    python -m pegase.mcp       # module form

Then point an MCP client at that command. Every tool call is Rules-of-Engagement
gated and written to the tamper-evident audit log — see :mod:`pegase.mcp.toolkit`.

The ``mcp`` SDK is an optional dependency (``pip install 'pegase[mcp]'``); it is
imported lazily so the rest of PEGASE works without it.
"""

from __future__ import annotations

from typing import Any

from pegase.mcp import toolkit

SERVER_NAME = "pegase"
SERVER_INSTRUCTIONS = (
    "PEGASE is a governed pentest-orchestration toolset. Every action you "
    "request is Rules-of-Engagement gated and recorded in a tamper-evident "
    "audit log. Missions REQUIRE an 'authorization' token (the RoE reference); "
    "without it, scans are denied. Actions are passive by default — set "
    "allow_active / allow_exploit only when the engagement explicitly permits "
    "them. Use verify_audit to prove the chain of actions has not been tampered "
    "with."
)


def _new_server() -> tuple[Any, str]:
    """Instantiate an MCP server across SDK variants (mcp 2.x / FastMCP 1.x)."""
    try:  # mcp >= 2.0
        from mcp.server import MCPServer  # type: ignore

        return MCPServer(name=SERVER_NAME, instructions=SERVER_INSTRUCTIONS), "mcpserver"
    except ImportError:
        pass
    try:  # mcp 1.x
        from mcp.server.fastmcp import FastMCP  # type: ignore

        return FastMCP(name=SERVER_NAME, instructions=SERVER_INSTRUCTIONS), "fastmcp"
    except ImportError as exc:  # pragma: no cover - only when SDK missing
        raise RuntimeError(
            "The MCP SDK is not installed. Install it with: pip install 'pegase[mcp]'"
        ) from exc


def build_server() -> Any:
    """Build and return the configured MCP server (tools registered)."""
    server, _ = _new_server()

    @server.tool()
    def list_modules() -> dict[str, Any]:
        """List the PEGASE modules available to run, with their action posture."""
        return toolkit.list_modules()

    @server.tool()
    def list_scenarios() -> dict[str, Any]:
        """List the built-in ThreatSim scenarios (named multi-stage kill-chains)."""
        return toolkit.list_scenarios()

    @server.tool()
    async def run_scan(
        targets: list[str],
        modules: list[str] | None = None,
        authorization: str | None = None,
        allow_active: bool = False,
        allow_exploit: bool = False,
        scope_patterns: list[str] | None = None,
        report_format: str = "",
    ) -> dict[str, Any]:
        """Run a governed scan.

        'authorization' is the Rules-of-Engagement reference and is REQUIRED —
        without it the scan is denied and the denial is audited. Scans are
        passive unless allow_active / allow_exploit is set. 'scope_patterns'
        narrows what is in scope (defaults to 'targets'); every target is
        re-validated against the scope guard. Set report_format to 'sarif' or
        'csv' to also receive an exportable report.
        """
        return await toolkit.run_scan_async(
            targets=targets,
            modules=modules,
            authorization=authorization,
            allow_active=allow_active,
            allow_exploit=allow_exploit,
            scope_patterns=scope_patterns,
            report_format=report_format,
        )

    @server.tool()
    async def run_scenario(
        targets: list[str],
        scenario: str,
        authorization: str | None = None,
        allow_active: bool = False,
        allow_exploit: bool = False,
        scope_patterns: list[str] | None = None,
        report_format: str = "",
    ) -> dict[str, Any]:
        """Run a named ThreatSim scenario under the same governance guarantees.

        'scenario' is a built-in name (see list_scenarios) or a YAML path.
        'authorization' (RoE reference) is REQUIRED.
        """
        return await toolkit.run_scenario_async(
            targets=targets,
            scenario=scenario,
            authorization=authorization,
            allow_active=allow_active,
            allow_exploit=allow_exploit,
            scope_patterns=scope_patterns,
            report_format=report_format,
        )

    @server.tool()
    async def advise(findings: list[dict[str, Any]]) -> dict[str, Any]:
        """Run the grounded, offline-by-default AI advisor over a list of findings.

        Returns a risk score, executive summary, attack narrative and
        prioritized, remediation-tagged risks.
        """
        return await toolkit.advise_async(findings=findings)

    @server.tool()
    def verify_audit() -> dict[str, Any]:
        """Verify the tamper-evident audit chain and report whether it is intact."""
        return toolkit.verify_audit()

    return server


def main() -> None:
    """Console entry point: run the MCP server over stdio."""
    server = build_server()
    server.run("stdio")


if __name__ == "__main__":
    main()
