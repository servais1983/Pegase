"""PEGASE Model Context Protocol (MCP) server.

Exposes PEGASE as a *governed* toolset for autonomous AI agents (Claude, or an
orchestrator such as PentAGI). Unlike a raw "run any tool" bridge, every action
requested through this server is:

  * least-privilege by default (passive only unless active/exploit is opted in),
  * re-validated against the mission Rules-of-Engagement / scope guard,
  * recorded in the hash-chained, tamper-evident audit log, tagged as
    agent-initiated so a later auditor can see *who* asked for each action.

The governance logic lives in :mod:`pegase.mcp.toolkit` (dependency-light and
fully unit-tested); :mod:`pegase.mcp.server` is a thin adapter that publishes
those functions over MCP.
"""

from pegase.mcp.toolkit import (
    advise,
    list_modules,
    list_scenarios,
    run_scan,
    run_scenario,
    verify_audit,
)

__all__ = [
    "advise",
    "list_modules",
    "list_scenarios",
    "run_scan",
    "run_scenario",
    "verify_audit",
]
