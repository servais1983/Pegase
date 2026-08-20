"""Smoke tests for the MCP server adapter.

Skipped when the optional ``mcp`` SDK is not installed, so the suite stays green
in minimal environments; CI installs the ``mcp`` extra to exercise these.
"""

from __future__ import annotations

import pytest

pytest.importorskip("mcp", reason="MCP SDK not installed (pip install 'pegase[mcp]')")


def test_build_server_registers_all_tools():
    from pegase.mcp.server import build_server

    server = build_server()
    assert server is not None


@pytest.mark.asyncio
async def test_server_exposes_governed_tools():
    from pegase.mcp.server import build_server

    server = build_server()
    tools = await server.list_tools()
    names = {getattr(t, "name", t) for t in tools}
    assert {
        "list_modules",
        "list_scenarios",
        "run_scan",
        "run_scenario",
        "advise",
        "verify_audit",
    } <= names


@pytest.mark.asyncio
async def test_run_scan_without_authorization_is_denied_through_mcp():
    from pegase.mcp.server import build_server

    server = build_server()
    result = await server.call_tool(
        "run_scan", {"targets": ["example.com"], "modules": ["recon"]}
    )
    # Across SDK shapes the denial text is always surfaced to the agent.
    assert "denied" in str(result).lower()
