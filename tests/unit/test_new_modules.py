"""Tests for the second-wave modules and the scenario engine."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from pegase.core.scope import ActionType, Scope, ScopeGuard, ScopeRule, ScopeViolation
from pegase.modules.physicalvector import PhysicalVector
from pegase.modules.postxploit import PostXploit, _host_of
from pegase.modules.toolforge import ToolForge
from pegase.modules.wirelessphantom import WirelessPhantom


def _guard(*patterns, actions=None):
    scope = Scope(
        rules=[ScopeRule(p) for p in (patterns or ["example.com"])],
        allowed_actions=actions or {ActionType.PASSIVE, ActionType.ACTIVE},
        authorization_token="t",
        starts_at=datetime.now(UTC),
    )
    return ScopeGuard(scope)


# --- PostXploit ------------------------------------------------------------


def test_host_of_normalization():
    assert _host_of("10.0.0.5:443") == "10.0.0.5"
    assert _host_of("https://app.example.com/x") == "app.example.com"
    assert _host_of("aws:123:s3:bucket") == "aws:123"


@pytest.mark.asyncio
async def test_postxploit_builds_graph():
    prior = [
        {"target": "10.0.0.5:22", "module": "netassault", "severity": "medium"},
        {"target": "10.0.0.5:445", "module": "netassault", "severity": "high"},
        {"target": "app.example.com", "module": "webbreacher", "severity": "low"},
    ]
    result = await PostXploit().run(
        targets=[], guard=_guard("10.0.0.0/24", "example.com"),
        parameters={"findings": prior},
    )
    graph = result.raw["graph"]
    ids = {n["id"] for n in graph["nodes"]}
    assert ids == {"10.0.0.5", "app.example.com"}
    # crown node is the high-severity host; one edge points to it
    assert len(graph["edges"]) == 1
    assert graph["edges"][0]["target"] == "10.0.0.5"


# --- WirelessPhantom -------------------------------------------------------


def test_wirelessphantom_parses_open_network(tmp_path):
    csv = (
        "BSSID, First time seen, channel, Privacy, Cipher, ESSID\n"
        "AA:BB:CC:DD:EE:FF, 2026-01-01, 6, OPN, , FreeWifi\n"
        "11:22:33:44:55:66, 2026-01-01, 11, WPA2, CCMP, SecureNet\n"
        "\n"
        "Station MAC, Probed ESSIDs\n"
        "DE:AD:BE:EF:00:01, HomeNetwork\n"
    )
    path = tmp_path / "survey-01.csv"
    path.write_text(csv, encoding="utf-8")
    import asyncio

    result = asyncio.run(
        WirelessPhantom().run(
            targets=["survey"], guard=_guard("survey"),
            parameters={"csv_path": str(path)},
        )
    )
    titles = [f.title for f in result.findings]
    assert any("Open Wi-Fi" in t for t in titles)
    assert any("probing" in t.lower() for t in titles)


# --- PhysicalVector --------------------------------------------------------


@pytest.mark.asyncio
async def test_physicalvector_generates_checklist():
    result = await PhysicalVector().run(
        targets=["HQ"], guard=_guard("HQ"),
        parameters={"observations": {"server-room": {"status": "exploited", "note": "door propped open"}}},
    )
    server = [f for f in result.findings if "server-room" in f.target]
    assert server and server[0].severity == "critical"


# --- ToolForge -------------------------------------------------------------


@pytest.mark.asyncio
async def test_toolforge_rejects_unknown_tool():
    with pytest.raises(ValueError, match="not in allowlist"):
        await ToolForge().run(
            targets=["example.com"], guard=_guard("example.com"),
            parameters={"tool": "rm-rf-everything"},
        )


@pytest.mark.asyncio
async def test_toolforge_requires_tool():
    with pytest.raises(ValueError, match="requires"):
        await ToolForge().run(
            targets=["example.com"], guard=_guard("example.com"), parameters={}
        )


# --- ScopeGuard still blocks new modules -----------------------------------


@pytest.mark.asyncio
async def test_physicalvector_respects_scope():
    with pytest.raises(ScopeViolation):
        await PhysicalVector().run(
            targets=["out-of-scope-site"], guard=_guard("only-this-site"),
        )
