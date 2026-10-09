"""Tests for WirelessPhantom (airodump-ng CSV survey analysis)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from pegase.core.scope import ActionType, Scope, ScopeGuard, ScopeRule
from pegase.modules.wirelessphantom import WirelessPhantom, _parse_airodump_csv, _read_block


def _guard(pattern: str = "wireless-survey") -> ScopeGuard:
    scope = Scope(
        rules=[ScopeRule(pattern)],
        allowed_actions={ActionType.PASSIVE},
        authorization_token="t",
        starts_at=datetime.now(UTC),
    )
    return ScopeGuard(scope)


_AP_HEADER = "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key"
_CLIENT_HEADER = "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs"


def _csv(ap_rows: list[str], client_rows: list[str]) -> str:
    return "\n".join([_AP_HEADER, *ap_rows, "", _CLIENT_HEADER, *client_rows]) + "\n"


@pytest.mark.asyncio
async def test_wirelessphantom_requires_csv_path():
    with pytest.raises(ValueError, match="requires parameters"):
        await WirelessPhantom().run(targets=[], guard=_guard(), parameters={})


@pytest.mark.asyncio
async def test_wirelessphantom_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        await WirelessPhantom().run(
            targets=[], guard=_guard(), parameters={"csv_path": str(tmp_path / "nope.csv")}
        )


@pytest.mark.asyncio
async def test_wirelessphantom_flags_open_wep_wpa1_and_hidden(tmp_path):
    csv_text = _csv(
        ap_rows=[
            "AA:AA:AA:AA:AA:AA, 2024-01-01, 2024-01-01, 6, 54, OPN, , , -40, 10, 0, 0.0.0.0, 9, OpenNet, ",
            "BB:BB:BB:BB:BB:BB, 2024-01-01, 2024-01-01, 6, 54, WEP, WEP, , -40, 10, 0, 0.0.0.0, 6, OldWep, ",
            "CC:CC:CC:CC:CC:CC, 2024-01-01, 2024-01-01, 6, 54, WPA, TKIP, PSK, -40, 10, 0, 0.0.0.0, 7, LegacyWpa, ",
            "DD:DD:DD:DD:DD:DD, 2024-01-01, 2024-01-01, 6, 54, WPA2, CCMP, PSK, -40, 10, 0, 0.0.0.0, 0, , ",
        ],
        client_rows=[],
    )
    path = tmp_path / "survey.csv"
    path.write_text(csv_text, encoding="utf-8")

    result = await WirelessPhantom().run(
        targets=["survey-site"], guard=_guard("survey-site"),
        parameters={"csv_path": str(path)},
    )
    titles = [f.title for f in result.findings]
    assert any("Open Wi-Fi network: OpenNet" in t for t in titles)
    assert any("WEP network: OldWep" in t for t in titles)
    assert any("WPA1-only network: LegacyWpa" in t for t in titles)
    # The WPA2 AP has an empty ESSID -> flagged as hidden, not open/weak.
    assert any("Hidden SSID at DD:DD:DD:DD:DD:DD" in t for t in titles)
    assert result.raw["access_points"] == 4


@pytest.mark.asyncio
async def test_wirelessphantom_flags_probing_clients(tmp_path):
    csv_text = _csv(
        ap_rows=[],
        client_rows=[
            "EE:EE:EE:EE:EE:EE, 2024-01-01, 2024-01-01, -50, 5, (not associated), HomeWifi,OfficeWifi",
        ],
    )
    path = tmp_path / "clients.csv"
    path.write_text(csv_text, encoding="utf-8")

    result = await WirelessPhantom().run(
        targets=["survey-site"], guard=_guard("survey-site"),
        parameters={"csv_path": str(path)},
    )
    probing = [f for f in result.findings if f.title == "Client probing for known networks"]
    assert len(probing) == 1
    assert probing[0].target == "EE:EE:EE:EE:EE:EE"
    assert "HomeWifi" in probing[0].description


def test_read_block_empty_input_returns_nothing():
    assert _read_block("") == []


def test_read_block_header_only_returns_nothing():
    assert _read_block(_AP_HEADER) == []


def test_read_block_all_blank_rows_returns_nothing():
    # Non-empty block, but every row is empty once stripped -> the
    # post-filter `if not rows:` branch, distinct from the empty-block
    # early return above.
    assert _read_block(",,,\n,,,\n") == []


def test_read_block_skips_short_rows():
    block = _AP_HEADER + "\nsingle-field"
    assert _read_block(block) == []


def test_parse_airodump_csv_splits_ap_and_client_sections():
    text = _csv(
        ap_rows=["AA:AA:AA:AA:AA:AA, t, t, 6, 54, OPN, , , -40, 1, 0, 0.0.0.0, 4, Test, "],
        client_rows=["BB:BB:BB:BB:BB:BB, t, t, -50, 1, (not associated), Test"],
    )
    aps, clients = _parse_airodump_csv(text)
    assert len(aps) == 1
    assert len(clients) == 1
    assert aps[0]["ESSID"] == "Test"
