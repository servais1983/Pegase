"""Reporting tests."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

from pegase.reporting.generator import build_html_report, build_json_report


def _mission():
    return SimpleNamespace(
        id="m1",
        name="Pentest X",
        client="ACME",
        status=SimpleNamespace(value="completed"),
        targets=["app.example.com"],
        scope_rules=[{"pattern": "app.example.com", "include": True}],
        starts_at=datetime.now(UTC),
        ends_at=None,
    )


def _finding(sev="high"):
    return SimpleNamespace(
        id="f1",
        module="webbreacher",
        target="app.example.com",
        title="Sensitive path exposed: /.env",
        description="Disclosed environment variables",
        severity=SimpleNamespace(value=sev),
        evidence={"status": 200},
        references=["https://owasp.org"],
        discovered_at=datetime.now(UTC),
    )


def test_json_report_groups_by_severity():
    report = build_json_report(_mission(), [_finding("high"), _finding("low")])
    assert report["summary"]["total"] == 2
    assert report["summary"]["by_severity"]["high"] == 1
    assert report["mission"]["name"] == "Pentest X"


def test_html_report_renders():
    html = build_html_report(_mission(), [_finding("critical")])
    assert "PEGASE Report" in html
    assert "critical" in html
    assert "Sensitive path exposed" in html
