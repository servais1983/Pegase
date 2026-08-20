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


def test_sarif_report_is_valid_2_1_0():
    from pegase.reporting.generator import build_sarif_report

    sarif = build_sarif_report(
        [_finding("critical"), _finding("low")], mission_name="Pentest X"
    )
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    run = sarif["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "PEGASE"
    # Two findings from the same module collapse to a single rule.
    assert len(driver["rules"]) == 1
    assert driver["rules"][0]["id"] == "pegase/webbreacher"
    # Rule advertises the highest severity seen (critical -> 9.5).
    assert driver["rules"][0]["properties"]["security-severity"] == "9.5"
    assert len(run["results"]) == 2
    assert run["properties"]["mission"] == "Pentest X"


def test_sarif_levels_map_severity():
    from pegase.reporting.generator import build_sarif_report

    results = build_sarif_report(
        [_finding("info"), _finding("medium"), _finding("critical")]
    )["runs"][0]["results"]
    levels = {r["properties"]["severity"]: r["level"] for r in results}
    assert levels["info"] == "note"
    assert levels["medium"] == "warning"
    assert levels["critical"] == "error"


def test_sarif_accepts_plain_dicts():
    from pegase.reporting.generator import build_sarif_report

    sarif = build_sarif_report(
        [
            {
                "module": "recon",
                "target": "example.com",
                "title": "Open port",
                "description": "22/tcp",
                "severity": "medium",
                "references": [],
            }
        ]
    )
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "pegase/recon"
    assert result["level"] == "warning"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "example.com"


def test_csv_report_header_and_sort():
    from pegase.reporting.generator import build_csv_report

    csv_text = build_csv_report([_finding("low"), _finding("critical")])
    lines = csv_text.strip().splitlines()
    assert lines[0] == "severity,module,target,title,description,references"
    # Critical sorts above low.
    assert lines[1].startswith("critical,")
    assert lines[2].startswith("low,")


def test_csv_quotes_embedded_commas():
    from pegase.reporting.generator import build_csv_report

    f = _finding("high")
    f.title = "SQLi in id, user, and name"
    csv_text = build_csv_report([f])
    assert '"SQLi in id, user, and name"' in csv_text
