"""HTML / JSON report generation."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from html import escape
from typing import Any

from pegase.db.models import Finding, Mission

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_COLOR = {
    "info": "#5d6d7e",
    "low": "#2ecc71",
    "medium": "#f1c40f",
    "high": "#e67e22",
    "critical": "#c0392b",
}


def _sev(f) -> str:
    s = f.severity
    return s.value if hasattr(s, "value") else str(s)


def build_json_report(
    mission: Mission,
    findings: list[Finding],
    ai_analysis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    by_sev = Counter(_sev(f) for f in findings)
    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "mission": {
            "id": mission.id,
            "name": mission.name,
            "client": mission.client,
            "status": mission.status.value if hasattr(mission.status, "value") else str(mission.status),
            "targets": mission.targets,
            "scope_rules": mission.scope_rules,
            "starts_at": mission.starts_at.isoformat() if mission.starts_at else None,
            "ends_at": mission.ends_at.isoformat() if mission.ends_at else None,
        },
        "summary": {
            "total": len(findings),
            "by_severity": dict(by_sev),
        },
        "findings": [
            {
                "id": f.id,
                "module": f.module,
                "target": f.target,
                "title": f.title,
                "description": f.description,
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "evidence": f.evidence,
                "references": f.references,
                "discovered_at": f.discovered_at.isoformat(),
            }
            for f in sorted(
                findings,
                key=lambda f: -SEVERITY_RANK.get(
                    f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    0,
                ),
            )
        ],
    }
    if ai_analysis is not None:
        report["ai_analysis"] = ai_analysis
    return report


def _ai_section_html(ai_analysis: dict[str, Any] | None) -> str:
    if not ai_analysis:
        return ""
    risks = ai_analysis.get("prioritized_risks", [])
    risk_rows = "".join(
        f"""<tr>
              <td><span style="color:{SEVERITY_COLOR.get(r.get('severity',''), '#888')};
                  font-weight:600">{escape(str(r.get('severity','')))}</span></td>
              <td><strong>{escape(str(r.get('title','')))}</strong></td>
              <td>{escape(', '.join(r.get('targets', [])[:4]))}</td>
              <td>{escape(str(r.get('remediation','')))}</td>
            </tr>"""
        for r in risks
    )
    provider = escape(str(ai_analysis.get("provider", "offline")))
    llm_used = ai_analysis.get("llm_used", False)
    return f"""
  <div class="ai">
    <h2>AI advisor <span class="tag">PEGASE AI</span></h2>
    <p class="meta">provider <code>{provider}</code>
       &middot; llm_used <code>{llm_used}</code>
       &middot; risk score <strong>{escape(str(ai_analysis.get('risk_score', 0)))}/100</strong></p>
    <p><strong>Executive summary.</strong> {escape(str(ai_analysis.get('executive_summary','')))}</p>
    <p><strong>Attack narrative.</strong> {escape(str(ai_analysis.get('attack_narrative','')))}</p>
    {"<table><thead><tr><th>Severity</th><th>Risk</th><th>Targets</th><th>Remediation</th></tr></thead><tbody>" + risk_rows + "</tbody></table>" if risk_rows else ""}
  </div>
"""


def build_html_report(
    mission: Mission,
    findings: list[Finding],
    ai_analysis: dict[str, Any] | None = None,
) -> str:
    sev_count = Counter(
        f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        for f in findings
    )

    def sev_chip(s: str, n: int) -> str:
        color = SEVERITY_COLOR.get(s, "#888")
        return (
            f'<span style="background:{color};color:#fff;padding:4px 10px;'
            f'border-radius:12px;margin-right:6px">{escape(s)}: {n}</span>'
        )

    rows: list[str] = []
    sorted_f = sorted(
        findings,
        key=lambda f: -SEVERITY_RANK.get(
            f.severity.value if hasattr(f.severity, "value") else str(f.severity), 0
        ),
    )
    for f in sorted_f:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        color = SEVERITY_COLOR.get(sev, "#888")
        refs = "".join(
            f'<li><a href="{escape(r)}" target="_blank" rel="noopener">{escape(r)}</a></li>'
            for r in (f.references or [])
        )
        rows.append(
            f"""
            <tr>
              <td><span style="color:{color};font-weight:600">{escape(sev)}</span></td>
              <td>{escape(f.module)}</td>
              <td>{escape(f.target)}</td>
              <td>
                <strong>{escape(f.title)}</strong>
                <p>{escape(f.description)}</p>
                {f'<ul>{refs}</ul>' if refs else ''}
              </td>
            </tr>
            """
        )

    status = mission.status.value if hasattr(mission.status, "value") else str(mission.status)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>PEGASE Report - {escape(mission.name)}</title>
<style>
  body {{ font-family: -apple-system,Segoe UI,Roboto,sans-serif; margin:32px; color:#222; }}
  h1 {{ margin:0; }}
  .meta {{ color:#666; margin-bottom:16px; }}
  table {{ width:100%; border-collapse:collapse; margin-top:16px; }}
  th, td {{ text-align:left; border-bottom:1px solid #eee; padding:10px; vertical-align:top; }}
  th {{ background:#fafafa; font-size:13px; text-transform:uppercase; letter-spacing:1px; }}
  .summary {{ margin:16px 0; }}
  .ai {{ margin:24px 0; padding:16px 20px; background:#f6f8ff; border:1px solid #dde3ff; border-radius:10px; }}
  .ai h2 {{ margin:0 0 8px; }}
  .tag {{ background:#4b5bdc; color:#fff; font-size:11px; padding:2px 8px; border-radius:10px; vertical-align:middle; }}
</style>
</head>
<body>
  <h1>PEGASE Report</h1>
  <div class="meta">
    Mission <strong>{escape(mission.name)}</strong>
    {f"for <em>{escape(mission.client)}</em>" if mission.client else ""}
    &middot; status <code>{escape(status)}</code>
    &middot; generated {datetime.now(UTC).isoformat()}
  </div>
  <div class="summary">
    {"".join(sev_chip(s, n) for s, n in sev_count.most_common())}
    <strong style="margin-left:12px">Total: {len(findings)}</strong>
  </div>
  {_ai_section_html(ai_analysis)}
  <table>
    <thead><tr><th>Severity</th><th>Module</th><th>Target</th><th>Finding</th></tr></thead>
    <tbody>{"".join(rows) or '<tr><td colspan="4">No findings.</td></tr>'}</tbody>
  </table>
</body>
</html>"""


# --------------------------------------------------------------------------- #
# Interchange exports: SARIF 2.1.0 and CSV.
#
# These builders operate on *plain finding dicts* (keys: module, target, title,
# description, severity, evidence, references) so they can be driven both from
# the API (DB-backed ``Finding`` rows) and from the CLI (in-memory findings).
# --------------------------------------------------------------------------- #

# GitHub code scanning reads ``security-severity`` (0.0-10.0) to bucket alerts.
SEVERITY_SECURITY_SCORE = {
    "info": "0.0",
    "low": "2.0",
    "medium": "5.5",
    "high": "8.0",
    "critical": "9.5",
}
# SARIF result levels are a fixed enum: none | note | warning | error.
SEVERITY_SARIF_LEVEL = {
    "info": "note",
    "low": "note",
    "medium": "warning",
    "high": "error",
    "critical": "error",
}

_TOOL_INFO_URI = "https://github.com/servais1983/Pegase"


def _finding_dicts(findings: list[Any]) -> list[dict[str, Any]]:
    """Normalise DB/dataclass findings (or dicts) to plain dicts."""
    out: list[dict[str, Any]] = []
    for f in findings:
        if isinstance(f, dict):
            sev = f.get("severity", "info")
            out.append(
                {
                    "module": f.get("module", ""),
                    "target": f.get("target", ""),
                    "title": f.get("title", ""),
                    "description": f.get("description", ""),
                    "severity": sev.value if hasattr(sev, "value") else str(sev),
                    "evidence": f.get("evidence") or {},
                    "references": f.get("references") or [],
                }
            )
        else:
            out.append(
                {
                    "module": f.module,
                    "target": f.target,
                    "title": f.title,
                    "description": f.description,
                    "severity": _sev(f),
                    "evidence": f.evidence or {},
                    "references": list(f.references or []),
                }
            )
    return out


def build_sarif_report(
    findings: list[Any],
    *,
    tool_version: str = "0.1.0",
    mission_name: str | None = None,
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log from PEGASE findings.

    One SARIF *rule* is emitted per PEGASE module (the ``ruleId`` is
    ``pegase/<module>``), and one *result* per finding. Severity is carried
    both as a SARIF ``level`` and, for GitHub code scanning, as a
    ``security-severity`` rule property.
    """
    norm = _finding_dicts(findings)

    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for f in norm:
        module = f["module"] or "pegase"
        sev = f["severity"] if f["severity"] in SEVERITY_SARIF_LEVEL else "info"
        rule_id = f"pegase/{module}"
        # Register the rule once, keeping the highest severity seen for it.
        rule = rules.get(rule_id)
        if rule is None:
            rule = {
                "id": rule_id,
                "name": module,
                "shortDescription": {"text": f"PEGASE {module} finding"},
                "helpUri": _TOOL_INFO_URI,
                "properties": {
                    "tags": ["security", "pegase", module],
                    "security-severity": SEVERITY_SECURITY_SCORE.get(sev, "0.0"),
                },
            }
            rules[rule_id] = rule
        else:
            # Promote the rule's advertised security-severity if this finding
            # is more severe than any previously recorded for the module.
            cur = float(rule["properties"]["security-severity"])
            new = float(SEVERITY_SECURITY_SCORE.get(sev, "0.0"))
            if new > cur:
                rule["properties"]["security-severity"] = SEVERITY_SECURITY_SCORE[sev]

        message = f["title"]
        if f["description"]:
            message = f"{f['title']}\n\n{f['description']}"

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": SEVERITY_SARIF_LEVEL.get(sev, "note"),
            "message": {"text": message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f["target"] or "unknown"}
                    }
                }
            ],
            "properties": {
                "severity": sev,
                "module": module,
                "references": f["references"],
            },
        }
        results.append(result)

    driver: dict[str, Any] = {
        "name": "PEGASE",
        "version": tool_version,
        "informationUri": _TOOL_INFO_URI,
        "rules": list(rules.values()),
    }
    run: dict[str, Any] = {"tool": {"driver": driver}, "results": results}
    if mission_name:
        run["properties"] = {"mission": mission_name}

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [run],
    }


def build_csv_report(findings: list[Any]) -> str:
    """Serialise findings to CSV (severity-sorted, RFC-4180 quoting)."""
    import csv
    import io

    norm = _finding_dicts(findings)
    norm.sort(key=lambda f: -SEVERITY_RANK.get(f["severity"], 0))

    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(["severity", "module", "target", "title", "description", "references"])
    for f in norm:
        writer.writerow(
            [
                f["severity"],
                f["module"],
                f["target"],
                f["title"],
                f["description"],
                " ".join(f["references"]),
            ]
        )
    return buf.getvalue()
