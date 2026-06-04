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


def build_json_report(mission: Mission, findings: list[Finding]) -> dict[str, Any]:
    by_sev = Counter(_sev(f) for f in findings)
    return {
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


def build_html_report(mission: Mission, findings: list[Finding]) -> str:
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
  <table>
    <thead><tr><th>Severity</th><th>Module</th><th>Target</th><th>Finding</th></tr></thead>
    <tbody>{"".join(rows) or '<tr><td colspan="4">No findings.</td></tr>'}</tbody>
  </table>
</body>
</html>"""
