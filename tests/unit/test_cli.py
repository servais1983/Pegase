"""Tests for the ``pegase`` command-line interface.

These exercise the offline, deterministic commands (no database, no network,
no LLM keys) through Click's ``CliRunner`` so the CLI surface stays covered.
"""

from __future__ import annotations

import json

import httpx
from click.testing import CliRunner

from pegase.cli import cli

runner = CliRunner()


def test_modules_lists_known_modules() -> None:
    result = runner.invoke(cli, ["modules"])
    assert result.exit_code == 0, result.output
    # A couple of the core modules must always be present.
    assert "recon" in result.output
    assert "aibreacher" in result.output


def test_scenarios_lists_builtin_scenarios() -> None:
    result = runner.invoke(cli, ["scenarios"])
    assert result.exit_code == 0, result.output
    assert "recon-and-enumerate" in result.output


def test_ai_providers_runs_offline_by_default() -> None:
    result = runner.invoke(cli, ["ai", "providers"])
    assert result.exit_code == 0, result.output
    assert "offline" in result.output.lower()


def test_template_valid(tmp_path) -> None:
    tpl = tmp_path / "mission.yaml"
    tpl.write_text(
        "name: demo\n"
        "targets:\n  - scanme.nmap.org\n"
        "scope_rules:\n  - {pattern: scanme.nmap.org}\n"
        "authorization_token: RoE-1\n",
        encoding="utf-8",
    )
    result = runner.invoke(cli, ["template", str(tpl)])
    assert result.exit_code == 0, result.output
    assert "OK" in result.output
    assert "demo" in result.output


def test_template_missing_keys_fails(tmp_path) -> None:
    tpl = tmp_path / "bad.yaml"
    tpl.write_text("name: demo\n", encoding="utf-8")
    result = runner.invoke(cli, ["template", str(tpl)])
    assert result.exit_code == 1
    assert "missing keys" in result.output


def test_template_empty_targets_fails(tmp_path) -> None:
    tpl = tmp_path / "empty.yaml"
    tpl.write_text(
        "name: demo\ntargets: []\nscope_rules: []\nauthorization_token: RoE-1\n",
        encoding="utf-8",
    )
    result = runner.invoke(cli, ["template", str(tpl)])
    assert result.exit_code == 1
    assert "targets cannot be empty" in result.output


def _write_findings(tmp_path) -> str:
    findings = [
        {
            "module": "netassault",
            "severity": "high",
            "title": "Open SSH service",
            "target": "scanme.nmap.org",
            "evidence": "22/tcp open ssh",
        },
        {
            "module": "webbreacher",
            "severity": "medium",
            "title": "Missing security headers",
            "target": "http://scanme.nmap.org",
            "evidence": "no Content-Security-Policy",
        },
    ]
    path = tmp_path / "findings.json"
    path.write_text(json.dumps(findings), encoding="utf-8")
    return str(path)


def test_ai_advise_offline(tmp_path) -> None:
    report = _write_findings(tmp_path)
    out = tmp_path / "analysis.json"
    result = runner.invoke(cli, ["ai", "advise", report, "--output", str(out)])
    assert result.exit_code == 0, result.output
    assert "Risk score" in result.output
    data = json.loads(out.read_text(encoding="utf-8"))
    assert "risk_score" in data
    assert 0 <= data["risk_score"] <= 100


def test_ai_recommend_offline(tmp_path) -> None:
    report = _write_findings(tmp_path)
    result = runner.invoke(cli, ["ai", "recommend", report])
    assert result.exit_code == 0, result.output
    assert "Recommended modules" in result.output


def test_scan_autopilot_chains_beyond_the_seed_module(monkeypatch) -> None:
    """``scan --autopilot`` must run more than just the seed module when the
    evidence it gathers (here: a CT-log subdomain containing "web") triggers
    a further recommendation. The literal-IP target skips the DNS resolver
    entirely, and crt.sh/the webbreacher HTTP check are both mocked, so no
    real network access happens."""
    monkeypatch.setattr("pegase.modules.recon.whois", None)

    # ``pegase.modules.recon.httpx`` and ``pegase.modules.webbreacher.httpx``
    # are the *same* imported module object, so ``httpx.AsyncClient`` can only
    # be monkeypatched once globally - one handler must serve both call sites,
    # dispatched by request URL.
    def handler(request: httpx.Request) -> httpx.Response:
        if "crt.sh" in str(request.url):
            return httpx.Response(200, content=b'[{"name_value": "web.203.0.113.10"}]')
        return httpx.Response(200, content=b"ok", headers={"Server": "nginx"})

    class _PatchedClient(httpx.AsyncClient):  # type: ignore[misc]
        def __init__(self, *a, **kw):
            kw["transport"] = httpx.MockTransport(handler)
            super().__init__(*a, **kw)

    monkeypatch.setattr("httpx.AsyncClient", _PatchedClient)

    result = runner.invoke(
        cli,
        [
            "scan",
            "--target", "203.0.113.10",
            "--authorization", "RoE-test",
            "--allow-active",
            "--autopilot",
            "--max-rounds", "3",
            "--max-modules", "10",
        ],
    )
    assert result.exit_code == 0, result.output
    out = result.output.lower()
    assert "autopilot" in out
    assert "round 1" in out
    assert "round 2" in out
    assert "webbreacher" in out


def test_scan_without_autopilot_runs_only_requested_modules(monkeypatch) -> None:
    monkeypatch.setattr("pegase.modules.recon.whois", None)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"[]")

    monkeypatch.setattr(
        "pegase.modules.recon.httpx.AsyncClient",
        lambda *a, **kw: httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )

    result = runner.invoke(
        cli,
        ["scan", "--target", "203.0.113.11", "--authorization", "RoE-test"],
    )
    assert result.exit_code == 0, result.output
    assert "autopilot" not in result.output.lower()


def test_cli_help_lists_commands() -> None:
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    for cmd in ("modules", "scenarios", "scan", "audit", "ai"):
        assert cmd in result.output
