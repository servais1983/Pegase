"""PEGASE command-line interface."""

from __future__ import annotations

import asyncio
import json
import sys
from datetime import UTC, datetime

import click
from rich.console import Console
from rich.table import Table

from pegase.core.audit import get_audit_log
from pegase.core.auth import hash_password
from pegase.core.config import get_settings
from pegase.core.logging import configure_logging
from pegase.core.orchestrator import MissionContext, Orchestrator
from pegase.core.scope import ActionType, Scope, ScopeRule
from pegase.modules import available_modules

console = Console()


@click.group()
@click.version_option()
def cli() -> None:
    """PEGASE - legal pentest orchestration platform."""
    configure_logging()


@cli.command("modules")
def list_modules() -> None:
    """List the installed modules."""
    table = Table(title="PEGASE modules")
    table.add_column("Name")
    table.add_column("Type")
    table.add_column("Description")
    for cls in available_modules().values():
        table.add_row(cls.name, cls.action_type.value, cls.description)
    console.print(table)


@cli.command("audit")
def verify_audit() -> None:
    """Verify the integrity of the audit log hash chain."""
    audit = get_audit_log()
    ok, count, error = audit.verify()
    if ok:
        console.print(f"[green]OK[/green] {count} entries, chain valid.")
    else:
        console.print(f"[red]TAMPER[/red] after {count} entries: {error}")
        sys.exit(2)


@cli.group("user")
def user_grp() -> None:
    """User management."""


@user_grp.command("create")
@click.option("--username", required=True)
@click.option("--email", required=True)
@click.option("--password", required=True, prompt=True, hide_input=True, confirmation_prompt=True)
@click.option("--role", default="operator", type=click.Choice(["operator", "admin", "auditor"]))
def create_user(username: str, email: str, password: str, role: str) -> None:
    """Create a user directly in the database (bootstrap)."""
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import sessionmaker

    from pegase.db.models import User

    engine = create_engine(get_settings().database_sync_url, future=True)
    Session = sessionmaker(engine, future=True, expire_on_commit=False)
    with Session() as db:
        existing = db.scalar(select(User).where(User.username == username))
        if existing:
            click.echo(f"user {username} already exists", err=True)
            sys.exit(1)
        db.add(
            User(
                username=username,
                email=email,
                password_hash=hash_password(password),
                role=role,
            )
        )
        db.commit()
    console.print(f"[green]created user {username} (role={role})[/green]")


@cli.command("template")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
def template_cmd(path: str) -> None:
    """Validate a mission template YAML file."""
    import yaml

    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    required = {"name", "targets", "scope_rules", "authorization_token"}
    missing = required - set(data or {})
    if missing:
        console.print(f"[red]missing keys[/red]: {sorted(missing)}")
        sys.exit(1)
    if not data.get("targets"):
        console.print("[red]targets cannot be empty[/red]")
        sys.exit(1)
    console.print(
        f"[green]OK[/green] template '{data['name']}' "
        f"({len(data['targets'])} target(s))"
    )


@cli.group("ai")
def ai_grp() -> None:
    """PEGASE AI layer: advisor, module recommendation, providers."""


@ai_grp.command("providers")
def ai_providers_cmd() -> None:
    """Show the available LLM providers and the active configuration."""
    from pegase.ai.providers import available_providers, get_provider

    settings = get_settings()
    provider = get_provider(settings)
    table = Table(title="AI providers")
    table.add_column("Provider")
    table.add_column("Active")
    for name in available_providers():
        active = "[green]yes[/green]" if name == provider.name else ""
        table.add_row(name, active)
    console.print(table)
    console.print(
        f"Configured: provider=[cyan]{settings.ai_provider}[/cyan] "
        f"model=[cyan]{settings.ai_model or '(default)'}[/cyan] "
        f"effective=[cyan]{provider.name}[/cyan] "
        f"offline=[cyan]{provider.offline}[/cyan]"
    )


@ai_grp.command("advise")
@click.argument("report", type=click.Path(exists=True, dir_okay=False))
@click.option("--output", type=click.Path(), default=None, help="Write analysis JSON to file")
def ai_advise_cmd(report: str, output: str | None) -> None:
    """Run the grounded AI advisor over a JSON report/findings file."""
    from pegase.ai.advisor import AIAdvisor

    findings = _load_findings(report)
    analysis = asyncio.run(AIAdvisor().analyze(findings))

    console.print(f"[bold]Risk score:[/bold] {analysis.risk_score}/100 "
                  f"(provider={analysis.provider}, llm_used={analysis.llm_used})")
    console.print(f"[bold]Summary:[/bold] {analysis.executive_summary}\n")
    table = Table(title=f"Prioritized risks ({len(analysis.prioritized_risks)})")
    for col in ("Severity", "Risk", "Targets", "Remediation"):
        table.add_column(col)
    for r in analysis.prioritized_risks:
        table.add_row(r.severity, r.title, ", ".join(r.targets[:3]), r.remediation[:60] + "...")
    console.print(table)
    console.print(f"\n[bold]Attack narrative:[/bold] {analysis.attack_narrative}")

    if output:
        with open(output, "w", encoding="utf-8") as fh:
            json.dump(analysis.to_dict(), fh, indent=2, default=str)
        console.print(f"wrote {output}")


@ai_grp.command("recommend")
@click.argument("report", type=click.Path(exists=True, dir_okay=False))
@click.option("--target", "targets", multiple=True, help="Additional target context")
def ai_recommend_cmd(report: str, targets: tuple[str, ...]) -> None:
    """Recommend which modules to run next, based on findings so far."""
    from pegase.ai.selection import recommend_modules

    findings = _load_findings(report)
    already = {f.get("module", "") for f in findings}
    recs = recommend_modules(findings, list(targets), already_run=already)
    table = Table(title=f"Recommended modules ({len(recs)})")
    for col in ("Priority", "Module", "Reason", "Triggered by"):
        table.add_column(col)
    for r in recs:
        table.add_row(str(r.priority), r.module, r.reason, ", ".join(r.triggered_by[:3]))
    console.print(table)


def _load_findings(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        return data.get("findings", [])
    if isinstance(data, list):
        return data
    return []


@cli.command("scenarios")
def scenarios_cmd() -> None:
    """List built-in ThreatSim scenarios."""
    from pegase.core.scenarios import list_builtin_scenarios

    table = Table(title="ThreatSim scenarios")
    table.add_column("Name")
    table.add_column("Description")
    for name, desc in list_builtin_scenarios().items():
        table.add_row(name, desc)
    console.print(table)


@cli.command("scan")
@click.option("--target", "targets", multiple=True, required=True, help="Target host/URL/CIDR")
@click.option("--module", "modules", multiple=True, default=("recon",), help="Module(s) to run")
@click.option("--scenario", default=None, help="ThreatSim scenario name or YAML path (overrides --module)")
@click.option("--scope", "scope_patterns", multiple=True, help="In-scope pattern (default: targets)")
@click.option("--authorization", required=True, help="Authorization token / RoE reference")
@click.option("--allow-active", is_flag=True, default=False)
@click.option("--allow-exploit", is_flag=True, default=False)
@click.option("--output", type=click.Path(), default=None, help="Write the report to file")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "sarif", "csv"]),
    default="json",
    help="Format for --output (json | sarif | csv)",
)
@click.option("--ai", "ai_analyze", is_flag=True, default=False, help="Run the grounded AI advisor on the findings")
def scan_cmd(
    targets: tuple[str, ...],
    modules: tuple[str, ...],
    scenario: str | None,
    scope_patterns: tuple[str, ...],
    authorization: str,
    allow_active: bool,
    allow_exploit: bool,
    output: str | None,
    output_format: str,
    ai_analyze: bool,
) -> None:
    """Run a one-off mission from the command line."""
    registry = available_modules()

    parameters: dict = {}
    if scenario:
        from pegase.core.scenarios import load_scenario

        scen = load_scenario(scenario)
        errors = scen.validate()
        if errors:
            click.echo(f"scenario invalid: {errors}", err=True)
            sys.exit(1)
        modules = tuple(scen.all_modules())
        parameters = scen.merged_parameters()
        console.print(f"[cyan]scenario[/cyan] {scen.name}: modules={list(modules)}")

    unknown = set(modules) - set(registry.keys())
    if unknown:
        click.echo(f"unknown modules: {sorted(unknown)}", err=True)
        sys.exit(1)

    actions = {ActionType.PASSIVE}
    if allow_active:
        actions.add(ActionType.ACTIVE)
    if allow_exploit:
        actions.add(ActionType.EXPLOIT)

    patterns = scope_patterns or targets
    scope = Scope(
        rules=[ScopeRule(pattern=p) for p in patterns],
        allowed_actions=actions,
        starts_at=datetime.now(UTC),
        authorization_token=authorization,
    )
    instances = [registry[m]() for m in modules]
    ctx = MissionContext(
        mission_id="cli-" + datetime.now(UTC).strftime("%Y%m%d%H%M%S"),
        actor="cli",
        scope=scope,
        targets=list(targets),
        parameters=parameters,
    )
    orchestrator = Orchestrator(instances)
    outcome = asyncio.run(orchestrator.run(ctx))

    table = Table(title=f"Findings ({len(outcome.findings)})")
    for col in ("Severity", "Module", "Target", "Title"):
        table.add_column(col)
    for f in outcome.findings:
        table.add_row(f.severity, f.module, f.target, f.title)
    console.print(table)
    if outcome.errors:
        console.print("[red]errors[/red]:", outcome.errors)

    if ai_analyze:
        from pegase.ai.advisor import AIAdvisor

        findings_dicts = [
            {
                "module": f.module, "target": f.target, "title": f.title,
                "description": f.description, "severity": f.severity,
                "evidence": f.evidence, "references": f.references,
            }
            for f in outcome.findings
        ]
        analysis = asyncio.run(AIAdvisor().analyze(findings_dicts))
        console.print(
            f"\n[bold cyan]AI advisor[/bold cyan] (provider={analysis.provider}, "
            f"llm_used={analysis.llm_used}) - risk {analysis.risk_score}/100"
        )
        console.print(analysis.executive_summary)
        for r in analysis.prioritized_risks[:5]:
            console.print(f"  [{r.severity}] {r.title} -> {r.remediation}")

    if output:
        with open(output, "w", encoding="utf-8") as fh:
            if output_format == "sarif":
                from pegase.reporting.generator import build_sarif_report

                json.dump(
                    build_sarif_report(
                        list(outcome.findings), mission_name=outcome.mission_id
                    ),
                    fh,
                    indent=2,
                    default=str,
                )
            elif output_format == "csv":
                from pegase.reporting.generator import build_csv_report

                fh.write(build_csv_report(list(outcome.findings)))
            else:
                json.dump(
                    {
                        "mission_id": outcome.mission_id,
                        "errors": outcome.errors,
                        "findings": [
                            {
                                "module": f.module,
                                "target": f.target,
                                "title": f.title,
                                "description": f.description,
                                "severity": f.severity,
                                "evidence": f.evidence,
                                "references": f.references,
                            }
                            for f in outcome.findings
                        ],
                    },
                    fh,
                    indent=2,
                    default=str,
                )
        console.print(f"wrote {output} ({output_format})")


if __name__ == "__main__":
    cli()
