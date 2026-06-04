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
@click.option("--output", type=click.Path(), default=None, help="Write JSON report to file")
def scan_cmd(
    targets: tuple[str, ...],
    modules: tuple[str, ...],
    scenario: str | None,
    scope_patterns: tuple[str, ...],
    authorization: str,
    allow_active: bool,
    allow_exploit: bool,
    output: str | None,
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

    if output:
        with open(output, "w", encoding="utf-8") as fh:
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
        console.print(f"wrote {output}")


if __name__ == "__main__":
    cli()
