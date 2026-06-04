"""Celery task pipeline test (run synchronously against SQLite).

We invoke ``run_mission_task`` as a plain function (Celery tasks are callable)
with the DB pointed at a temporary SQLite file, and a registered fake module,
to prove the API->worker->DB persistence path end-to-end without a broker.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from pegase.core.scope import ActionType
from pegase.db.models import Base, Finding, Mission, MissionStatus
from pegase.modules.base import Finding as ModFinding
from pegase.modules.base import Module, ModuleResult


class _Fake(Module):
    name = "faketest"
    action_type = ActionType.PASSIVE

    async def run(self, *, targets, guard, parameters=None) -> ModuleResult:
        guard.check(targets[0], self.action_type)
        return ModuleResult(
            module=self.name,
            findings=[
                ModFinding(
                    module=self.name,
                    target=targets[0],
                    title="fake finding",
                    description="from worker test",
                    severity="high",
                )
            ],
        )


@pytest.fixture()
def sqlite_url(tmp_path, monkeypatch):
    db_file = tmp_path / "worker.db"
    url = f"sqlite:///{db_file}"
    engine = create_engine(url, future=True)
    Base.metadata.create_all(engine)
    Session = sessionmaker(engine, future=True, expire_on_commit=False)
    with Session() as s:
        s.add(
            Mission(
                id="m-worker",
                name="worker-test",
                status=MissionStatus.RUNNING,
                targets=["example.com"],
                scope_rules=[{"pattern": "example.com", "include": True}],
                allowed_actions=["passive"],
                parameters={},
                authorization_token="RoE-1",
                starts_at=datetime.now(UTC),
            )
        )
        s.commit()

    # Point the sync session + settings + audit at the temp resources.
    from pegase.core import config as cfg

    monkeypatch.setenv("PEGASE_DATABASE_SYNC_URL", url)
    monkeypatch.setenv("PEGASE_AUDIT_LOG_PATH", str(tmp_path / "audit.log"))
    monkeypatch.setenv("PEGASE_ARTIFACT_DIR", str(tmp_path / "artifacts"))
    cfg.get_settings.cache_clear()  # type: ignore[attr-defined]

    # Register the fake module in the registry used by the task.
    import pegase.modules as modules_pkg

    orig = modules_pkg.available_modules

    def _patched():
        reg = dict(orig())
        reg["faketest"] = _Fake
        return reg

    monkeypatch.setattr("pegase.tasks.scans.available_modules", _patched)
    # Reset audit singleton.
    from pegase.core import audit

    audit._default = None
    return url


def test_run_mission_task_persists_findings(sqlite_url):
    from pegase.tasks.scans import run_mission_task

    result = run_mission_task.run("m-worker", ["faketest"], "tester")
    assert result["ok"] is True
    assert result["findings"] == 1

    engine = create_engine(sqlite_url, future=True)
    Session = sessionmaker(engine, future=True)
    with Session() as s:
        mission = s.scalar(select(Mission).where(Mission.id == "m-worker"))
        assert mission.status == MissionStatus.COMPLETED
        findings = list(s.scalars(select(Finding).where(Finding.mission_id == "m-worker")))
        assert len(findings) == 1
        assert findings[0].title == "fake finding"
        assert findings[0].severity.value == "high"
