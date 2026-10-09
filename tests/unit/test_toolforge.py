"""ToolForge tests — subprocess execution is mocked, no real binaries run."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from pegase.core.scope import ActionType, Scope, ScopeGuard, ScopeRule, ScopeViolation
from pegase.modules.toolforge import ToolForge


def _guard(pattern: str = "example.com") -> ScopeGuard:
    scope = Scope(
        rules=[ScopeRule(pattern)],
        allowed_actions={ActionType.ACTIVE},
        authorization_token="t",
        starts_at=datetime.now(UTC),
    )
    return ScopeGuard(scope)


class _FakeProc:
    def __init__(self, returncode: int, stdout: bytes, stderr: bytes) -> None:
        self.returncode = returncode
        self._stdout = stdout
        self._stderr = stderr

    async def communicate(self):
        return self._stdout, self._stderr

    def kill(self):
        pass

    async def wait(self):
        return self.returncode


@pytest.mark.asyncio
async def test_toolforge_requires_tool_parameter():
    with pytest.raises(ValueError, match="requires parameters"):
        await ToolForge().run(targets=["example.com"], guard=_guard(), parameters={})


@pytest.mark.asyncio
async def test_toolforge_rejects_non_allowlisted_tool():
    with pytest.raises(ValueError, match="not in allowlist"):
        await ToolForge().run(
            targets=["example.com"],
            guard=_guard(),
            parameters={"tool": "rm -rf"},
        )


@pytest.mark.asyncio
async def test_toolforge_errors_when_binary_missing(monkeypatch):
    monkeypatch.setattr("pegase.modules.toolforge.shutil.which", lambda _b: None)
    with pytest.raises(RuntimeError, match="not found on PATH"):
        await ToolForge().run(
            targets=["example.com"],
            guard=_guard(),
            parameters={"tool": "dig"},
        )


@pytest.mark.asyncio
async def test_toolforge_runs_allowlisted_tool_and_captures_output(monkeypatch):
    monkeypatch.setattr("pegase.modules.toolforge.shutil.which", lambda _b: "/usr/bin/dig")

    captured_argv: list[str] = []

    async def fake_create_subprocess_exec(*argv, **kw):
        captured_argv.extend(argv)
        return _FakeProc(0, b"93.184.216.34\n", b"")

    monkeypatch.setattr(
        "pegase.modules.toolforge.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )

    result = await ToolForge().run(
        targets=["example.com"],
        guard=_guard(),
        parameters={"tool": "dig"},
    )

    assert captured_argv == ["dig", "+short", "example.com"]
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.severity == "info"
    assert "93.184.216.34" in f.description
    assert result.raw["example.com"]["dig"]["exit_code"] == 0


@pytest.mark.asyncio
async def test_toolforge_non_zero_exit_is_low_severity(monkeypatch):
    monkeypatch.setattr("pegase.modules.toolforge.shutil.which", lambda _b: "/usr/bin/dig")

    async def fake_create_subprocess_exec(*argv, **kw):
        return _FakeProc(1, b"", b"error: timed out")

    monkeypatch.setattr(
        "pegase.modules.toolforge.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )

    result = await ToolForge().run(
        targets=["example.com"],
        guard=_guard(),
        parameters={"tool": "dig"},
    )
    assert result.findings[0].severity == "low"
    assert "error: timed out" in result.findings[0].description


@pytest.mark.asyncio
async def test_toolforge_extra_tools_are_registered(monkeypatch):
    monkeypatch.setattr("pegase.modules.toolforge.shutil.which", lambda _b: "/usr/bin/customscan")

    async def fake_create_subprocess_exec(*argv, **kw):
        return _FakeProc(0, b"ok", b"")

    monkeypatch.setattr(
        "pegase.modules.toolforge.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )

    result = await ToolForge().run(
        targets=["example.com"],
        guard=_guard(),
        parameters={
            "tool": "customscan",
            "extra_tools": {"customscan": ["customscan", "--target", "{target}"]},
        },
    )
    assert result.findings[0].evidence["argv"] == [
        "customscan",
        "--target",
        "example.com",
    ]


@pytest.mark.asyncio
async def test_toolforge_enforces_scope_guard(monkeypatch):
    monkeypatch.setattr("pegase.modules.toolforge.shutil.which", lambda _b: "/usr/bin/dig")
    with pytest.raises(ScopeViolation):
        await ToolForge().run(
            targets=["not-in-scope.invalid"],
            guard=_guard("example.com"),
            parameters={"tool": "dig"},
        )
