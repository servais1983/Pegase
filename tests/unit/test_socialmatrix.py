"""SocialMatrix campaign generation tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pegase.core.audit import AuditLog
from pegase.core.scope import ActionType, Scope, ScopeGuard, ScopeRule
from pegase.modules.socialmatrix import SocialMatrix


@pytest.mark.asyncio
async def test_socialmatrix_requires_consent_proof(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "pegase.modules.socialmatrix.get_audit_log",
        lambda: AuditLog(tmp_path / "audit.log"),
    )
    scope = Scope(
        rules=[ScopeRule("example.com")],
        allowed_actions={ActionType.PASSIVE},
        authorization_token="t",
        starts_at=datetime.now(UTC),
    )
    guard = ScopeGuard(scope)
    with pytest.raises(ValueError, match="consent_proof"):
        await SocialMatrix().run(
            targets=[],
            guard=guard,
            parameters={"recipients": [{"email": "a@example.com"}]},
        )


@pytest.mark.asyncio
async def test_socialmatrix_generates_artifacts(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "pegase.modules.socialmatrix.get_audit_log",
        lambda: AuditLog(tmp_path / "audit.log"),
    )

    class _S:
        artifact_dir = tmp_path / "artifacts"
        require_authorization_token = True

    monkeypatch.setattr(
        "pegase.modules.socialmatrix.get_settings", lambda: _S()
    )

    scope = Scope(
        rules=[ScopeRule("example.com")],
        allowed_actions={ActionType.PASSIVE},
        authorization_token="t",
        starts_at=datetime.now(UTC),
    )
    guard = ScopeGuard(scope)
    result = await SocialMatrix().run(
        targets=[],
        guard=guard,
        parameters={
            "campaign_id": "test-campaign",
            "consent_proof": "RoE-2026-001-clause-7",
            "brand": "Acme",
            "recipients": [
                {"email": "alice@example.com", "name": "Alice"},
                {"email": "bob@example.com", "name": "Bob"},
            ],
        },
    )
    assert result.raw["campaign_id"] == "test-campaign"
    assert len(result.raw["recipients"]) == 2
    campaign_dir = Path(_S.artifact_dir) / "socialmatrix" / "test-campaign"
    assert (campaign_dir / "campaign.json").exists()
    manifest = json.loads((campaign_dir / "campaign.json").read_text())
    assert manifest["consent_proof"] == "RoE-2026-001-clause-7"
    # Each recipient gets its own page
    page_count = len(list(campaign_dir.glob("*.html")))
    assert page_count == 2


@pytest.mark.asyncio
async def test_socialmatrix_rejects_out_of_scope_recipient(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "pegase.modules.socialmatrix.get_audit_log",
        lambda: AuditLog(tmp_path / "audit.log"),
    )

    class _S:
        artifact_dir = tmp_path / "artifacts"
        require_authorization_token = True

    monkeypatch.setattr(
        "pegase.modules.socialmatrix.get_settings", lambda: _S()
    )

    scope = Scope(
        rules=[ScopeRule("example.com")],
        allowed_actions={ActionType.PASSIVE},
        authorization_token="t",
        starts_at=datetime.now(UTC),
    )
    from pegase.core.scope import ScopeViolation

    with pytest.raises(ScopeViolation):
        await SocialMatrix().run(
            targets=[],
            guard=ScopeGuard(scope),
            parameters={
                "consent_proof": "RoE-1",
                "recipients": [{"email": "victim@evil.org"}],
            },
        )


@pytest.mark.asyncio
async def test_socialmatrix_requires_non_empty_recipients(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "pegase.modules.socialmatrix.get_audit_log",
        lambda: AuditLog(tmp_path / "audit.log"),
    )
    scope = Scope(
        rules=[ScopeRule("example.com")],
        allowed_actions={ActionType.PASSIVE},
        authorization_token="t",
        starts_at=datetime.now(UTC),
    )
    guard = ScopeGuard(scope)
    with pytest.raises(ValueError, match="non-empty 'recipients'"):
        await SocialMatrix().run(
            targets=[], guard=guard,
            parameters={"recipients": [], "consent_proof": "RoE-clause-3"},
        )


@pytest.mark.asyncio
async def test_socialmatrix_rejects_unknown_template(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "pegase.modules.socialmatrix.get_audit_log",
        lambda: AuditLog(tmp_path / "audit.log"),
    )
    scope = Scope(
        rules=[ScopeRule("example.com")],
        allowed_actions={ActionType.PASSIVE},
        authorization_token="t",
        starts_at=datetime.now(UTC),
    )
    guard = ScopeGuard(scope)
    with pytest.raises(ValueError, match="unknown template"):
        await SocialMatrix().run(
            targets=[], guard=guard,
            parameters={
                "recipients": [{"email": "a@example.com"}],
                "consent_proof": "RoE-clause-3",
                "template": "does-not-exist",
            },
        )


@pytest.mark.asyncio
async def test_socialmatrix_skips_recipient_without_email(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "pegase.modules.socialmatrix.get_audit_log",
        lambda: AuditLog(tmp_path / "audit.log"),
    )
    monkeypatch.chdir(tmp_path)
    scope = Scope(
        rules=[ScopeRule("example.com")],
        allowed_actions={ActionType.PASSIVE},
        authorization_token="t",
        starts_at=datetime.now(UTC),
    )
    guard = ScopeGuard(scope)
    result = await SocialMatrix().run(
        targets=[], guard=guard,
        parameters={
            "recipients": [{"name": "No Email Here"}, {"email": "a@example.com"}],
            "consent_proof": "RoE-clause-3",
        },
    )
    assert len(result.raw["recipients"]) == 1
