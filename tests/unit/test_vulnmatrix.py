"""VulnMatrix correlation tests."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from pegase.core.scope import ActionType, Scope, ScopeGuard, ScopeRule
from pegase.modules.vulnmatrix import VulnMatrix


@pytest.mark.asyncio
async def test_vulnmatrix_matches_vsftpd_backdoor():
    scope = Scope(
        rules=[ScopeRule("10.0.0.0/24")],
        allowed_actions={ActionType.PASSIVE},
        authorization_token="t",
        starts_at=datetime.now(UTC),
    )
    guard = ScopeGuard(scope)
    prior = [
        {
            "target": "10.0.0.5",
            "title": "Open port 21/tcp (ftp)",
            "description": "vsftpd 2.3.4",
            "evidence": {"product": "vsftpd", "version": "2.3.4"},
        }
    ]
    result = await VulnMatrix().run(
        targets=[], guard=guard, parameters={"findings": prior}
    )
    assert any(f.severity == "critical" for f in result.findings)
