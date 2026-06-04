"""Scope enforcement tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from pegase.core.scope import ActionType, Scope, ScopeGuard, ScopeRule, ScopeViolation


def _scope(**kw) -> Scope:
    defaults = dict(
        rules=[ScopeRule("10.0.0.0/24"), ScopeRule("*.example.com")],
        allowed_actions={ActionType.PASSIVE, ActionType.ACTIVE},
        authorization_token="ROE-123",
    )
    defaults.update(kw)
    return Scope(**defaults)


def test_cidr_in_scope():
    g = ScopeGuard(_scope())
    g.check("10.0.0.5", ActionType.ACTIVE)


def test_cidr_out_of_scope():
    g = ScopeGuard(_scope())
    with pytest.raises(ScopeViolation):
        g.check("10.0.1.5", ActionType.ACTIVE)


def test_wildcard_hostname_match():
    g = ScopeGuard(_scope())
    g.check("app.example.com", ActionType.PASSIVE)
    g.check("api.staging.example.com", ActionType.PASSIVE)


def test_explicit_exclusion_wins():
    scope = _scope(
        rules=[
            ScopeRule("*.example.com"),
            ScopeRule("ceo.example.com", include=False),
        ]
    )
    g = ScopeGuard(scope)
    g.check("app.example.com", ActionType.ACTIVE)
    with pytest.raises(ScopeViolation):
        g.check("ceo.example.com", ActionType.ACTIVE)


def test_action_not_allowed():
    g = ScopeGuard(_scope(allowed_actions={ActionType.PASSIVE}))
    with pytest.raises(ScopeViolation):
        g.check("app.example.com", ActionType.ACTIVE)


def test_missing_authorization_token():
    g = ScopeGuard(_scope(authorization_token=None))
    with pytest.raises(ScopeViolation):
        g.check("app.example.com", ActionType.PASSIVE)


def test_engagement_window_closed():
    past = datetime.now(UTC) - timedelta(hours=1)
    g = ScopeGuard(_scope(ends_at=past))
    with pytest.raises(ScopeViolation):
        g.check("app.example.com", ActionType.PASSIVE)


def test_url_target_normalized():
    g = ScopeGuard(_scope())
    g.check("https://api.example.com/v1/foo", ActionType.ACTIVE)


def test_allows_returns_bool():
    g = ScopeGuard(_scope())
    assert g.allows("app.example.com", ActionType.PASSIVE) is True
    assert g.allows("evil.org", ActionType.PASSIVE) is False
