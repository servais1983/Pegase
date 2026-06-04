"""Scope / Rules-of-Engagement enforcement.

Every active action issued by any module MUST pass through ``ScopeGuard``.
A request is allowed only when:
  * the mission has a current, non-expired authorization,
  * the target (IP, hostname or URL) is covered by an in-scope rule,
  * the target is not in any explicit out-of-scope rule,
  * the action type is permitted (passive / active / exploit),
  * the time window is open.

The guard never trusts caller-supplied scope - it always re-validates against
the mission record loaded from the database (or from an in-memory fixture in
tests). Any denial is also written to the audit log.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from urllib.parse import urlparse


class ActionType(str, Enum):
    PASSIVE = "passive"  # OSINT, DNS, whois - never touches target
    ACTIVE = "active"  # nmap, http GET, banner grab - touches but doesn't exploit
    EXPLOIT = "exploit"  # actual exploitation - requires explicit allow


class ScopeViolation(Exception):
    """Raised when an action would step outside the agreed scope."""

    def __init__(self, message: str, target: str, action: ActionType) -> None:
        super().__init__(message)
        self.target = target
        self.action = action


@dataclass(frozen=True)
class ScopeRule:
    """A single in- or out-of-scope rule.

    ``pattern`` accepts:
      * CIDR        (e.g. ``10.0.0.0/24``)
      * single IP   (e.g. ``203.0.113.4``)
      * hostname    (e.g. ``app.example.com``)
      * wildcard    (e.g. ``*.example.com``)
      * URL         (e.g. ``https://api.example.com``)
    """

    pattern: str
    include: bool = True  # False = explicit exclusion (out-of-scope)

    def matches(self, target: str) -> bool:
        return _matches(self.pattern, target)


@dataclass
class Scope:
    rules: list[ScopeRule] = field(default_factory=list)
    allowed_actions: set[ActionType] = field(
        default_factory=lambda: {ActionType.PASSIVE, ActionType.ACTIVE}
    )
    starts_at: datetime | None = None
    ends_at: datetime | None = None
    authorization_token: str | None = None

    def in_window(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(UTC)
        starts = _as_aware(self.starts_at)
        ends = _as_aware(self.ends_at)
        if starts and now < starts:
            return False
        return not (ends and now > ends)

    def covers(self, target: str) -> bool:
        normalized = _normalize(target)
        excluded = any(
            r.matches(normalized) for r in self.rules if not r.include
        )
        if excluded:
            return False
        return any(r.matches(normalized) for r in self.rules if r.include)


class ScopeGuard:
    """Façade used by modules. Raises ``ScopeViolation`` to abort the action."""

    def __init__(self, scope: Scope, *, require_authorization: bool = True) -> None:
        self._scope = scope
        self._require_auth = require_authorization

    def check(self, target: str, action: ActionType) -> None:
        if self._require_auth and not self._scope.authorization_token:
            raise ScopeViolation(
                "Mission has no authorization token; refusing to act.",
                target=target,
                action=action,
            )
        if not self._scope.in_window():
            raise ScopeViolation(
                "Mission engagement window is closed.",
                target=target,
                action=action,
            )
        if action not in self._scope.allowed_actions:
            raise ScopeViolation(
                f"Action '{action.value}' not permitted by Rules of Engagement.",
                target=target,
                action=action,
            )
        if not self._scope.covers(target):
            raise ScopeViolation(
                f"Target '{target}' is out of scope.",
                target=target,
                action=action,
            )

    def allows(self, target: str, action: ActionType) -> bool:
        try:
            self.check(target, action)
            return True
        except ScopeViolation:
            return False


# ---------- matching helpers ---------------------------------------------


def _as_aware(dt: datetime | None) -> datetime | None:
    """Coerce a possibly-naive datetime to UTC.

    Datetimes loaded from SQLite (and some drivers) come back naive even though
    they were stored as UTC. Treat naive values as UTC so window comparisons
    never raise ``can't compare offset-naive and offset-aware datetimes``.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def _normalize(target: str) -> str:
    target = target.strip()
    if "://" in target:
        parsed = urlparse(target)
        return (parsed.hostname or target).lower()
    return target.lower()


_WILDCARD_RE = re.compile(r"^\*\.([a-z0-9.\-]+)$", re.IGNORECASE)


def _matches(pattern: str, target: str) -> bool:
    pattern = pattern.strip()
    target = _normalize(target)

    # URL-style pattern - reduce to host
    if "://" in pattern:
        pattern = urlparse(pattern).hostname or pattern

    # CIDR / single IP
    try:
        network = ipaddress.ip_network(pattern, strict=False)
        try:
            return ipaddress.ip_address(target) in network
        except ValueError:
            return False
    except ValueError:
        pass

    # Wildcard hostname
    m = _WILDCARD_RE.match(pattern)
    if m:
        suffix = m.group(1).lower()
        return target == suffix or target.endswith("." + suffix)

    return pattern.lower() == target
