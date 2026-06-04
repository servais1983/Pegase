"""Base classes for PEGASE modules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar

from pegase.core.scope import ActionType, ScopeGuard


@dataclass
class Finding:
    module: str
    target: str
    title: str
    description: str
    severity: str = "info"  # info|low|medium|high|critical
    evidence: dict[str, Any] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)


@dataclass
class ModuleResult:
    module: str
    findings: list[Finding] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


class Module(ABC):
    """Base class for every attack / support module.

    ``needs_upstream_findings`` is the dependency hint used by the
    Orchestrator: modules with this flag run only after every other module
    has finished, and receive the consolidated finding list through
    ``parameters["findings"]``.
    """

    name: ClassVar[str] = "module"
    description: ClassVar[str] = ""
    action_type: ClassVar[ActionType] = ActionType.PASSIVE
    needs_upstream_findings: ClassVar[bool] = False

    @abstractmethod
    async def run(
        self,
        *,
        targets: list[str],
        guard: ScopeGuard,
        parameters: dict[str, Any] | None = None,
    ) -> ModuleResult:
        ...
