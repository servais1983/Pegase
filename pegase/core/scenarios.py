"""ThreatSim - scenario engine.

A scenario describes a named, multi-stage engagement: an ordered list of
stages, each running a set of modules with stage-specific parameters. ThreatSim
resolves a scenario into the flat module list + parameter map that the
Orchestrator already understands, so scenarios are pure configuration on top of
the existing safe execution path (scope guard, audit, two-phase chaining).

Scenarios are loaded from YAML. Built-in scenarios model common APT-style
kill chains while staying within PEGASE's passive/active boundaries.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from pegase.modules import available_modules


@dataclass
class Stage:
    name: str
    modules: list[str]
    parameters: dict[str, Any] = field(default_factory=dict)


@dataclass
class Scenario:
    name: str
    description: str
    stages: list[Stage]

    def all_modules(self) -> list[str]:
        seen: list[str] = []
        for stage in self.stages:
            for m in stage.modules:
                if m not in seen:
                    seen.append(m)
        return seen

    def merged_parameters(self) -> dict[str, Any]:
        params: dict[str, Any] = {}
        for stage in self.stages:
            for module, mp in stage.parameters.items():
                params.setdefault(module, {}).update(mp)
        return params

    def validate(self) -> list[str]:
        errors: list[str] = []
        registry = available_modules()
        for stage in self.stages:
            for m in stage.modules:
                if m not in registry:
                    errors.append(f"stage '{stage.name}': unknown module '{m}'")
        if not self.stages:
            errors.append("scenario has no stages")
        return errors


_BUILTIN: dict[str, dict[str, Any]] = {
    "recon-and-enumerate": {
        "description": "OSINT recon, then network + web enumeration, then correlate.",
        "stages": [
            {"name": "recon", "modules": ["recon"]},
            {"name": "enumerate", "modules": ["netassault", "webbreacher"]},
            {"name": "correlate", "modules": ["vulnmatrix", "postxploit"]},
        ],
    },
    "external-apt": {
        "description": "Full external kill chain simulation.",
        "stages": [
            {"name": "recon", "modules": ["recon"]},
            {
                "name": "weaponize",
                "modules": ["netassault", "webbreacher"],
                "parameters": {"netassault": {"ports": "1-1024"}},
            },
            {"name": "analyze", "modules": ["vulnmatrix"]},
            {"name": "model", "modules": ["postxploit"]},
        ],
    },
    "cloud-review": {
        "description": "Cloud posture review + attack-path modelling.",
        "stages": [
            {"name": "assess", "modules": ["cloudstrike"]},
            {"name": "model", "modules": ["postxploit"]},
        ],
    },
}


def load_scenario(name_or_path: str) -> Scenario:
    """Load a built-in scenario by name, or a YAML file by path."""
    if name_or_path in _BUILTIN:
        data = _BUILTIN[name_or_path]
        return _from_dict(name_or_path, data)
    path = Path(name_or_path)
    if not path.exists():
        raise ValueError(
            f"unknown scenario '{name_or_path}'. "
            f"built-ins: {sorted(_BUILTIN)} or pass a YAML path."
        )
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return _from_dict(data.get("name", path.stem), data)


def list_builtin_scenarios() -> dict[str, str]:
    return {k: v["description"] for k, v in _BUILTIN.items()}


def _from_dict(name: str, data: dict[str, Any]) -> Scenario:
    stages = [
        Stage(
            name=s.get("name", f"stage-{i}"),
            modules=list(s.get("modules", [])),
            parameters=dict(s.get("parameters", {})),
        )
        for i, s in enumerate(data.get("stages", []))
    ]
    return Scenario(
        name=name,
        description=data.get("description", ""),
        stages=stages,
    )
