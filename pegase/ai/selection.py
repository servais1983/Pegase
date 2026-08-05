"""Recon-aware module selection.

Rather than firing every module blindly, PEGASE picks the next modules based on
what reconnaissance actually observed. Given the findings gathered so far (and
the target list), it recommends which additional modules are worth running, with
a reason and a priority. The recommendation is deterministic and evidence-driven
- it never invents a reason that the findings don't support.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

from pegase.modules import available_modules


@dataclass
class ModuleRecommendation:
    module: str
    priority: int  # 1 (low) .. 5 (urgent)
    reason: str
    triggered_by: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# signal patterns -> (module, priority, reason)
_SIGNALS: list[tuple[re.Pattern[str], str, int, str]] = [
    (re.compile(r"\b(80|443|8080|8443|http|https|web|nginx|apache|iis)\b", re.I),
     "webbreacher", 4, "HTTP surface observed - enumerate the web application."),
    (re.compile(r"\b(22|ssh|445|smb|3389|rdp|21|ftp|open port|service)\b", re.I),
     "netassault", 4, "Exposed network service observed - enumerate it."),
    (re.compile(r"\b(s3|bucket|aws|gcp|azure|iam|cloud|storage)\b", re.I),
     "cloudstrike", 4, "Cloud footprint observed - review posture and identity."),
    (re.compile(r"\b(chat|/v1/|completion|prompt|assistant|llm|openai|gpt|bot)\b", re.I),
     "neuroprobe", 5, "LLM/chat endpoint observed - test for prompt injection."),
    (re.compile(r"\b(apk|android|ios|mobile|play\.google|itunes)\b", re.I),
     "mobilehunter", 3, "Mobile artifact observed - inspect the app."),
    (re.compile(r"\b(email|@|employee|linkedin|staff|phish)\b", re.I),
     "socialmatrix", 2, "People/email surface observed - consider social vectors."),
]


def recommend_modules(
    findings: list[dict[str, Any]],
    targets: list[str] | None = None,
    already_run: set[str] | None = None,
) -> list[ModuleRecommendation]:
    registry = available_modules()
    already_run = {m.lower() for m in (already_run or set())}
    targets = targets or []

    # Aggregate the text we can key signals off of.
    corpus: dict[str, list[str]] = {}
    for f in findings:
        blob = " ".join(str(f.get(k, "")) for k in ("title", "description", "target"))
        ev = f.get("evidence")
        if isinstance(ev, dict):
            blob += " " + " ".join(str(v) for v in ev.values())
        corpus.setdefault(blob, []).append(str(f.get("target", "")))
    target_blob = " ".join(targets)

    recs: dict[str, ModuleRecommendation] = {}
    for pattern, module, priority, reason in _SIGNALS:
        if module not in registry or module in already_run:
            continue
        hits: list[str] = []
        for blob, tgts in corpus.items():
            if pattern.search(blob):
                hits.extend(t for t in tgts if t)
        if pattern.search(target_blob):
            hits.extend(t for t in targets)
        if hits:
            recs[module] = ModuleRecommendation(
                module=module,
                priority=priority,
                reason=reason,
                triggered_by=sorted(set(hits))[:10],
            )

    # Correlators are worth running whenever there is anything to correlate.
    if findings:
        for module, reason in (
            ("vulnmatrix", "Findings exist - correlate them against known-vulnerable versions."),
            ("postxploit", "Findings exist - model attack paths and impact."),
        ):
            if module in registry and module not in already_run and module not in recs:
                recs[module] = ModuleRecommendation(
                    module=module, priority=3, reason=reason,
                    triggered_by=sorted({str(f.get("target", "")) for f in findings if f.get("target")})[:10],
                )

    return sorted(recs.values(), key=lambda r: r.priority, reverse=True)
