"""Multi-model jury - confidence scoring for findings.

A finding can be validated by putting it before several models: one asserts, the
others adjudicate. PEGASE's jury does exactly that, but with a guarantee - the
*deterministic* juror always sits on the panel and votes purely on the evidence
attached to the finding (references, evidence richness, corroborating severity).
Optional LLM jurors add their vote on top; the final verdict is the panel
majority weighted by confidence. With no model configured the jury still returns
a defensible, evidence-based confidence rather than a coin flip.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

from pegase.ai.providers import LLMProvider
from pegase.core.logging import get_logger

log = get_logger(__name__)

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Vote:
    juror: str
    confirmed: bool
    confidence: float  # 0.0 .. 1.0
    rationale: str


@dataclass
class Verdict:
    finding: str
    confirmed: bool
    confidence: float
    votes: list[Vote] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


class Jury:
    def __init__(self, providers: list[LLMProvider] | None = None) -> None:
        # Non-offline providers become live jurors; the deterministic juror is
        # always present.
        self._jurors = [p for p in (providers or []) if not p.offline]

    async def deliberate(self, finding: dict[str, Any]) -> Verdict:
        votes = [_heuristic_vote(finding)]
        for provider in self._jurors:
            vote = await _llm_vote(provider, finding)
            if vote is not None:
                votes.append(vote)

        # Weighted majority: sum signed confidence.
        signed = sum((v.confidence if v.confirmed else -v.confidence) for v in votes)
        confirmed = signed >= 0
        confidence = round(min(1.0, abs(signed) / len(votes)), 3)
        return Verdict(
            finding=finding.get("title", "") or str(finding.get("id", "")),
            confirmed=confirmed,
            confidence=confidence,
            votes=votes,
        )


def _heuristic_vote(finding: dict[str, Any]) -> Vote:
    """Evidence-only confidence. More receipts + higher severity + references
    => higher confidence that the finding is real and actionable."""
    sev = finding.get("severity", "info")
    sev = sev.value if hasattr(sev, "value") else str(sev).lower()
    ev = finding.get("evidence") or {}
    refs = finding.get("references") or []

    score = 0.35
    score += 0.10 * _SEV_RANK.get(sev, 0)          # up to +0.40
    if isinstance(ev, dict) and ev:
        score += min(0.20, 0.04 * len(ev))          # richer evidence
    if refs:
        score += 0.10                               # external corroboration
    if finding.get("description"):
        score += 0.05
    confidence = round(max(0.0, min(1.0, score)), 3)
    confirmed = confidence >= 0.5
    reason = f"evidence-based: severity={sev}, evidence_keys={len(ev) if isinstance(ev, dict) else 0}, refs={len(refs)}"
    return Vote(juror="deterministic", confirmed=confirmed, confidence=confidence, rationale=reason)


async def _llm_vote(provider: LLMProvider, finding: dict[str, Any]) -> Vote | None:
    system = (
        "You are a peer reviewer validating a penetration-test finding. Judge only "
        "from the evidence given. Reply as strict JSON: "
        '{"confirmed": bool, "confidence": 0..1, "rationale": "short"}. '
        "Do not invent facts beyond the evidence."
    )
    prompt = json.dumps({
        "title": finding.get("title"),
        "severity": str(finding.get("severity")),
        "description": finding.get("description"),
        "evidence": finding.get("evidence"),
        "references": finding.get("references"),
    }, default=str)[:4000]
    resp = await provider.complete(system=system, prompt=prompt)
    if not resp.ok or not resp.text:
        return None
    try:
        data = json.loads(_first_json(resp.text))
    except (ValueError, TypeError):
        log.info("jury_vote_unparseable", juror=provider.name)
        return None
    try:
        conf = float(data.get("confidence", 0.0))
    except (TypeError, ValueError):
        conf = 0.0
    return Vote(
        juror=provider.name,
        confirmed=bool(data.get("confirmed", False)),
        confidence=round(max(0.0, min(1.0, conf)), 3),
        rationale=str(data.get("rationale", ""))[:300],
    )


def _first_json(text: str) -> str:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        return text
    return text[start:end + 1]
