"""AIAdvisor - grounded analysis over a mission's findings.

The advisor turns a raw finding list into decision-ready output:

  * a risk score (0-100) derived from severity weights,
  * prioritized, de-duplicated risks each carrying its receipts and a
    remediation drawn from a curated knowledge base,
  * an attack-chain narrative reconstructed from the finding graph,
  * an executive summary.

Everything above is produced by a **deterministic engine** that always runs, so
the advisor is useful offline and in CI. When a real LLM provider is configured,
its narrative is layered on top - but only after every sentence passes the
``Grounder``. Model prose that cannot be tied back to a finding is discarded,
never shown. This is how PEGASE gets LLM-grade intelligence without inheriting
LLM hallucination risk.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

from pegase.ai.grounding import Grounder
from pegase.ai.providers import LLMProvider, get_provider
from pegase.core.logging import get_logger

log = get_logger(__name__)

_SEV_WEIGHT = {"info": 0, "low": 2, "medium": 5, "high": 8, "critical": 13}
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Remediation knowledge base: (regex over title+description) -> advice.
# First match wins; order from most to least specific.
_REMEDIATION_KB: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"vsftpd 2\.3\.4|backdoor", re.I),
     "Remove the backdoored build immediately and rebuild the host from a trusted image; rotate all credentials that touched it."),
    (re.compile(r"openssh", re.I),
     "Upgrade OpenSSH to a supported release, disable password auth, and restrict exposure to a bastion/VPN."),
    (re.compile(r"apache|nginx|iis|httpd", re.I),
     "Patch the web server to the current stable branch and remove version banners (ServerTokens/server_tokens)."),
    (re.compile(r"\bphp\b", re.I),
     "Move to a supported PHP branch and enable disable_functions/open_basedir hardening."),
    (re.compile(r"tls|certificate|ssl|cipher", re.I),
     "Renew/repair the certificate chain and disable legacy TLS versions and weak ciphers."),
    (re.compile(r"open port|service|banner", re.I),
     "Close or firewall the exposed service; expose only what the engagement scope requires."),
    (re.compile(r"prompt injection|llm|system prompt|jailbreak", re.I),
     "Isolate untrusted input from system instructions, add output filtering, and never expose the system prompt to users."),
    (re.compile(r"subdomain|dns|ct log", re.I),
     "Review the exposed subdomain inventory and decommission stale or forgotten hosts."),
    (re.compile(r"header|cors|cookie", re.I),
     "Set the missing security headers (CSP, HSTS, X-Content-Type-Options) and scope cookies with Secure/HttpOnly/SameSite."),
    (re.compile(r"s3|bucket|storage|iam|cloud", re.I),
     "Apply least-privilege IAM, block public access on storage, and enable logging + object lock where relevant."),
]

_GENERIC_REMEDIATION = (
    "Validate the finding, assess exploitability in context, and remediate per your"
    " patch-management and hardening standards."
)


@dataclass
class RiskItem:
    title: str
    severity: str
    targets: list[str]
    rationale: str
    remediation: str
    evidence_refs: list[str] = field(default_factory=list)
    count: int = 1

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AIAnalysis:
    risk_score: int
    executive_summary: str
    attack_narrative: str
    prioritized_risks: list[RiskItem]
    provider: str
    grounded: bool
    llm_used: bool
    dropped_sentences: list[str] = field(default_factory=list)
    severity_counts: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["prioritized_risks"] = [r.to_dict() for r in self.prioritized_risks]
        return d


class AIAdvisor:
    def __init__(self, provider: LLMProvider | None = None) -> None:
        self._provider = provider or get_provider()

    async def analyze(self, findings: list[dict[str, Any]]) -> AIAnalysis:
        findings = [_normalize(f) for f in findings]
        counts = _severity_counts(findings)
        score = _risk_score(findings)
        risks = _build_risks(findings)
        narrative = _attack_narrative(findings)
        summary = _executive_summary(findings, score, counts)

        analysis = AIAnalysis(
            risk_score=score,
            executive_summary=summary,
            attack_narrative=narrative,
            prioritized_risks=risks,
            provider=self._provider.name,
            grounded=True,
            llm_used=False,
            severity_counts=counts,
        )

        # Optional LLM enrichment - only replaces the narrative if grounded.
        if not self._provider.offline and findings:
            await self._enrich(analysis, findings)
        return analysis

    async def _enrich(self, analysis: AIAnalysis, findings: list[dict[str, Any]]) -> None:
        system = (
            "You are a senior penetration-test analyst. Write a concise, factual "
            "attack-chain narrative. Reference only the findings provided by their "
            "target and title. Do not speculate or invent hosts, ports, CVEs or "
            "services. If unsure, say less."
        )
        prompt = "Findings:\n" + "\n".join(
            f"- [{f['severity']}] {f['module']} @ {f['target']}: {f['title']}"
            for f in findings[:60]
        )
        resp = await self._provider.complete(system=system, prompt=prompt)
        if not resp.ok or not resp.text:
            return
        grounder = Grounder(findings)
        kept, dropped = grounder.ground_text(resp.text)
        analysis.dropped_sentences = dropped
        # Only adopt the model narrative when enough of it survived grounding.
        if kept and len(kept) >= 0.5 * len(resp.text):
            analysis.attack_narrative = kept
            analysis.llm_used = True
        else:
            log.info("llm_narrative_rejected", kept=len(kept), total=len(resp.text))


# ---------------------------------------------------------------------------
# Deterministic engine
# ---------------------------------------------------------------------------


def _normalize(f: Any) -> dict[str, Any]:
    """Accept both plain dicts and ORM Finding-like objects."""
    if isinstance(f, dict):
        d = dict(f)
    else:  # ORM object
        d = {
            "id": getattr(f, "id", ""),
            "module": getattr(f, "module", ""),
            "target": getattr(f, "target", ""),
            "title": getattr(f, "title", ""),
            "description": getattr(f, "description", ""),
            "severity": getattr(f, "severity", "info"),
            "evidence": getattr(f, "evidence", {}) or {},
            "references": getattr(f, "references", []) or [],
        }
    sev = d.get("severity", "info")
    d["severity"] = sev.value if hasattr(sev, "value") else str(sev).lower()
    d.setdefault("evidence", {})
    d.setdefault("references", [])
    d.setdefault("module", "")
    d.setdefault("target", "")
    d.setdefault("title", "")
    d.setdefault("description", "")
    return d


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {k: 0 for k in _SEV_WEIGHT}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts


def _risk_score(findings: list[dict[str, Any]]) -> int:
    """Bounded 0-100 score. A single critical already lands in the danger zone;
    volume of lower-severity findings raises it with diminishing returns."""
    if not findings:
        return 0
    raw = sum(_SEV_WEIGHT.get(f["severity"], 0) for f in findings)
    # Squash with a soft curve so 3-4 highs approach but never trivially hit 100.
    score = 100 * (1 - (0.86 ** raw))
    return int(round(min(100.0, score)))


def _remediation_for(text: str) -> str:
    for pattern, advice in _REMEDIATION_KB:
        if pattern.search(text):
            return advice
    return _GENERIC_REMEDIATION


def _build_risks(findings: list[dict[str, Any]]) -> list[RiskItem]:
    """Group findings by (title) and rank by severity then count."""
    groups: dict[str, RiskItem] = {}
    for f in findings:
        if f["severity"] in ("info",):
            continue  # informational noise is not a "risk" item
        key = f["title"].strip().lower()
        blob = f"{f['title']} {f['description']}"
        ref = str(f.get("id") or f["target"])
        if key in groups:
            item = groups[key]
            item.count += 1
            if f["target"] and f["target"] not in item.targets:
                item.targets.append(f["target"])
            if ref not in item.evidence_refs:
                item.evidence_refs.append(ref)
            if _SEV_RANK[f["severity"]] > _SEV_RANK[item.severity]:
                item.severity = f["severity"]
        else:
            groups[key] = RiskItem(
                title=f["title"],
                severity=f["severity"],
                targets=[f["target"]] if f["target"] else [],
                rationale=(f["description"] or f["title"])[:400],
                remediation=_remediation_for(blob),
                evidence_refs=[ref],
                count=1,
            )
    return sorted(
        groups.values(),
        key=lambda r: (_SEV_RANK[r.severity], r.count),
        reverse=True,
    )


def _attack_narrative(findings: list[dict[str, Any]]) -> str:
    """Reconstruct a phased kill-chain story from the findings, deterministically."""
    if not findings:
        return "No findings were produced, so no attack path could be reconstructed."

    phases: list[tuple[str, list[str]]] = []
    recon = [f for f in findings if f["module"] in ("recon", "socialmatrix")]
    surface = [f for f in findings if f["module"] in ("netassault", "webbreacher",
                                                       "cloudstrike", "wirelessphantom",
                                                       "mobilehunter", "neuroprobe")]
    weakness = [f for f in findings if f["module"] in ("vulnmatrix",)]
    modeled = [f for f in findings if f["module"] in ("postxploit", "physicalvector")]

    if recon:
        phases.append(("Reconnaissance", [f"{f['target']}: {f['title']}" for f in recon[:5]]))
    if surface:
        phases.append(("Attack surface", [f"{f['target']}: {f['title']}" for f in surface[:8]]))
    if weakness:
        phases.append(("Weakness correlation", [f"{f['target']}: {f['title']}" for f in weakness[:8]]))
    if modeled:
        phases.append(("Exploitation / impact modelling",
                       [f"{f['target']}: {f['title']}" for f in modeled[:6]]))

    crown = max(findings, key=lambda f: _SEV_RANK[f["severity"]])
    parts = []
    for name, items in phases:
        parts.append(f"{name}: " + "; ".join(items) + ".")
    parts.append(
        f"Highest-impact finding: [{crown['severity']}] {crown['title']} on "
        f"{crown['target']}."
    )
    return " ".join(parts)


def _executive_summary(findings: list[dict[str, Any]], score: int,
                       counts: dict[str, int]) -> str:
    if not findings:
        return "The engagement produced no findings within the authorized scope."
    crit = counts.get("critical", 0)
    high = counts.get("high", 0)
    med = counts.get("medium", 0)
    headline = "low"
    if score >= 80 or crit:
        headline = "critical"
    elif score >= 55 or high:
        headline = "high"
    elif score >= 30 or med:
        headline = "moderate"
    return (
        f"Overall risk is {headline} (score {score}/100) across {len(findings)} "
        f"finding(s): {crit} critical, {high} high, {med} medium. "
        "Prioritise the critical/high items below; each carries a grounded "
        "remediation."
    )
