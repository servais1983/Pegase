"""Grounding / anti-hallucination guardrail - "no claim without a receipt".

PEGASE's core discipline is that no assertion is trusted unless it is backed by
evidence. The Grounder applies that rule to every piece of model-generated text
before it is allowed anywhere near a report: a claim
survives only if it references a real finding (by id, target or an evidence
token that actually occurred) and passes basic sanity checks (length bounds and
a speculative-language filter). Ungrounded claims are dropped, not shown.

The guardrail is deliberately deterministic and model-free so it cannot itself
hallucinate.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# Phrases that betray an ungrounded / speculative model answer. A claim that
# leans on these AND lacks a matching receipt is rejected outright.
_SPECULATIVE = re.compile(
    r"\b(i think|i believe|probably|might be|maybe|as an ai|i cannot|i'm not sure|"
    r"it seems|could potentially|i assume|hypothetically|in theory)\b",
    re.IGNORECASE,
)

_MIN_LEN = 8
_MAX_LEN = 2000
_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._:\-/]{2,}", re.IGNORECASE)


@dataclass
class Claim:
    """A single model-produced assertion together with its receipts."""

    statement: str
    evidence_refs: list[str] = field(default_factory=list)
    severity: str = "info"


class Grounder:
    """Validates claims against the finding set they must be derived from."""

    def __init__(self, findings: list[dict[str, Any]]) -> None:
        self._ids: set[str] = set()
        self._tokens: set[str] = set()
        for f in findings:
            fid = str(f.get("id", "")).lower()
            if fid:
                self._ids.add(fid)
            for key in ("target", "module", "title"):
                val = str(f.get(key, "")).lower()
                if val:
                    self._ids.add(val)
                    self._tokens.update(_tokenize(val))
            ev = f.get("evidence")
            if isinstance(ev, dict):
                self._tokens.update(_tokenize(" ".join(str(v) for v in ev.values())))

    def has_receipt(self, claim: Claim) -> bool:
        """True when at least one evidence ref matches a known finding token."""
        for ref in claim.evidence_refs:
            r = str(ref).lower().strip()
            if not r:
                continue
            if r in self._ids or r in self._tokens:
                return True
            if any(tok in self._tokens or tok in self._ids for tok in _tokenize(r)):
                return True
        return False

    def is_grounded(self, claim: Claim) -> tuple[bool, str]:
        """Return ``(ok, reason)``. ``reason`` explains a rejection."""
        stmt = claim.statement.strip()
        if not (_MIN_LEN <= len(stmt) <= _MAX_LEN):
            return False, "length-out-of-bounds"
        if not self.has_receipt(claim):
            if _SPECULATIVE.search(stmt):
                return False, "speculative-and-unreceipted"
            return False, "no-receipt"
        return True, "ok"

    def filter(self, claims: list[Claim]) -> tuple[list[Claim], list[tuple[Claim, str]]]:
        """Split claims into ``(grounded, rejected_with_reason)``."""
        grounded: list[Claim] = []
        rejected: list[tuple[Claim, str]] = []
        for c in claims:
            ok, reason = self.is_grounded(c)
            if ok:
                grounded.append(c)
            else:
                rejected.append((c, reason))
        return grounded, rejected

    def ground_text(self, text: str) -> tuple[str, list[str]]:
        """Sentence-level grounding for free-form model prose.

        Splits ``text`` into sentences and keeps only those that reference a
        known finding token. Returns ``(kept_text, dropped_sentences)`` so the
        caller can decide whether the surviving narrative is worth using.
        """
        kept: list[str] = []
        dropped: list[str] = []
        for sentence in _split_sentences(text):
            toks = _tokenize(sentence)
            if any(t in self._tokens or t in self._ids for t in toks):
                kept.append(sentence)
            else:
                dropped.append(sentence)
        return " ".join(kept).strip(), dropped


def _tokenize(text: str) -> set[str]:
    return {m.group(0).lower() for m in _TOKEN_RE.finditer(text)}


def _split_sentences(text: str) -> list[str]:
    return [s.strip() for s in re.split(r"(?<=[.!?])\s+", text.strip()) if s.strip()]
