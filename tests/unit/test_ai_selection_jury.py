"""Tests for recon-aware module selection and the multi-model jury."""

from __future__ import annotations

import pytest

from pegase.ai.jury import Jury
from pegase.ai.providers import LLMResponse, OfflineProvider
from pegase.ai.selection import recommend_modules


def test_recommend_web_and_correlators():
    findings = [
        {"module": "netassault", "target": "10.0.0.5", "title": "Open port 80 http",
         "description": "nginx", "evidence": {"server": "nginx"}, "severity": "info"},
    ]
    recs = recommend_modules(findings, targets=["10.0.0.5"], already_run={"netassault"})
    modules = {r.module for r in recs}
    assert "webbreacher" in modules
    assert "vulnmatrix" in modules  # correlator suggested
    assert "netassault" not in modules  # already run excluded


def test_recommend_llm_endpoint_triggers_aibreacher():
    findings = [
        {"module": "webbreacher", "target": "https://api.example.com/v1/chat",
         "title": "Chat completion endpoint", "description": "assistant bot",
         "evidence": {}, "severity": "low"},
    ]
    recs = recommend_modules(findings, targets=[])
    ai_rec = [r for r in recs if r.module == "aibreacher"]
    assert ai_rec and ai_rec[0].priority == 5


def test_recommend_priority_sorted():
    findings = [
        {"module": "recon", "target": "app.example.com", "title": "web http 443 chat bot",
         "description": "cloud s3 bucket", "evidence": {}, "severity": "info"},
    ]
    recs = recommend_modules(findings, targets=[])
    priorities = [r.priority for r in recs]
    assert priorities == sorted(priorities, reverse=True)


def test_recommend_no_findings_no_recs():
    assert recommend_modules([], targets=[]) == []


@pytest.mark.asyncio
async def test_jury_offline_confidence_from_evidence():
    jury = Jury([OfflineProvider()])  # offline juror is filtered out
    critical = {
        "title": "vsftpd backdoor", "severity": "critical",
        "description": "backdoor", "evidence": {"product": "vsftpd", "version": "2.3.4"},
        "references": ["https://x"],
    }
    verdict = await jury.deliberate(critical)
    assert verdict.confirmed is True
    assert verdict.confidence >= 0.7
    assert len(verdict.votes) == 1  # only the deterministic juror


@pytest.mark.asyncio
async def test_jury_low_evidence_low_confidence():
    jury = Jury([])
    thin = {"title": "maybe something", "severity": "info", "description": "", "evidence": {}}
    verdict = await jury.deliberate(thin)
    assert verdict.confidence < 0.5


@pytest.mark.asyncio
async def test_jury_llm_juror_adds_vote():
    class ConfirmingProvider(OfflineProvider):
        name = "confirm"

        @property
        def offline(self):
            return False

        async def complete(self, *, system, prompt):
            return LLMResponse(
                '{"confirmed": true, "confidence": 0.9, "rationale": "clear"}',
                self.name, "c-1", ok=True,
            )

    jury = Jury([ConfirmingProvider()])
    verdict = await jury.deliberate(
        {"title": "high issue", "severity": "high", "description": "x", "evidence": {"a": 1}}
    )
    jurors = {v.juror for v in verdict.votes}
    assert jurors == {"deterministic", "confirm"}
    assert verdict.confirmed is True
