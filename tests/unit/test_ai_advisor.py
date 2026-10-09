"""Tests for the grounded AI advisor and providers (offline path)."""

from __future__ import annotations

import pytest

from pegase.ai.advisor import AIAdvisor
from pegase.ai.providers import (
    AnthropicProvider,
    LLMResponse,
    OfflineProvider,
    OpenAIProvider,
    get_provider,
)
from pegase.core.config import Settings

FINDINGS = [
    {"id": "a", "module": "recon", "target": "example.com", "title": "DNS records collected",
     "description": "A/MX/NS", "severity": "info", "evidence": {"records": {"A": ["1.2.3.4"]}}},
    {"id": "b", "module": "netassault", "target": "10.0.0.5", "title": "vsftpd 2.3.4 backdoor",
     "description": "Backdoor CVE-2011-2523", "severity": "critical",
     "evidence": {"product": "vsftpd", "version": "2.3.4"}, "references": ["https://x"]},
    {"id": "c", "module": "webbreacher", "target": "app.example.com",
     "title": "Apache httpd 2.2 EOL", "description": "old apache", "severity": "high",
     "evidence": {"server": "Apache/2.2.15"}},
]


@pytest.mark.asyncio
async def test_advisor_offline_produces_grounded_analysis():
    analysis = await AIAdvisor(OfflineProvider()).analyze(FINDINGS)
    assert analysis.provider == "offline"
    assert analysis.llm_used is False
    assert 0 <= analysis.risk_score <= 100
    # A critical finding should drive a high score.
    assert analysis.risk_score >= 55
    titles = [r.title for r in analysis.prioritized_risks]
    assert "vsftpd 2.3.4 backdoor" in titles
    # Highest severity risk is first.
    assert analysis.prioritized_risks[0].severity == "critical"
    # Remediation KB matched the backdoor.
    assert "rebuild" in analysis.prioritized_risks[0].remediation.lower()
    # Info findings are excluded from risks.
    assert "DNS records collected" not in titles


@pytest.mark.asyncio
async def test_advisor_empty_findings():
    analysis = await AIAdvisor(OfflineProvider()).analyze([])
    assert analysis.risk_score == 0
    assert analysis.prioritized_risks == []
    assert "no findings" in analysis.executive_summary.lower()


@pytest.mark.asyncio
async def test_advisor_uses_grounded_llm_narrative(monkeypatch):
    class FakeProvider(OfflineProvider):
        name = "fake"

        @property
        def offline(self):  # behave like a live provider
            return False

        async def complete(self, *, system, prompt):
            # References a real finding target -> should survive grounding.
            return LLMResponse(
                "The host 10.0.0.5 exposes a vsftpd backdoor. app.example.com runs old Apache.",
                self.name, "fake-1", ok=True,
            )

    analysis = await AIAdvisor(FakeProvider()).analyze(FINDINGS)
    assert analysis.llm_used is True
    assert "10.0.0.5" in analysis.attack_narrative


@pytest.mark.asyncio
async def test_advisor_rejects_ungrounded_llm_narrative():
    class HallucinatingProvider(OfflineProvider):
        name = "halluc"

        @property
        def offline(self):
            return False

        async def complete(self, *, system, prompt):
            return LLMResponse(
                "There is a secret nuclear launch server at fantasy.invalid controlling everything.",
                self.name, "h-1", ok=True,
            )

    analysis = await AIAdvisor(HallucinatingProvider()).analyze(FINDINGS)
    # Hallucination dropped -> narrative falls back to the deterministic one.
    assert analysis.llm_used is False
    assert "fantasy.invalid" not in analysis.attack_narrative


def test_get_provider_defaults_offline():
    p = get_provider(Settings(ai_provider="offline"))
    assert p.offline is True


def test_get_provider_cloud_without_key_degrades_offline():
    p = get_provider(Settings(ai_provider="anthropic", ai_api_key=""))
    assert p.offline is True


def test_get_provider_cloud_with_key():
    p = get_provider(Settings(ai_provider="anthropic", ai_api_key="sk-test"))
    assert isinstance(p, AnthropicProvider)
    assert p.offline is False


def test_get_provider_openai_with_key():
    p = get_provider(Settings(ai_provider="openai", ai_api_key="sk-test"))
    assert isinstance(p, OpenAIProvider)


def test_get_provider_unknown_falls_back_offline():
    p = get_provider(Settings(ai_provider="does-not-exist"))
    assert p.offline is True


@pytest.mark.asyncio
async def test_advisor_live_provider_failed_completion_keeps_deterministic_narrative():
    class FailingProvider(OfflineProvider):
        name = "failing"

        @property
        def offline(self):
            return False

        async def complete(self, *, system, prompt):
            return LLMResponse("", self.name, "f-1", ok=False, error="rate limited")

    analysis = await AIAdvisor(FailingProvider()).analyze(FINDINGS)
    assert analysis.llm_used is False


@pytest.mark.asyncio
async def test_advisor_merges_duplicate_titles_into_one_risk():
    dup_findings = [
        {"id": "x1", "module": "netassault", "target": "10.0.0.1", "title": "Open Redis",
         "description": "no auth", "severity": "high", "evidence": {}},
        {"id": "x2", "module": "netassault", "target": "10.0.0.2", "title": "open redis",
         "description": "no auth either", "severity": "critical", "evidence": {}},
    ]
    analysis = await AIAdvisor(OfflineProvider()).analyze(dup_findings)
    assert len(analysis.prioritized_risks) == 1
    risk = analysis.prioritized_risks[0]
    assert risk.count == 2
    assert set(risk.targets) == {"10.0.0.1", "10.0.0.2"}
    assert set(risk.evidence_refs) == {"x1", "x2"}
    # Severity escalates to the higher of the two duplicate findings.
    assert risk.severity == "critical"


@pytest.mark.asyncio
async def test_advisor_narrative_includes_weakness_and_modeling_phases():
    findings = FINDINGS + [
        {"id": "v1", "module": "vulnmatrix", "target": "10.0.0.5", "title": "CVE match",
         "description": "matched known CVE", "severity": "high", "evidence": {}},
        {"id": "p1", "module": "postxploit", "target": "10.0.0.5", "title": "Attack path",
         "description": "graph built", "severity": "high", "evidence": {}},
    ]
    analysis = await AIAdvisor(OfflineProvider()).analyze(findings)
    assert "CVE match" in analysis.attack_narrative or "Weakness correlation" in analysis.attack_narrative


@pytest.mark.asyncio
async def test_advisor_moderate_headline_for_medium_severity_only():
    findings = [
        {"id": "m1", "module": "webbreacher", "target": "app.example.com",
         "title": "Missing security header", "description": "no CSP",
         "severity": "medium", "evidence": {}},
    ]
    analysis = await AIAdvisor(OfflineProvider()).analyze(findings)
    assert "moderate" in analysis.executive_summary.lower()
