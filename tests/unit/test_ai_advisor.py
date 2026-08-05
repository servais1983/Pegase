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
