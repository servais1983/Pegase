"""PEGASE AI layer ("Neuro").

PEGASE's own LLM-augmented intelligence layer, wired into the platform's
existing safety model: multi-provider language models, a grounding /
anti-hallucination guardrail ("no claim without a receipt"), a findings advisor,
recon-aware module selection, and a multi-model validation jury.

Everything works fully offline via a deterministic engine, so the platform keeps
its "no demo mode" promise even without API keys.
"""

from pegase.ai.advisor import AIAdvisor, AIAnalysis, RiskItem
from pegase.ai.grounding import Claim, Grounder
from pegase.ai.jury import Jury, Verdict, Vote
from pegase.ai.providers import (
    LLMProvider,
    LLMResponse,
    available_providers,
    get_provider,
)
from pegase.ai.selection import ModuleRecommendation, recommend_modules

__all__ = [
    "AIAdvisor",
    "AIAnalysis",
    "RiskItem",
    "Claim",
    "Grounder",
    "Jury",
    "Verdict",
    "Vote",
    "LLMProvider",
    "LLMResponse",
    "available_providers",
    "get_provider",
    "ModuleRecommendation",
    "recommend_modules",
]
