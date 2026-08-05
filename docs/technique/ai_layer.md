# AI layer

PEGASE's AI layer (`pegase/ai/`) is an LLM-augmented intelligence layer wired
into the platform's existing safety model. It is **offline-first**: the default
provider is fully deterministic and makes no network calls, so every capability
below works — and is tested in CI — with **zero API keys**. Configuring an LLM
provider only *enriches* the output; it never becomes a dependency.

## Design principles

1. **No claim without a receipt.** Every model-generated sentence is validated
   against the finding set it must derive from. Anything that cannot be tied
   back to a real finding is dropped before it reaches a report.
2. **Deterministic core, optional LLM.** The advisor, selection, and jury all
   produce useful output from a deterministic engine. LLM output is layered on
   top and always passes the guardrail first.
3. **Never take the platform down.** A misconfigured provider, a missing key, or
   a failing API silently degrades to the offline engine.
4. **Same safety envelope.** AI endpoints operate over already-collected,
   scope-guarded findings; the red-team module (`aibreacher`) is authorization-
   gated like every other module.

## Components

| Component | File | What it does |
|-----------|------|--------------|
| Providers | `providers.py` | One async `complete()` interface over `offline` / `anthropic` / `openai` / `ollama`. Cloud providers use the existing `httpx` dep (no SDK required). |
| Grounder | `grounding.py` | Anti-hallucination guardrail. Sentence- and claim-level validation against finding ids / targets / evidence tokens, plus length bounds and a speculative-language filter. |
| AIAdvisor | `advisor.py` | Risk score (0-100), prioritized & de-duplicated risks with remediation, attack-chain narrative, executive summary. |
| Selection | `selection.py` | Recon-aware `recommend_modules()` — what to run next, with a reason and priority. |
| Jury | `jury.py` | Multi-model finding validation. A deterministic, evidence-only juror is always on the panel. |

## Configuration

```bash
PEGASE_AI_PROVIDER=offline     # offline | anthropic | openai | ollama
PEGASE_AI_MODEL=               # provider default when empty
PEGASE_AI_API_KEY=             # required for cloud providers
PEGASE_AI_BASE_URL=            # self-hosted / gateway / ollama override
PEGASE_AI_JURY_ENABLED=false   # multi-model finding validation
```

## CLI

```bash
pegase ai providers                 # available providers + active config
pegase ai advise report.json        # grounded analysis of a report
pegase ai recommend report.json     # recon-aware next-module suggestions
pegase scan ... --ai                # inline advisor after a scan
```

## API

| Endpoint | Purpose |
|----------|---------|
| `GET /api/v1/ai/providers` | Available providers + effective config |
| `GET /api/v1/ai/missions/{id}/advise` | Grounded advisor analysis |
| `GET /api/v1/ai/missions/{id}/recommend` | Recon-aware module recommendations |
| `GET /api/v1/ai/missions/{id}/jury` | Per-finding confidence verdicts |
| `GET /api/v1/reports/{id}.json?ai=true` | Report with embedded advisor section |
| `GET /api/v1/reports/{id}.html?ai=true` | HTML report with advisor section |

## AIBreacher (AI/LLM red-teaming)

`aibreacher` is an **active** module that checks an in-scope chat/LLM HTTP
endpoint against the OWASP Top 10 for LLM Applications, using **benign,
non-destructive detection** only:

* **LLM01 Prompt injection** — plants a random canary token and observes whether
  the endpoint reflects it (following an injected instruction). Never attempts
  to produce harmful content.
* **LLM06 System-prompt disclosure** — checks whether the endpoint reveals its
  hidden instructions when asked.

Findings record the probe and whether it triggered — **redacted receipts**,
never the sensitive body of the model's response. Every request passes the
`ScopeGuard`.

```bash
pegase scan --target https://app.example.com/chat \
  --scenario llm-redteam --authorization ROE-x --allow-active
```

Module parameters (via mission `parameters.aibreacher`):

| key | default | meaning |
|-----|---------|---------|
| `endpoints` | mission targets | endpoints to probe |
| `input_field` | `message` | JSON key carrying the user message |
| `template` | `{}` | request body template; `{PROMPT}` is replaced with the probe |
| `response_path` | whole body | dotted path to the model's reply text |
| `method` | `POST` | HTTP method |
| `headers` | `{}` | extra request headers (e.g. auth) |
