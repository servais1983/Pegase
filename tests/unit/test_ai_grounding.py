"""Tests for the anti-hallucination grounding guardrail."""

from __future__ import annotations

from pegase.ai.grounding import Claim, Grounder

FINDINGS = [
    {
        "id": "f1",
        "module": "netassault",
        "target": "10.0.0.5",
        "title": "Open port 22 (OpenSSH 7.2)",
        "description": "SSH service exposed",
        "evidence": {"product": "OpenSSH", "version": "7.2", "port": 22},
    },
    {
        "id": "f2",
        "module": "webbreacher",
        "target": "app.example.com",
        "title": "Missing security headers",
        "description": "No CSP",
        "evidence": {"server": "nginx/1.14"},
    },
]


def test_claim_with_real_receipt_is_grounded():
    g = Grounder(FINDINGS)
    claim = Claim("OpenSSH 7.2 on 10.0.0.5 is outdated", evidence_refs=["10.0.0.5"], severity="high")
    ok, reason = g.is_grounded(claim)
    assert ok, reason


def test_claim_without_receipt_is_rejected():
    g = Grounder(FINDINGS)
    claim = Claim("The database at db.internal is exposed", evidence_refs=["db.internal"])
    ok, reason = g.is_grounded(claim)
    assert not ok
    assert reason == "no-receipt"


def test_speculative_unreceipted_claim_rejected():
    g = Grounder(FINDINGS)
    claim = Claim("I think there might be an RCE somewhere", evidence_refs=["nowhere"])
    ok, reason = g.is_grounded(claim)
    assert not ok
    assert reason == "speculative-and-unreceipted"


def test_too_short_claim_rejected():
    g = Grounder(FINDINGS)
    ok, reason = g.is_grounded(Claim("nope", evidence_refs=["10.0.0.5"]))
    assert not ok
    assert reason == "length-out-of-bounds"


def test_filter_splits_grounded_and_rejected():
    g = Grounder(FINDINGS)
    claims = [
        Claim("nginx on app.example.com lacks headers", evidence_refs=["app.example.com"]),
        Claim("Invented finding about mars.example", evidence_refs=["mars.example"]),
    ]
    grounded, rejected = g.filter(claims)
    assert len(grounded) == 1
    assert len(rejected) == 1


def test_ground_text_keeps_only_referenced_sentences():
    g = Grounder(FINDINGS)
    text = (
        "The host 10.0.0.5 runs OpenSSH. There is definitely a hidden admin panel. "
        "app.example.com is missing headers."
    )
    kept, dropped = g.ground_text(text)
    assert "10.0.0.5" in kept
    assert "app.example.com" in kept
    assert any("hidden admin panel" in d for d in dropped)


def test_has_receipt_skips_empty_ref():
    g = Grounder(FINDINGS)
    claim = Claim(
        "OpenSSH 7.2 on 10.0.0.5 is outdated",
        evidence_refs=["", "10.0.0.5"],
        severity="high",
    )
    ok, _reason = g.is_grounded(claim)
    assert ok


def test_has_receipt_matches_via_tokenized_compound_ref():
    # A dedicated finding set whose evidence value is itself multi-word, so
    # it tokenizes into separate tokens ("nginx", "server") rather than one
    # compound token the way "nginx/1.14" would.
    findings = [
        {
            "id": "g1", "module": "webbreacher", "target": "app.example.com",
            "title": "Server banner", "description": "banner grab",
            "evidence": {"banner": "nginx server"},
        }
    ]
    g = Grounder(findings)
    # The ref itself ("about nginx config") is never a single known token -
    # only tokenizing it and matching "nginx" individually succeeds.
    claim = Claim(
        "nginx is running on app.example.com",
        evidence_refs=["about nginx config"],
    )
    assert g.has_receipt(claim) is True
