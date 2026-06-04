"""Audit log integrity tests."""

from __future__ import annotations

from pegase.core.audit import AuditLog


def test_chain_grows_and_verifies(tmp_audit_path):
    log = AuditLog(tmp_audit_path)
    a = log.append(action="mission.created", actor="alice", mission="m1")
    b = log.append(action="module.started", actor="alice", mission="m1", target="recon")
    c = log.append(action="mission.finished", actor="alice", mission="m1")
    assert b["prev"] == a["hash"]
    assert c["prev"] == b["hash"]
    ok, count, error = log.verify()
    assert ok and count == 3 and error is None


def test_chain_detects_tamper(tmp_audit_path):
    log = AuditLog(tmp_audit_path)
    log.append(action="a", actor="alice")
    log.append(action="b", actor="alice")
    # Tamper with the file
    content = tmp_audit_path.read_text(encoding="utf-8").replace("alice", "mallory", 1)
    tmp_audit_path.write_text(content, encoding="utf-8")
    ok, _, error = log.verify()
    assert not ok
    assert error and "hash mismatch" in error


def test_empty_log_verifies(tmp_audit_path):
    log = AuditLog(tmp_audit_path)
    ok, count, error = log.verify()
    assert ok and count == 0 and error is None
