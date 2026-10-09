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


def test_verify_skips_blank_lines(tmp_audit_path):
    log = AuditLog(tmp_audit_path)
    log.append(action="a", actor="alice")
    # Inject a blank line between entries.
    with open(tmp_audit_path, "a", encoding="utf-8") as fh:
        fh.write("\n")
    log.append(action="b", actor="alice")
    ok, count, error = log.verify()
    assert ok and count == 2 and error is None


def test_verify_detects_malformed_json_line(tmp_audit_path):
    log = AuditLog(tmp_audit_path)
    log.append(action="a", actor="alice")
    with open(tmp_audit_path, "a", encoding="utf-8") as fh:
        fh.write("{not valid json\n")
    ok, count, error = log.verify()
    assert not ok
    assert count == 2
    assert "malformed JSON" in error


def test_verify_detects_broken_prev_pointer(tmp_audit_path):
    log = AuditLog(tmp_audit_path)
    log.append(action="a", actor="alice")
    log.append(action="b", actor="alice")
    # Replace the second line's "prev" with an unrelated hash so it no
    # longer chains from the first entry, then re-sign it so the hash
    # mismatch check (tested separately above) doesn't fire first.
    import json

    lines = tmp_audit_path.read_text(encoding="utf-8").splitlines()
    second = json.loads(lines[1])
    second["prev"] = "f" * 64
    import hashlib

    entry_for_hash = {k: v for k, v in second.items() if k != "hash"}
    canonical = json.dumps(entry_for_hash, sort_keys=True, separators=(",", ":"))
    second["hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    lines[1] = json.dumps(second, sort_keys=True)
    tmp_audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, count, error = log.verify()
    assert not ok
    assert count == 2
    assert "broken prev pointer" in error


def test_last_hash_treats_blank_tail_as_genesis(tmp_audit_path):
    log = AuditLog(tmp_audit_path)
    # The file exists but has non-zero size containing only whitespace.
    tmp_audit_path.write_text("\n\n", encoding="utf-8")
    assert log._last_hash() == "0" * 64


def test_last_hash_treats_malformed_last_line_as_genesis(tmp_audit_path):
    log = AuditLog(tmp_audit_path)
    tmp_audit_path.write_text("{not valid json\n", encoding="utf-8")
    assert log._last_hash() == "0" * 64


def test_get_audit_log_with_explicit_path_bypasses_singleton(tmp_path):
    from pegase.core.audit import get_audit_log

    log1 = get_audit_log(tmp_path / "custom.log")
    log1.append(action="x", actor="y")
    log2 = get_audit_log(tmp_path / "custom.log")
    assert log1 is not log2  # a fresh AuditLog is returned each time
    assert log2.path == log1.path


def test_get_audit_log_singleton_uses_settings_path(tmp_path, monkeypatch):
    import pegase.core.audit as audit_mod
    from pegase.core import config as cfg

    monkeypatch.setenv("PEGASE_AUDIT_LOG_PATH", str(tmp_path / "singleton.log"))
    cfg.get_settings.cache_clear()  # type: ignore[attr-defined]
    monkeypatch.setattr(audit_mod, "_default", None)

    log1 = audit_mod.get_audit_log()
    log2 = audit_mod.get_audit_log()
    assert log1 is log2  # the module-level singleton is reused
    assert log1.path == tmp_path / "singleton.log"
