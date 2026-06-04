"""Hash-chained, append-only audit log.

Every line is a JSON object terminated by ``\\n``. Each entry carries:
  * ``ts``       ISO-8601 UTC timestamp,
  * ``mission``  mission UUID (or ``"system"``),
  * ``actor``    user or service principal,
  * ``action``   verb (e.g. ``mission.created``, ``module.exec``, ``scope.denied``),
  * ``target``   subject of the action (host, URL, mission id, ...),
  * ``meta``     free-form structured payload,
  * ``prev``     hex SHA-256 of the previous entry's canonical form,
  * ``hash``     hex SHA-256 of this entry's canonical form (prev + payload).

The chain lets a later auditor detect tampering even of a single byte. The
log is intentionally append-only and is never rewritten by the application;
operators rotate it externally (e.g. via ``logrotate copytruncate``-style
hand-off into immutable storage).
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_GENESIS_HASH = "0" * 64


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        if not self.path.exists():
            self.path.touch(mode=0o600)

    def append(
        self,
        *,
        action: str,
        actor: str,
        mission: str = "system",
        target: str = "",
        meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            prev = self._last_hash()
            payload: dict[str, Any] = {
                "ts": datetime.now(UTC).isoformat(),
                "mission": mission,
                "actor": actor,
                "action": action,
                "target": target,
                "meta": meta or {},
                "prev": prev,
            }
            canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            payload["hash"] = digest
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(payload, sort_keys=True) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            return payload

    def verify(self) -> tuple[bool, int, str | None]:
        """Return ``(ok, lines_checked, error)``. ``ok`` is False on tamper."""
        prev = _GENESIS_HASH
        count = 0
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                count += 1
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as exc:
                    return False, count, f"line {count}: malformed JSON ({exc})"
                claimed = entry.pop("hash", None)
                if entry.get("prev") != prev:
                    return False, count, f"line {count}: broken prev pointer"
                canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"))
                actual = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
                if actual != claimed:
                    return False, count, f"line {count}: hash mismatch"
                prev = actual
        return True, count, None

    def _last_hash(self) -> str:
        if self.path.stat().st_size == 0:
            return _GENESIS_HASH
        with open(self.path, "rb") as fh:
            # Read the last non-empty line efficiently.
            fh.seek(0, os.SEEK_END)
            end = fh.tell()
            buf = b""
            while end > 0:
                step = min(4096, end)
                end -= step
                fh.seek(end)
                buf = fh.read(step) + buf
                if b"\n" in buf.rstrip(b"\n"):
                    break
            lines = [ln for ln in buf.splitlines() if ln.strip()]
            if not lines:
                return _GENESIS_HASH
            try:
                last = json.loads(lines[-1])
            except json.JSONDecodeError:
                return _GENESIS_HASH
            return last.get("hash", _GENESIS_HASH)


_default: AuditLog | None = None


def get_audit_log(path: Path | None = None) -> AuditLog:
    """Module-level singleton. Tests can override by passing ``path``."""
    global _default
    if path is not None:
        return AuditLog(path)
    if _default is None:
        from pegase.core.config import get_settings

        _default = AuditLog(get_settings().audit_log_path)
    return _default
