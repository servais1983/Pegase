"""JWT revocation (blocklist) store.

A revoked token's ``jti`` is stored until its natural expiry so a stolen or
logged-out token can be rejected before it would otherwise expire. Backed by
Redis in production (shared across API replicas); falls back to an in-process
set when Redis is unavailable (single-process / tests).
"""

from __future__ import annotations

import time

from pegase.core.config import get_settings
from pegase.core.logging import get_logger

log = get_logger(__name__)

_KEY_PREFIX = "pegase:revoked:"


class _MemoryStore:
    def __init__(self) -> None:
        self._data: dict[str, float] = {}

    def revoke(self, jti: str, ttl_seconds: int) -> None:
        self._data[jti] = time.time() + max(ttl_seconds, 1)

    def is_revoked(self, jti: str) -> bool:
        exp = self._data.get(jti)
        if exp is None:
            return False
        if exp < time.time():
            self._data.pop(jti, None)
            return False
        return True


class RevocationStore:
    def __init__(self) -> None:
        self._mem = _MemoryStore()
        self._redis = None
        settings = get_settings()
        if settings.is_production:
            try:
                import redis

                self._redis = redis.Redis.from_url(
                    settings.redis_url, decode_responses=True
                )
                self._redis.ping()
            except Exception as exc:  # noqa: BLE001
                log.warning("revocation_redis_unavailable", error=str(exc))
                self._redis = None

    def revoke(self, jti: str, ttl_seconds: int) -> None:
        if not jti:
            return
        if self._redis is not None:
            try:
                self._redis.setex(_KEY_PREFIX + jti, max(ttl_seconds, 1), "1")
                return
            except Exception as exc:  # noqa: BLE001
                log.warning("revocation_redis_write_failed", error=str(exc))
        self._mem.revoke(jti, ttl_seconds)

    def is_revoked(self, jti: str) -> bool:
        if not jti:
            return False
        if self._redis is not None:
            try:
                return self._redis.exists(_KEY_PREFIX + jti) == 1
            except Exception as exc:  # noqa: BLE001
                log.warning("revocation_redis_read_failed", error=str(exc))
        return self._mem.is_revoked(jti)


_store: RevocationStore | None = None


def get_revocation_store() -> RevocationStore:
    global _store
    if _store is None:
        _store = RevocationStore()
    return _store
