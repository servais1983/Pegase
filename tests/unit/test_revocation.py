"""Tests for pegase.core.revocation: the JWT revocation (blocklist) store."""

from __future__ import annotations

from pegase.core.config import Settings
from pegase.core.revocation import RevocationStore, _MemoryStore, get_revocation_store


class _FakeRedis:
    def __init__(self, *, ping_ok=True, op_raises=False):
        self._ping_ok = ping_ok
        self._op_raises = op_raises
        self.store: dict[str, str] = {}

    def ping(self):
        if not self._ping_ok:
            raise ConnectionError("no redis here")
        return True

    def setex(self, key, ttl, value):
        if self._op_raises:
            raise ConnectionError("write failed")
        self.store[key] = value

    def exists(self, key):
        if self._op_raises:
            raise ConnectionError("read failed")
        return 1 if key in self.store else 0


# -- _MemoryStore ----------------------------------------------------------


def test_memory_store_revoke_and_check():
    store = _MemoryStore()
    assert store.is_revoked("abc") is False
    store.revoke("abc", 3600)
    assert store.is_revoked("abc") is True


def test_memory_store_expires_and_cleans_up(monkeypatch):
    store = _MemoryStore()
    store.revoke("abc", 10)
    # Fast-forward time past expiry.
    import pegase.core.revocation as rev_mod

    monkeypatch.setattr(rev_mod.time, "time", lambda: store._data["abc"] + 1)
    assert store.is_revoked("abc") is False
    assert "abc" not in store._data  # popped on expiry check


# -- RevocationStore: development (no redis attempted) ----------------------


def test_revocation_store_development_never_touches_redis(monkeypatch):
    settings = Settings(environment="development", secret_key="x")
    monkeypatch.setattr("pegase.core.revocation.get_settings", lambda: settings)
    store = RevocationStore()
    assert store._redis is None
    store.revoke("jti-1", 3600)
    assert store.is_revoked("jti-1") is True


def test_revocation_store_ignores_empty_jti():
    store = RevocationStore.__new__(RevocationStore)
    store._mem = _MemoryStore()
    store._redis = None
    store.revoke("", 3600)
    assert store.is_revoked("") is False
    assert store._mem._data == {}


# -- RevocationStore: production with redis ---------------------------------


def test_revocation_store_production_uses_redis_when_available(monkeypatch):
    settings = Settings(environment="production", secret_key="x" * 40)
    monkeypatch.setattr("pegase.core.revocation.get_settings", lambda: settings)

    fake = _FakeRedis()
    monkeypatch.setattr(
        "redis.Redis.from_url", classmethod(lambda cls, *a, **kw: fake)
    )

    store = RevocationStore()
    assert store._redis is fake

    store.revoke("jti-2", 3600)
    assert store.is_revoked("jti-2") is True
    assert "pegase:revoked:jti-2" in fake.store


def test_revocation_store_production_falls_back_when_ping_fails(monkeypatch):
    settings = Settings(environment="production", secret_key="x" * 40)
    monkeypatch.setattr("pegase.core.revocation.get_settings", lambda: settings)

    fake = _FakeRedis(ping_ok=False)
    monkeypatch.setattr(
        "redis.Redis.from_url", classmethod(lambda cls, *a, **kw: fake)
    )

    store = RevocationStore()
    assert store._redis is None
    # Still fully functional via the in-memory fallback.
    store.revoke("jti-3", 3600)
    assert store.is_revoked("jti-3") is True


def test_revocation_store_falls_back_to_memory_when_redis_ops_fail(monkeypatch):
    settings = Settings(environment="production", secret_key="x" * 40)
    monkeypatch.setattr("pegase.core.revocation.get_settings", lambda: settings)

    fake = _FakeRedis(op_raises=True)
    monkeypatch.setattr(
        "redis.Redis.from_url", classmethod(lambda cls, *a, **kw: fake)
    )

    store = RevocationStore()
    assert store._redis is fake

    # setex/exists both raise -> falls back to the in-memory store and still
    # produces a correct, if degraded, answer.
    store.revoke("jti-4", 3600)
    assert store.is_revoked("jti-4") is True
    assert fake.store == {}  # redis write never actually landed


# -- singleton ---------------------------------------------------------------


def test_get_revocation_store_is_a_singleton(monkeypatch):
    import pegase.core.revocation as rev_mod

    monkeypatch.setattr(rev_mod, "_store", None)
    a = get_revocation_store()
    b = get_revocation_store()
    assert a is b
