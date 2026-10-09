"""Tests for pegase.db.session's engine-kwargs branching."""

from __future__ import annotations

from sqlalchemy.pool import StaticPool

from pegase.db.session import _engine_kwargs


def test_engine_kwargs_sqlite_uses_static_pool():
    kw = _engine_kwargs("sqlite+aiosqlite:///:memory:")
    assert kw["poolclass"] is StaticPool
    assert kw["connect_args"] == {"check_same_thread": False}


def test_engine_kwargs_non_sqlite_uses_pool_pre_ping():
    kw = _engine_kwargs("postgresql+asyncpg://user:pass@localhost/db")
    assert kw == {"pool_pre_ping": True, "future": True}
