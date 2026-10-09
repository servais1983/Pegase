"""Tests for pegase.core.config.get_settings' production safety check."""

from __future__ import annotations

import pytest

from pegase.core import config as cfg


def test_get_settings_rejects_default_secret_in_production(monkeypatch):
    monkeypatch.setenv("PEGASE_ENVIRONMENT", "production")
    monkeypatch.delenv("PEGASE_SECRET_KEY", raising=False)
    cfg.get_settings.cache_clear()  # type: ignore[attr-defined]
    try:
        with pytest.raises(RuntimeError, match="PEGASE_SECRET_KEY"):
            cfg.get_settings()
    finally:
        cfg.get_settings.cache_clear()  # type: ignore[attr-defined]


def test_get_settings_accepts_strong_secret_in_production(monkeypatch):
    monkeypatch.setenv("PEGASE_ENVIRONMENT", "production")
    monkeypatch.setenv("PEGASE_SECRET_KEY", "a-strong-random-production-secret")
    cfg.get_settings.cache_clear()  # type: ignore[attr-defined]
    try:
        settings = cfg.get_settings()
        assert settings.is_production is True
    finally:
        cfg.get_settings.cache_clear()  # type: ignore[attr-defined]
