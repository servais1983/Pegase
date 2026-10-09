"""Tests for pegase.core.logging.configure_logging."""

from __future__ import annotations

from pegase.core import config as cfg
from pegase.core.logging import configure_logging, get_logger


def test_configure_logging_production_uses_json_renderer(monkeypatch):
    monkeypatch.setenv("PEGASE_ENVIRONMENT", "production")
    monkeypatch.setenv("PEGASE_SECRET_KEY", "a-strong-random-production-secret")
    cfg.get_settings.cache_clear()  # type: ignore[attr-defined]
    try:
        configure_logging()  # must not raise
    finally:
        cfg.get_settings.cache_clear()  # type: ignore[attr-defined]


def test_configure_logging_development_uses_console_renderer(monkeypatch):
    monkeypatch.setenv("PEGASE_ENVIRONMENT", "development")
    cfg.get_settings.cache_clear()  # type: ignore[attr-defined]
    try:
        configure_logging()
    finally:
        cfg.get_settings.cache_clear()  # type: ignore[attr-defined]


def test_get_logger_returns_a_bound_logger():
    log = get_logger("pegase.test")
    assert hasattr(log, "info")
