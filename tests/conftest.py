"""Shared pytest fixtures."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("PEGASE_SECRET_KEY", "test-secret-not-for-production")
os.environ.setdefault("PEGASE_ENVIRONMENT", "development")


@pytest.fixture()
def tmp_audit_path(tmp_path: Path) -> Path:
    return tmp_path / "audit.log"
