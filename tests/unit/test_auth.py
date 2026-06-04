"""JWT and password hashing tests."""

from __future__ import annotations

import pytest

from pegase.core.auth import (
    create_access_token,
    decode_token,
    hash_password,
    verify_password,
)


def test_password_roundtrip():
    h = hash_password("Sup3r-secret-passphrase!")
    assert verify_password("Sup3r-secret-passphrase!", h)
    assert not verify_password("wrong", h)


def test_jwt_roundtrip():
    tok = create_access_token("user-123", role="admin")
    decoded = decode_token(tok)
    assert decoded["sub"] == "user-123"
    assert decoded["role"] == "admin"


def test_jwt_invalid_token():
    with pytest.raises(ValueError):
        decode_token("not.a.token")
