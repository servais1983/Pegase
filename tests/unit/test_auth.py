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


def test_password_longer_than_bcrypt_limit_is_prehashed():
    # bcrypt caps input at 72 bytes; passwords longer than that must still
    # round-trip correctly via the SHA-256 pre-hash.
    long_password = "x" * 200
    h = hash_password(long_password)
    assert verify_password(long_password, h)
    assert not verify_password("y" * 200, h)


def test_verify_password_handles_malformed_hash_gracefully():
    # bcrypt.checkpw raises ValueError on a hash that isn't valid bcrypt
    # output; verify_password must return False, not propagate.
    assert verify_password("anything", "not-a-real-bcrypt-hash") is False
