"""Authentication helpers - password hashing and JWT issuance."""

from __future__ import annotations

# bcrypt has a 72-byte input cap. We pre-hash long passwords with SHA-256 so
# the user-facing password length is unbounded but the data fed to bcrypt is
# always 60 hex chars.
import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

import bcrypt
from jose import JWTError, jwt

from pegase.core.config import get_settings

_BCRYPT_LIMIT = 72


def _prep(password: str) -> bytes:
    raw = password.encode("utf-8")
    if len(raw) > _BCRYPT_LIMIT:
        raw = hashlib.sha256(raw).hexdigest().encode("ascii")
    return raw


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_prep(password), bcrypt.gensalt()).decode("ascii")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(_prep(password), hashed.encode("ascii"))
    except ValueError:
        return False


def _new_jti() -> str:
    import uuid

    return uuid.uuid4().hex


def create_access_token(
    subject: str,
    *,
    role: str = "operator",
    expires_minutes: int | None = None,
    extra: dict[str, Any] | None = None,
) -> str:
    settings = get_settings()
    expire = datetime.now(UTC) + timedelta(
        minutes=expires_minutes or settings.jwt_expire_minutes
    )
    payload: dict[str, Any] = {
        "sub": subject,
        "role": role,
        "type": "access",
        "jti": _new_jti(),
        "exp": expire,
        "iat": datetime.now(UTC),
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def create_refresh_token(
    subject: str,
    *,
    role: str = "operator",
    expires_days: int | None = None,
) -> str:
    settings = get_settings()
    days = expires_days or settings.refresh_token_expire_days
    expire = datetime.now(UTC) + timedelta(days=days)
    payload: dict[str, Any] = {
        "sub": subject,
        "role": role,
        "type": "refresh",
        "jti": _new_jti(),
        "exp": expire,
        "iat": datetime.now(UTC),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict[str, Any]:
    settings = get_settings()
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
    except JWTError as exc:
        raise ValueError(f"invalid token: {exc}") from exc
