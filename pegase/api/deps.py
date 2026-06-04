"""FastAPI dependencies."""

from __future__ import annotations

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pegase.core.auth import decode_token
from pegase.core.revocation import get_revocation_store
from pegase.db.models import User
from pegase.db.session import get_session

oauth2 = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token", auto_error=True)


async def current_user(
    token: str = Depends(oauth2),
    db: AsyncSession = Depends(get_session),
) -> User:
    try:
        payload = decode_token(token)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    if payload.get("type") not in (None, "access"):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "refresh token cannot be used here"
        )
    if get_revocation_store().is_revoked(payload.get("jti", "")):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "token revoked")
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing subject")
    user = await db.scalar(select(User).where(User.id == user_id))
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user not found")
    return user


def require_role(*roles: str):
    async def checker(user: User = Depends(current_user)) -> User:
        if user.role not in roles and user.role != "admin":
            raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient role")
        return user

    return checker
