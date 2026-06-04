"""Auth routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pegase.api.deps import current_user, oauth2, require_role
from pegase.api.schemas import (
    RefreshRequest,
    TokenResponse,
    UserCreate,
    UserOut,
)
from pegase.core.auth import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from pegase.core.config import get_settings
from pegase.core.revocation import get_revocation_store
from pegase.db.models import User
from pegase.db.session import get_session

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/token", response_model=TokenResponse)
async def token(
    request: Request,  # noqa: ARG001 - injected so SlowAPIMiddleware sees the route
    form: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_session),
) -> TokenResponse:
    user = await db.scalar(select(User).where(User.username == form.username))
    if not user or not verify_password(form.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
    if not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "user disabled")
    settings = get_settings()
    tok = create_access_token(user.id, role=user.role)
    refresh = create_refresh_token(user.id, role=user.role)
    return TokenResponse(
        access_token=tok,
        refresh_token=refresh,
        expires_in=settings.jwt_expire_minutes * 60,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    payload: RefreshRequest,
    db: AsyncSession = Depends(get_session),
) -> TokenResponse:
    try:
        claims = decode_token(payload.refresh_token)
    except ValueError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc
    if claims.get("type") != "refresh":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not a refresh token")
    store = get_revocation_store()
    if store.is_revoked(claims.get("jti", "")):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "refresh token revoked")
    user = await db.scalar(select(User).where(User.id == claims.get("sub")))
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user not found")
    settings = get_settings()
    access = create_access_token(user.id, role=user.role)
    return TokenResponse(
        access_token=access, expires_in=settings.jwt_expire_minutes * 60
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def logout(
    token: str = Depends(oauth2),
    user: User = Depends(current_user),
):
    """Revoke the presented access token (best-effort, until natural expiry)."""
    from datetime import UTC, datetime

    claims = decode_token(token)
    jti = claims.get("jti", "")
    exp = claims.get("exp")
    ttl = 3600
    if exp:
        ttl = max(int(exp - datetime.now(UTC).timestamp()), 1)
    get_revocation_store().revoke(jti, ttl)
    return None


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: UserCreate,
    _: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_session),
) -> User:
    existing = await db.scalar(
        select(User).where(
            (User.username == payload.username) | (User.email == payload.email)
        )
    )
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT, "user already exists")
    user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    await db.flush()
    return user


@router.get("/me", response_model=UserOut)
async def me(user: User = Depends(current_user)) -> User:
    return user
