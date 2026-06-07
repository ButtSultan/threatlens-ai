"""
Authentication endpoints: register, login, refresh token, logout.
"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_current_user
from app.core.security import (
    create_access_token, create_refresh_token,
    decode_token, get_password_hash, verify_password
)
from app.db.session import get_db
from app.models.models import AuditLog, User, UserRole
from app.schemas.schemas import (
    LoginRequest, RefreshRequest, TokenResponse,
    UserCreate, UserResponse
)

router = APIRouter()
logger = logging.getLogger(__name__)

# Module-level limiter for auth endpoints
_limiter = Limiter(key_func=get_remote_address)


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    user_data: UserCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Register a new user account."""
    # Check for existing username
    result = await db.execute(select(User).where(User.username == user_data.username))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username already registered")

    # Check for existing email
    result = await db.execute(select(User).where(User.email == user_data.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    # Create user
    user = User(
        username=user_data.username,
        email=user_data.email,
        full_name=user_data.full_name,
        hashed_password=get_password_hash(user_data.password),
        role=user_data.role,
        is_active=True,
        is_verified=True,
    )
    db.add(user)
    await db.flush()

    # Audit log
    audit = AuditLog(
        user_id=user.id,
        action="user_register",
        resource_type="user",
        resource_id=str(user.id),
        ip_address=request.client.host if request.client else None,
        success=True,
    )
    db.add(audit)
    await db.commit()
    await db.refresh(user)

    logger.info("New user registered", extra={"username": user.username, "role": user.role})
    return user


@router.post("/login", response_model=TokenResponse)
@_limiter.limit("10/minute")
async def login(
    credentials: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Authenticate user and return JWT tokens."""
    result = await db.execute(select(User).where(User.username == credentials.username))
    user = result.scalar_one_or_none()

    # Audit failed login
    if not user or not verify_password(credentials.password, user.hashed_password):
        audit = AuditLog(
            action="login_failed",
            details={"username": credentials.username},
            ip_address=request.client.host if request.client else None,
            success=False,
        )
        db.add(audit)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")

    # Update last login
    user.last_login = datetime.now(timezone.utc)

    # Audit successful login
    audit = AuditLog(
        user_id=user.id,
        action="login_success",
        ip_address=request.client.host if request.client else None,
        success=True,
    )
    db.add(audit)
    await db.commit()
    await db.refresh(user)

    token_data = {"sub": str(user.id), "username": user.username, "role": user.role.value}
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    logger.info("User logged in", extra={"username": user.username})
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=1800,
        user=user,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    data: RefreshRequest,
    db: AsyncSession = Depends(get_db),
):
    """Refresh access token using a valid refresh token."""
    payload = decode_token(data.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    from uuid import UUID
    result = await db.execute(select(User).where(User.id == str(payload["sub"])))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    token_data = {"sub": str(user.id), "username": user.username, "role": user.role.value}
    return TokenResponse(
        access_token=create_access_token(token_data),
        refresh_token=create_refresh_token(token_data),
        expires_in=1800,
        user=user,
    )


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    """Get the currently authenticated user's profile."""
    return current_user
