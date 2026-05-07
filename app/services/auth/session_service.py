import uuid
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from jose import jwt, JWTError
from app.core.config import settings
from app.models.user import ActiveSession, User
from datetime import datetime, timedelta, timezone


def create_access_token(user_id: uuid.UUID, role: str | None) -> str:
    payload = {
        "sub": str(user_id),
        "role": role or "member",
        "type": "access",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm="HS256")


def create_refresh_token(user_id: uuid.UUID, session_id: uuid.UUID) -> str:
    payload = {
        "sub": str(user_id),
        "session_id": str(session_id),
        "type": "refresh",
        "exp": datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm="HS256")


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise ValueError("Token expired")
    except JWTError:
        raise ValueError("Invalid token")


async def create_session(
    db: AsyncSession,
    user: User,
    ip_address: str | None = None,
    device_hint: str | None = None,
) -> tuple[str, str]:
    """Called by signin/signup after verifying credentials."""
    session = ActiveSession(
        user_id=user.id,
        ip_address=ip_address,
        device_hint=device_hint,
        last_seen_at=datetime.now(timezone.utc),
    )
    db.add(session)
    await db.flush()

    access_token = create_access_token(user.id, user.role)
    refresh_token = create_refresh_token(user.id, session.id)

    await db.commit()
    return access_token, refresh_token


async def rotate_tokens(
    db: AsyncSession,
    refresh_token: str,
) -> tuple[str, str]:
    """Validate refresh token, detect reuse, issue new token pair."""
    try:
        payload = decode_token(refresh_token)
    except ValueError as e:
        raise ValueError(str(e))

    if payload.get("type") != "refresh":
        raise ValueError("Invalid token type")

    session_id = uuid.UUID(payload["session_id"])
    user_id = uuid.UUID(payload["sub"])

    result = await db.execute(
        select(ActiveSession).where(
            ActiveSession.id == session_id,
            ActiveSession.user_id == user_id,
        )
    )
    session = result.scalar_one_or_none()

    if not session:
        await db.execute(
            delete(ActiveSession).where(ActiveSession.user_id == user_id)
        )
        await db.commit()
        raise ValueError("Token reuse detected — all sessions invalidated")

    user_result = await db.execute(select(User).where(User.id == user_id))
    user = user_result.scalar_one_or_none()

    if not user:
        raise ValueError("User not found")

    session.last_seen_at = datetime.now(timezone.utc)
    await db.commit()

    new_access = create_access_token(user.id, user.role)
    new_refresh = create_refresh_token(user.id, session_id)

    return new_access, new_refresh


async def invalidate_session(
    db: AsyncSession,
    refresh_token: str,
) -> None:
    """Delete the session row — logout."""
    try:
        payload = decode_token(refresh_token)
    except ValueError:
        return

    if payload.get("type") != "refresh":
        return

    session_id = uuid.UUID(payload["session_id"])

    result = await db.execute(
        select(ActiveSession).where(ActiveSession.id == session_id)
    )
    session = result.scalar_one_or_none()

    if session:
        await db.delete(session)
        await db.commit()