from typing import Annotated

from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_session
from app.models.user import User
from app.services.auth.session_service import decode_token

DBSession = Annotated[AsyncSession, Depends(get_session)]

security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_session),
) -> User:
    token = credentials.credentials

    try:
        payload = decode_token(token)
    except ValueError:
        raise HTTPException(
            status_code=401,
            detail={"status_code": 401, "message": "Authentication required", "data": None}
        )

    if payload.get("type") != "access":
        raise HTTPException(
            status_code=401,
            detail={"status_code": 401, "message": "Authentication required", "data": None}
        )

    user_id = payload["sub"]
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=401,
            detail={"status_code": 401, "message": "Authentication required", "data": None}
        )

    return user


CurrentUser = Annotated[User, Depends(get_current_user)]