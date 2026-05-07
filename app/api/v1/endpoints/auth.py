from fastapi import APIRouter, HTTPException
from app.api.deps import CurrentUser, DBSession
from app.schemas.auth import LogoutRequest, RefreshRequest
from app.services.auth.session_service import invalidate_session, rotate_tokens
from app.core.config import settings

router = APIRouter()


@router.post("/refresh")
async def refresh_token(
    body: RefreshRequest,
    db: DBSession,
) -> dict:
    try:
        access_token, new_refresh_token = await rotate_tokens(db, body.refresh_token)
    except ValueError:
        raise HTTPException(
            status_code=401,
            detail={"status_code": 401, "message": "Invalid or expired refresh token", "data": None}
        )

    return {
        "status_code": 200,
        "message": "Token refreshed successfully",
        "data": {
            "access_token": access_token,
            "refresh_token": new_refresh_token,
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        }
    }


@router.post("/logout")
async def logout(
    body: LogoutRequest,
    db: DBSession,
    current_user: CurrentUser,
) -> dict:
    await invalidate_session(db, body.refresh_token)

    return {
        "status_code": 200,
        "message": "Logged out successfully",
        "data": None
    }


@router.get("/me")
async def get_me(
    current_user: CurrentUser,
) -> dict:
    return {
        "status_code": 200,
        "message": "User retrieved successfully",
        "data": {
            "id": str(current_user.id),
            "email": current_user.email,
            "name": current_user.name,
            "role": current_user.role,
            "avatar_url": current_user.avatar_url,
            "created_at": str(current_user.created_at),
        }
    }