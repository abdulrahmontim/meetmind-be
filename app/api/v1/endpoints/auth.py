import logging
from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import CurrentUser, DBSession
from app.core.config import settings
from app.core.exceptions import UserAlreadyExistsException
from app.db.session import get_session
from app.schemas.auth import (
    ErrorResponse,
    LogoutRequest,
    RefreshRequest,
    SignupRequest,
    SignupResponse,
    SignupResponseData,
)
from app.schemas.response import APIResponse
from app.schemas.verification import (
    ResendVerificationRequest,
    VerifyEmailRequest,
)
from app.services.auth import AuthService
from app.services.auth.session_service import invalidate_session, rotate_tokens
from app.services.verification_service import VerificationService

router = APIRouter()
verification_service = VerificationService()
logger = logging.getLogger(__name__)


# ==========================================
# Signup & Session Endpoints
# ==========================================

@router.post("/signup", response_model=SignupResponse, status_code=status.HTTP_201_CREATED)
async def signup(
    request: SignupRequest,
    response: Response,
    db: AsyncSession = Depends(get_session)
) -> SignupResponse:
    """Register a new user, issue auth tokens, and attach cookies to the response."""
    try:
        user = await AuthService.create_user(request, db)
        access_token = await AuthService.create_access_token(user)
        refresh_token = await AuthService.create_refresh_token(db, user.id)

        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            secure=True,
            samesite="lax",
        )

        # Set Refresh Token Cookie
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            max_age=settings.REFRESH_TOKEN_EXPIRE_MINUTES * 60,
            secure=True,
            samesite="lax",
        )

        return SignupResponse(
            status_code=201,
            message="Account created successfully",
            data=SignupResponseData(
                id=str(user.id),
                email=user.email,
                name=user.name,
                access_token=access_token,
                refresh_token=refresh_token
            )
        )
    except UserAlreadyExistsException as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
        
    except Exception as e:
        logger.exception(f"An unexpected error occurred during signup: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")


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


# ==========================================
# Email Verification Endpoints
# ==========================================

@router.post("/verify-email")
async def verify_email(
    payload: VerifyEmailRequest,
    db: AsyncSession = Depends(get_session),
) -> APIResponse:

    user, error = await verification_service.verify_email(db, payload.token)

    if error:
        raise HTTPException(
            status_code=400,
            detail={
                "status_code": 400,
                "message": error,
                "data": None,
            },
        )

    return APIResponse(
        status_code=200,
        message="Email verified successfully",
        data={
            "id": str(user.id),
            "email": user.email,
        },
    )


@router.post("/resend-verification")
async def resend_verification(
    payload: ResendVerificationRequest,
    db: AsyncSession = Depends(get_session),
) -> APIResponse:

    success, error = await verification_service.resend_verification(
        db, payload.email
    )

    if error:
        raise HTTPException(
            status_code=400,
            detail={
                "status_code": 400,
                "message": error,
                "data": None,
            },
        )

    return APIResponse(
        status_code=200,
        message="Verification email resent",
        data=None,
    )