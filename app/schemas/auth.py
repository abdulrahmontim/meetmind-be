from pydantic import BaseModel, Field


class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., description="Refresh token to rotate.")


class LogoutRequest(BaseModel):
    refresh_token: str = Field(..., description="Refresh token to invalidate.")


class TokenData(BaseModel):
    access_token: str
    refresh_token: str
    expires_in: int


class RefreshTokenData(BaseModel):
    access_token: str
    refresh_token: str
    expires_in: int