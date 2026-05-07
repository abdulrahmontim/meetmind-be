import uuid
import pytest
import re
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, patch, MagicMock
from uuid import uuid4

from jose import jwt
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import UserAlreadyExistsException
from app.models.user import User, ActiveSession
from app.services.auth.session_service import create_session

# ── Constants & Helpers ──────────────────────────────────────────────────────

SIGNUP_URL = "/api/v1/auth/signup"
FAKE_ACCESS = "fake.access.token"
FAKE_REFRESH = "fake.refresh.token"

CREATE_USER = "app.services.auth.AuthService.create_user"
CREATE_ACCESS = "app.services.auth.AuthService.create_access_token"
CREATE_REFRESH = "app.services.auth.AuthService.create_refresh_token"

VALID_PAYLOAD = {
    "name": "John Doe",
    "email": "john@example.com",
    "password": "SecurePass1",
}

def make_user(**kwargs) -> User:
    user = MagicMock(spec=User)
    user.id = kwargs.get("id", uuid4())
    user.email = kwargs.get("email", "john@example.com")
    user.name = kwargs.get("name", "John Doe")
    user.password_hash = kwargs.get("password_hash", "hashed")
    return user

# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
async def test_user(db: AsyncSession):
    """Create a real test user in the DB."""
    user = User(
        email="test@example.com",
        name="Test User",
        password_hash="fake_hash",
        role="member",
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user

@pytest.fixture
async def authenticated_tokens(db: AsyncSession, test_user):
    """Create a real session and return valid tokens."""
    access_token, refresh_token = await create_session(db, test_user, "127.0.0.1", "test-device")
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": test_user,
    }

# ── Test Signup (Mocked) ──────────────────────────────────────────────────────

class TestSignup:
    @pytest.mark.anyio
    async def test_signup_success(self, client):
        user = make_user()
        with patch(CREATE_USER, new_callable=AsyncMock, return_value=user), \
             patch(CREATE_ACCESS, new_callable=AsyncMock, return_value=FAKE_ACCESS), \
             patch(CREATE_REFRESH, new_callable=AsyncMock, return_value=FAKE_REFRESH):
            response = await client.post(SIGNUP_URL, json=VALID_PAYLOAD)
        
        body = response.json()
        assert response.status_code == 201
        assert body["data"]["access_token"] == FAKE_ACCESS
        assert body["data"]["email"] == "john@example.com"

    @pytest.mark.anyio
    async def test_signup_duplicate_email(self, client):
        with patch(CREATE_USER, new_callable=AsyncMock, side_effect=UserAlreadyExistsException(email="john@example.com")):
            response = await client.post(SIGNUP_URL, json=VALID_PAYLOAD)
        assert response.status_code == 400

    @pytest.mark.anyio
    async def test_signup_invalid_password_format(self, client):
        response = await client.post(SIGNUP_URL, json={**VALID_PAYLOAD, "password": "short"})
        assert response.status_code == 422

# ── Test Token Rotation ───────────────────────────────────────────────────────

class TestRefreshToken:
    async def test_refresh_token_success(self, client, authenticated_tokens):
        response = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": authenticated_tokens["refresh_token"]},
        )
        assert response.status_code == 200
        assert "access_token" in response.json()["data"]

    async def test_refresh_token_expired(self, client):
        expired_payload = {
            "sub": str(uuid.uuid4()),
            "type": "refresh",
            "exp": datetime.now(timezone.utc) - timedelta(hours=1),
        }
        token = jwt.encode(expired_payload, settings.JWT_SECRET, algorithm="HS256")
        response = await client.post("/api/v1/auth/refresh", json={"refresh_token": token})
        assert response.status_code == 401

    async def test_refresh_token_reuse_detection(self, client, db, authenticated_tokens):
        token = authenticated_tokens["refresh_token"]
        # Rotate once
        await client.post("/api/v1/auth/refresh", json={"refresh_token": token})
        # Try again with same token (reuse)
        response = await client.post("/api/v1/auth/refresh", json={"refresh_token": token})
        assert response.status_code == 401

# ── Test Logout & Identity ───────────────────────────────────────────────────

class TestAuthIdentity:
    async def test_logout_success(self, client, db, authenticated_tokens):
        response = await client.post(
            "/api/v1/auth/logout",
            json={"refresh_token": authenticated_tokens["refresh_token"]},
            headers={"Authorization": f"Bearer {authenticated_tokens['access_token']}"},
        )
        assert response.status_code == 200
        
        # Verify DB session is gone
        res = await db.execute(select(ActiveSession).where(ActiveSession.user_id == authenticated_tokens["user"].id))
        assert len(res.scalars().all()) == 0

    async def test_get_me_success(self, client, authenticated_tokens):
        response = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {authenticated_tokens['access_token']}"},
        )
        assert response.status_code == 200
        assert response.json()["data"]["email"] == "test@example.com"

    async def test_get_me_unauthorized(self, client):
        response = await client.get("/api/v1/auth/me")
        assert response.status_code == 401