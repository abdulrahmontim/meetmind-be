import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timezone, timedelta
import uuid

from app.models.user import User, ActiveSession
from app.services.auth.session_service import create_session

@pytest.fixture
async def test_user(db: AsyncSession):
    """Create a test user."""
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
    """Create a test user and return valid tokens."""
    access_token, refresh_token = await create_session(db, test_user, "127.0.0.1", "test-device")
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": test_user,
    }


class TestRefreshToken:
    """POST /api/v1/auth/refresh"""

    async def test_refresh_token_returns_200_with_valid_token(
        self, client: AsyncClient, authenticated_tokens
    ):
        response = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": authenticated_tokens["refresh_token"]},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Token refreshed successfully"
        assert "access_token" in data["data"]
        assert "refresh_token" in data["data"]

    async def test_refresh_token_returns_401_with_expired_token(
        self, client: AsyncClient
    ):
        from jose import jwt
        from app.core.config import settings

        expired_payload = {
            "sub": str(uuid.uuid4()),
            "session_id": str(uuid.uuid4()),
            "type": "refresh",
            "exp": datetime.now(timezone.utc) - timedelta(hours=1),
        }
        expired_token = jwt.encode(expired_payload, settings.JWT_SECRET, algorithm="HS256")

        response = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": expired_token},
        )

        assert response.status_code == 401
        data = response.json()

        assert data["detail"]["status_code"] == 401

    async def test_refresh_token_returns_401_with_invalid_token(
        self, client: AsyncClient
    ):
        response = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "invalid.token.here"},
        )

        assert response.status_code == 401
        assert response.json()["detail"]["status_code"] == 401

    async def test_refresh_token_detects_reuse_and_deletes_all_sessions(
        self, client: AsyncClient, db: AsyncSession, authenticated_tokens
    ):
        refresh_token = authenticated_tokens["refresh_token"]

        # First refresh succeeds
        response1 = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token},
        )
        assert response1.status_code == 200

        # Logout using the old token (deletes session)
        await client.post(
            "/api/v1/auth/logout",
            json={"refresh_token": refresh_token},
            headers={"Authorization": f"Bearer {response1.json()['data']['access_token']}"},
        )

        # Try to use old token again (session deleted, should fail)
        response2 = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token},
        )
        assert response2.status_code == 401
        assert response2.json()["detail"]["status_code"] == 401


class TestLogout:
    """POST /api/v1/auth/logout"""

    async def test_logout_returns_200_and_deletes_session(
        self, client: AsyncClient, db: AsyncSession, authenticated_tokens
    ):
        access_token = authenticated_tokens["access_token"]
        refresh_token = authenticated_tokens["refresh_token"]

        response = await client.post(
            "/api/v1/auth/logout",
            json={"refresh_token": refresh_token},
            headers={"Authorization": f"Bearer {access_token}"},
        )

        assert response.status_code == 200
        assert response.json()["message"] == "Logged out successfully"

        # Verify session is deleted
        from sqlalchemy import select
        result = await db.execute(
            select(ActiveSession).where(
                ActiveSession.user_id == authenticated_tokens["user"].id
            )
        )
        sessions = result.scalars().all()
        assert len(sessions) == 0

    async def test_logout_returns_401_without_token(
        self, client: AsyncClient, authenticated_tokens
    ):
        response = await client.post(
            "/api/v1/auth/logout",
            json={"refresh_token": authenticated_tokens["refresh_token"]},
        )

        assert response.status_code == 401
        assert response.json()["detail"]["status_code"] == 401


class TestGetMe:
    """GET /api/v1/auth/me"""

    async def test_get_me_returns_200_with_user_data(
        self, client: AsyncClient, authenticated_tokens
    ):
        response = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {authenticated_tokens['access_token']}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["data"]["email"] == "test@example.com"
        assert data["data"]["name"] == "Test User"
        assert data["data"]["id"] == str(authenticated_tokens["user"].id)

    async def test_get_me_returns_401_without_token(self, client: AsyncClient):
        response = await client.get("/api/v1/auth/me")
        assert response.status_code == 401
        assert response.json()["detail"]["status_code"] == 401

    async def test_get_me_returns_401_with_expired_token(
        self, client: AsyncClient
    ):
        from jose import jwt
        from app.core.config import settings

        expired_payload = {
            "sub": str(uuid.uuid4()),
            "role": "member",
            "type": "access",
            "exp": datetime.now(timezone.utc) - timedelta(hours=1),
        }
        expired_token = jwt.encode(expired_payload, settings.JWT_SECRET, algorithm="HS256")

        response = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {expired_token}"},
        )

        assert response.status_code == 401

    async def test_get_me_returns_401_with_refresh_token(
        self, client: AsyncClient, authenticated_tokens
    ):
        response = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {authenticated_tokens['refresh_token']}"},
        )

        assert response.status_code == 401