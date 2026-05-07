import os
import asyncio
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.models.base import Base
from app.core.config import settings
from app.db.session import get_session

# Identify if we should use the real Postgres DB or fall back to SQLite
# We check the scheme of the TEST_DATABASE_URL defined in your settings
USE_POSTGRES = "postgresql" in str(settings.TEST_DATABASE_URL)

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    try:
        loop = asyncio.get_event_loop_policy().get_event_loop()
    except RuntimeError:
        loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="session")
async def engine():
    """
    Hybrid Engine: Uses Postgres if configured, otherwise SQLite + StaticPool.
    """
    if USE_POSTGRES:
        # Your implementation: Real Postgres testing
        database_url = str(settings.TEST_DATABASE_URL)
        engine = create_async_engine(database_url, echo=False)
    else:
        # Dev branch implementation: Fast In-Memory SQLite
        database_url = "sqlite+aiosqlite://"
        engine = create_async_engine(
            database_url,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )

    async with engine.begin() as conn:
        # Ensure all models (user, session, etc.) are imported so Base sees them
        from app.models import user, base  # Add other models as needed
        await conn.run_sync(Base.metadata.create_all)

    yield engine
    await engine.dispose()

@pytest.fixture
async def db(engine):
    """
    Provides a functional database session. 
    Rolls back after each test to keep the DB clean without dropping tables.
    """
    async_session = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    async with async_session() as session:
        yield session
        await session.rollback()

@pytest.fixture
async def client(db: AsyncSession):
    """
    Test client that overrides the FastAPI session dependency 
    to share the transaction with the 'db' fixture.
    """
    async def _override_get_session():
        yield db

    # Apply override
    app.dependency_overrides[get_session] = _override_get_session
    
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    
    # Clean up to prevent side effects in other tests
    app.dependency_overrides.clear()