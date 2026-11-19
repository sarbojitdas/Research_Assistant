import os
from typing import AsyncGenerator

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.apps.core.database import (
    get_engine,
    get_session_factory,
    init_db,
    dispose_db,
)
from src.apps.db.models.user_model import User
from src.apps.db.models.password_reset_otp_model import PasswordResetOTP
from src.apps.db.models.refresh_token_model import RefreshToken
from src.apps.db.base import Base

os.environ.setdefault("APP_ENV", "testing")


@pytest.fixture
async def setup_database() -> AsyncGenerator[None, None]:
    await dispose_db()
    get_engine()
    get_session_factory()
    await init_db()
    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
async def db_session(
    setup_database: None,
) -> AsyncGenerator[AsyncSession, None]:
    async with get_session_factory()() as session:
        yield session
        await session.rollback()


@pytest.fixture
async def client(
    setup_database: None,
) -> AsyncGenerator[AsyncClient, None]:
    from src.apps.api.main import create_app

    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
async def test_user(db_session: AsyncSession) -> User:
    from src.apps.core.security import hash_password

    user = User(
        full_name="Test User",
        email="test@example.com",
        password_hash=hash_password("TestPassword123"),
        is_active=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest.fixture
def mock_email(monkeypatch: pytest.MonkeyPatch) -> None:
    async def mock_send(to_email: str, otp: str) -> None:
        pass

    monkeypatch.setattr(
        "src.apps.services.email_service.send_password_reset_otp",
        mock_send,
    )
