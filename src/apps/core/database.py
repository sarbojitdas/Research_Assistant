from sqlalchemy.ext.asyncio import (
    create_async_engine,
    AsyncSession,
    async_sessionmaker,
    AsyncEngine,
)
from sqlalchemy import text

from src.apps.core.config import settings

_engine: AsyncEngine | None = None
_async_session_local: async_sessionmaker[AsyncSession] | None = None


def _get_database_url() -> str:
    database_url = settings.DATABASE_URL
    if database_url.startswith("postgresql://"):
        database_url = database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    elif database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql+asyncpg://", 1)
    return database_url


def _get_use_ssl() -> bool:
    return settings.APP_ENV != "development"


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        use_ssl = _get_use_ssl()
        _engine = create_async_engine(
            _get_database_url(),
            echo=settings.DEBUG and settings.APP_ENV == "development",
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=10,
            connect_args={"ssl": "require"} if use_ssl else {},
        )
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _async_session_local
    if _async_session_local is None:
        _async_session_local = async_sessionmaker(
            bind=get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _async_session_local


# Backwards-compatible module-level accessors
engine = get_engine()
AsyncSessionLocal = get_session_factory()


async def test_database_connection() -> bool:
    async with get_engine().connect() as connection:
        result = await connection.execute(text("SELECT 1"))
        return result.scalar() == 1


async def get_db():
    async with get_session_factory()() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db() -> None:
    await test_database_connection()


async def dispose_db() -> None:
    global _engine, _async_session_local
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _async_session_local = None
