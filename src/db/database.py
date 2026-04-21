"""
Configuración del engine de base de datos y sesión async.

Provee el engine SQLAlchemy async, la fábrica de sesiones
y un dependency de FastAPI para inyección en endpoints.
"""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from src.core.config import get_settings
from src.core.exceptions import DatabaseError
from src.core.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()


def build_engine() -> AsyncEngine:
    """
    Construye el engine async de SQLAlchemy con el pool configurado.

    Returns:
        AsyncEngine listo para operar.
    """
    return create_async_engine(
        str(settings.database.database_url),
        pool_size=settings.database.database_pool_size,
        max_overflow=settings.database.database_max_overflow,
        echo=settings.database.database_echo,
        pool_pre_ping=True,
        connect_args={"statement_cache_size": 0}
    )


engine: AsyncEngine = build_engine()

AsyncSessionFactory: async_sessionmaker[AsyncSession] = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency de FastAPI que provee una sesión de base de datos.

    Maneja commit/rollback automáticamente y cierra la sesión
    al finalizar cada request.

    Yields:
        AsyncSession activa para la request.

    Raises:
        DatabaseError: Si ocurre un error durante la transacción.
    """
    async with AsyncSessionFactory() as session:
        try:
            yield session
            await session.commit()
        except Exception as exc:
            await session.rollback()
            logger.error("db_session_error", error=str(exc))
            raise DatabaseError(f"Error en transacción: {exc}") from exc
        finally:
            await session.close()