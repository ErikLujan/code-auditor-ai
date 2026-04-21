"""
Fixtures de pytest reutilizables para toda la suite de tests.

Provee cliente HTTP de prueba, sesión de DB en memoria,
usuarios de prueba y tokens JWT para testing de endpoints.
"""

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from main import app
from src.core.security import create_access_token, hash_password
from src.db.base import Base
from src.db.database import get_db_session
from src.db.models import Repository, User

# Engine SQLite en memoria para tests
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture(scope="function")
async def db_engine():
    """
    Crea un engine SQLite en memoria para cada test.

    Crea todas las tablas al inicio y las elimina al finalizar.

    Yields:
        AsyncEngine configurado para tests.
    """
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def db_session(db_engine):
    """
    Provee una sesión de DB limpia para cada test.

    Args:
        db_engine: Engine de test inyectado.

    Yields:
        AsyncSession activa para el test.
    """
    factory = async_sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture(scope="function")
async def client(db_session):
    """
    Cliente HTTP async que sobreescribe la dependencia de DB.

    Reemplaza get_db_session con la sesión de test para
    aislar completamente los tests de la DB real.

    Args:
        db_session: Sesión de test inyectada.

    Yields:
        AsyncClient configurado para llamar a la app.
    """
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db_session] = override_get_db

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def test_user(db_session: AsyncSession) -> User:
    """
    Crea un usuario de prueba en la DB de test.

    Args:
        db_session: Sesión de test.

    Returns:
        Usuario creado con contraseña conocida 'TestPass123'.
    """
    user = User(
        email="test@example.com",
        hashed_password=hash_password("TestPass123"),
        is_active=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def test_superuser(db_session: AsyncSession) -> User:
    """
    Crea un superusuario de prueba en la DB de test.

    Args:
        db_session: Sesión de test.

    Returns:
        Usuario superusuario creado.
    """
    user = User(
        email="admin@example.com",
        hashed_password=hash_password("AdminPass123"),
        is_active=True,
        is_superuser=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest.fixture
def auth_headers(test_user: User) -> dict[str, str]:
    """
    Genera headers de autenticación JWT para el usuario de test.

    Args:
        test_user: Usuario de prueba.

    Returns:
        Dict con header Authorization Bearer listo para usar.
    """
    token = create_access_token(subject=test_user.id)
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def test_repository(db_session: AsyncSession, test_user: User) -> Repository:
    """
    Crea un repositorio de prueba asociado al usuario de test.

    Args:
        db_session: Sesión de test.
        test_user: Usuario propietario.

    Returns:
        Repositorio creado.
    """
    repo = Repository(
        owner_id=test_user.id,
        github_url="https://github.com/testowner/testrepo",
        full_name="testowner/testrepo",
        default_branch="main",
    )
    db_session.add(repo)
    await db_session.commit()
    await db_session.refresh(repo)
    return repo