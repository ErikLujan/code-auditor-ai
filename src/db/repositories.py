"""
Repositorios de acceso a datos.

Implementa el patrón Repository para abstraer las operaciones
de base de datos del resto de la aplicación. Cada clase maneja
las queries de una entidad específica (SRP).
"""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.exceptions import AnalysisNotFoundError, DatabaseError
from src.core.logging import get_logger
from src.db.models import Analysis, AnalysisStatus, Finding, Repository, User

logger = get_logger(__name__)


class UserRepository:
    """
    Repositorio de operaciones de base de datos para User.

    Args:
        session: Sesión async de SQLAlchemy inyectada.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(self, user_id: str) -> User | None:
        """
        Busca un usuario por su ID.

        Args:
            user_id: UUID del usuario.

        Returns:
            User si existe, None si no.
        """
        result = await self._session.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()

    async def get_by_email(self, email: str) -> User | None:
        """
        Busca un usuario por su email.

        Args:
            email: Email del usuario.

        Returns:
            User si existe, None si no.
        """
        result = await self._session.execute(select(User).where(User.email == email))
        return result.scalar_one_or_none()

    async def create(self, email: str, hashed_password: str) -> User:
        """
        Crea un nuevo usuario en base de datos.

        Args:
            email: Email único del usuario.
            hashed_password: Hash bcrypt de la contraseña.

        Returns:
            Usuario creado con ID asignado.

        Raises:
            DatabaseError: Si el email ya existe.
        """
        user = User(email=email, hashed_password=hashed_password)
        self._session.add(user)
        try:
            await self._session.flush()
        except Exception as exc:
            logger.error("user_create_error", email=email, error=str(exc))
            raise DatabaseError(f"Error al crear usuario: {exc}") from exc
        logger.info("user_created", user_id=user.id)
        return user

    async def exists_by_email(self, email: str) -> bool:
        """
        Verifica si existe un usuario con el email dado.

        Args:
            email: Email a verificar.

        Returns:
            True si existe, False si no.
        """
        result = await self._session.execute(
            select(User.id).where(User.email == email)
        )
        return result.scalar_one_or_none() is not None


class RepositoryRepository:
    """
    Repositorio de operaciones de base de datos para Repository.

    Args:
        session: Sesión async de SQLAlchemy inyectada.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(self, repo_id: str) -> Repository | None:
        """
        Busca un repositorio por su ID.

        Args:
            repo_id: UUID del repositorio.

        Returns:
            Repository si existe, None si no.
        """
        result = await self._session.execute(
            select(Repository).where(Repository.id == repo_id)
        )
        return result.scalar_one_or_none()

    async def get_by_url(self, github_url: str) -> Repository | None:
        """
        Busca un repositorio por su URL de GitHub.

        Args:
            github_url: URL canónica del repositorio.

        Returns:
            Repository si existe, None si no.
        """
        result = await self._session.execute(
            select(Repository).where(Repository.github_url == github_url)
        )
        return result.scalar_one_or_none()

    async def list_by_owner(self, owner_id: str) -> list[Repository]:
        """
        Lista todos los repositorios de un usuario.

        Args:
            owner_id: UUID del usuario propietario.

        Returns:
            Lista de repositorios ordenados por fecha de creación.
        """
        result = await self._session.execute(
            select(Repository)
            .where(Repository.owner_id == owner_id, Repository.is_active == True)
            .order_by(Repository.created_at.desc())
        )
        return list(result.scalars().all())

    async def create(self, owner_id: str, github_url: str, full_name: str) -> Repository:
        """
        Registra un nuevo repositorio para un usuario.

        Args:
            owner_id: UUID del usuario propietario.
            github_url: URL validada del repositorio GitHub.
            full_name: Nombre completo en formato owner/repo.

        Returns:
            Repository creado.

        Raises:
            DatabaseError: Si ocurre un error al persistir.
        """
        repo = Repository(owner_id=owner_id, github_url=github_url, full_name=full_name)
        self._session.add(repo)
        try:
            await self._session.flush()
        except Exception as exc:
            logger.error("repository_create_error", url=github_url, error=str(exc))
            raise DatabaseError(f"Error al registrar repositorio: {exc}") from exc
        logger.info("repository_created", repo_id=repo.id, full_name=full_name)
        return repo


class AnalysisRepository:
    """
    Repositorio de operaciones de base de datos para Analysis.

    Args:
        session: Sesión async de SQLAlchemy inyectada.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(self, analysis_id: str) -> Analysis:
        """
        Busca un análisis por su ID.

        Args:
            analysis_id: UUID del análisis.

        Returns:
            Analysis encontrado.

        Raises:
            AnalysisNotFoundError: Si el análisis no existe.
        """
        result = await self._session.execute(
            select(Analysis).where(Analysis.id == analysis_id)
        )
        analysis = result.scalar_one_or_none()
        if not analysis:
            raise AnalysisNotFoundError(analysis_id)
        return analysis

    async def list_by_repository(
        self, repository_id: str, limit: int = 20, offset: int = 0
    ) -> list[Analysis]:
        """
        Lista análisis de un repositorio con paginación.

        Args:
            repository_id: UUID del repositorio.
            limit: Cantidad máxima de resultados (default 20).
            offset: Desplazamiento para paginación (default 0).

        Returns:
            Lista de análisis ordenados por fecha descendente.
        """
        result = await self._session.execute(
            select(Analysis)
            .where(Analysis.repository_id == repository_id)
            .order_by(Analysis.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(result.scalars().all())

    async def create(self, repository_id: str, commit_sha: str, triggered_by: str = "manual") -> Analysis:
        """
        Crea un nuevo análisis en estado PENDING.

        Args:
            repository_id: UUID del repositorio a analizar.
            commit_sha: SHA del commit a analizar.
            triggered_by: Origen del análisis ('manual' o 'webhook').

        Returns:
            Analysis creado en estado PENDING.
        """
        analysis = Analysis(
            repository_id=repository_id,
            commit_sha=commit_sha,
            triggered_by=triggered_by,
            status=AnalysisStatus.PENDING,
        )
        self._session.add(analysis)
        await self._session.flush()
        logger.info("analysis_created", analysis_id=analysis.id, commit=commit_sha)
        return analysis

    async def update_status(
        self,
        analysis_id: str,
        status: AnalysisStatus,
        error_message: str | None = None,
    ) -> Analysis:
        """
        Actualiza el estado de un análisis.

        Args:
            analysis_id: UUID del análisis a actualizar.
            status: Nuevo estado del análisis.
            error_message: Mensaje de error (solo para status FAILED/TIMEOUT).

        Returns:
            Analysis actualizado.

        Raises:
            AnalysisNotFoundError: Si el análisis no existe.
        """
        analysis = await self.get_by_id(analysis_id)
        analysis.status = status
        if error_message:
            analysis.error_message = error_message
        await self._session.flush()
        logger.info("analysis_status_updated", analysis_id=analysis_id, status=status)
        return analysis


class FindingRepository:
    """
    Repositorio de operaciones de base de datos para Finding.

    Args:
        session: Sesión async de SQLAlchemy inyectada.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def bulk_create(self, findings: list[Finding]) -> list[Finding]:
        """
        Persiste múltiples hallazgos en una sola operación.

        Args:
            findings: Lista de instancias Finding a persistir.

        Returns:
            Lista de findings persistidos con IDs asignados.

        Raises:
            DatabaseError: Si ocurre un error al persistir.
        """
        self._session.add_all(findings)
        try:
            await self._session.flush()
        except Exception as exc:
            logger.error("findings_bulk_create_error", count=len(findings), error=str(exc))
            raise DatabaseError(f"Error al persistir hallazgos: {exc}") from exc
        logger.info("findings_created", count=len(findings))
        return findings

    async def list_by_analysis(self, analysis_id: str) -> list[Finding]:
        """
        Lista todos los hallazgos de un análisis ordenados por severidad.

        Args:
            analysis_id: UUID del análisis padre.

        Returns:
            Lista de hallazgos ordenados por severidad descendente.
        """
        result = await self._session.execute(
            select(Finding)
            .where(Finding.analysis_id == analysis_id, Finding.is_false_positive == False)
            .order_by(Finding.severity)
        )
        return list(result.scalars().all())