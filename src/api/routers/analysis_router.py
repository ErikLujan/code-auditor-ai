"""
Endpoints de gestión de repositorios y análisis de código.

Todos los endpoints requieren autenticación JWT.
Los usuarios solo pueden acceder a sus propios repositorios y análisis.
"""

import math

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import get_settings
from src.api.deps import PaginationParams, get_current_user, RateLimiter
from src.api.schemas.analysis_schemas import (
    AnalysisCreateRequest,
    AnalysisDetailResponse,
    AnalysisResponse,
    FindingResponse,
    PaginatedResponse,
    RepositoryRegisterRequest,
    RepositoryResponse,
)
from src.core.exceptions import AnalysisNotFoundError, DatabaseError
from src.core.logging import get_logger
from src.db.database import get_db_session
from src.db.models import User
from src.db.repositories import AnalysisRepository, FindingRepository, RepositoryRepository
from src.services.analysis_service import AnalysisService, build_auditor_agent

logger = get_logger(__name__)
settings = get_settings()

repos_router = APIRouter(prefix="/repositories", tags=["Repositorios"])
analysis_router = APIRouter(prefix="/analyses", tags=["Análisis"])


# ── Repositorios ──────────────────────────────────────────────────────────────

@repos_router.post(
    "",
    response_model=RepositoryResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Registrar repositorio",
    dependencies=[Depends(RateLimiter(requests=10, window_seconds=60))]
)
async def register_repository(
    payload: RepositoryRegisterRequest,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> RepositoryResponse:
    """
    Registra un repositorio GitHub para auditoría.

    La URL es validada contra el patrón de GitHub antes de persistir.
    """
    repo_db = RepositoryRepository(session)

    existing = await repo_db.get_by_url(payload.github_url)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="El repositorio ya está registrado",
        )

    full_name = "/".join(payload.github_url.rstrip("/").split("/")[-2:])

    try:
        repository = await repo_db.create(
            owner_id=current_user.id,
            github_url=payload.github_url,
            full_name=full_name,
        )
    except DatabaseError as exc:
        logger.error("repository_register_error", url=payload.github_url, error=exc.message)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al registrar el repositorio",
        ) from exc

    return RepositoryResponse.model_validate(repository)


@repos_router.get(
    "",
    response_model=PaginatedResponse,
    summary="Listar repositorios del usuario",
    dependencies=[Depends(RateLimiter(requests=60, window_seconds=60))]
)
async def list_repositories(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
    pagination: PaginationParams = Depends(),
) -> PaginatedResponse:
    """Lista todos los repositorios registrados por el usuario autenticado."""
    repo_db = RepositoryRepository(session)
    repositories = await repo_db.list_by_owner(current_user.id)

    items = repositories[pagination.offset: pagination.offset + pagination.page_size]
    total = len(repositories)

    return PaginatedResponse(
        items=[RepositoryResponse.model_validate(r) for r in items],
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        pages=math.ceil(total / pagination.page_size) if total else 1,
    )


@repos_router.get(
    "/{repository_id}",
    response_model=RepositoryResponse,
    summary="Obtener repositorio por ID",
    dependencies=[Depends(RateLimiter(requests=60, window_seconds=60))]
)
async def get_repository(
    repository_id: str,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> RepositoryResponse:
    """Obtiene un repositorio por su ID. Verifica que pertenezca al usuario autenticado."""
    repo_db = RepositoryRepository(session)
    repository = await repo_db.get_by_id(repository_id)

    if not repository or repository.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repositorio no encontrado",
        )

    return RepositoryResponse.model_validate(repository)


# ── Análisis ──────────────────────────────────────────────────────────────────

@analysis_router.post(
    "",
    response_model=AnalysisResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Iniciar análisis",
    dependencies=[Depends(RateLimiter(
        requests=settings.rate_limit.rate_limit_requests_per_minute, 
        window_seconds=60
    ))]
)
async def create_analysis(
    payload: AnalysisCreateRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> AnalysisResponse:
    """
    Inicia un análisis de código sobre un repositorio registrado.

    El análisis se crea en estado PENDING y se ejecuta en background.
    Usar GET /analyses/{id} para consultar el resultado.
    """
    repo_db = RepositoryRepository(session)
    repository = await repo_db.get_by_id(payload.repository_id)

    if not repository or repository.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repositorio no encontrado",
        )

    analysis_db = AnalysisRepository(session)
    analysis = await analysis_db.create(
        repository_id=payload.repository_id,
        commit_sha=payload.commit_sha or "HEAD",
    )

    await session.commit()

    background_tasks.add_task(
        run_analysis_background,
        analysis_id=analysis.id,
        repo_full_name=repository.full_name,
        commit_sha=analysis.commit_sha,
    )

    logger.info(
        "analysis_queued",
        analysis_id=analysis.id,
        repo=repository.full_name,
    )
    return AnalysisResponse.model_validate(analysis)


@analysis_router.get(
    "/{analysis_id}",
    response_model=AnalysisDetailResponse,
    summary="Obtener análisis con hallazgos",
    dependencies=[Depends(RateLimiter(requests=60, window_seconds=60))]
)
async def get_analysis(
    analysis_id: str,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> AnalysisDetailResponse:
    """Obtiene un análisis con todos sus hallazgos."""
    try:
        analysis_db = AnalysisRepository(session)
        analysis = await analysis_db.get_by_id(analysis_id)
    except AnalysisNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.message) from exc

    repo_db = RepositoryRepository(session)
    repository = await repo_db.get_by_id(analysis.repository_id)
    if not repository or repository.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Análisis no encontrado")

    finding_db = FindingRepository(session)
    findings = await finding_db.list_by_analysis(analysis_id)

    analysis_response = AnalysisResponse.model_validate(analysis)
    return AnalysisDetailResponse(
        **analysis_response.model_dump(),
        findings=[FindingResponse.model_validate(f) for f in findings],
    )


@analysis_router.get(
    "",
    response_model=PaginatedResponse,
    summary="Listar análisis de un repositorio",
    dependencies=[Depends(RateLimiter(requests=60, window_seconds=60))]
)
async def list_analyses(
    repository_id: str,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
    pagination: PaginationParams = Depends(),
) -> PaginatedResponse:
    """Lista los análisis de un repositorio con paginación."""
    repo_db = RepositoryRepository(session)
    repository = await repo_db.get_by_id(repository_id)

    if not repository or repository.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repositorio no encontrado",
        )

    analysis_db = AnalysisRepository(session)
    analyses = await analysis_db.list_by_repository(
        repository_id,
        limit=pagination.page_size,
        offset=pagination.offset,
    )

    return PaginatedResponse(
        items=[AnalysisResponse.model_validate(a) for a in analyses],
        total=len(analyses),
        page=pagination.page,
        page_size=pagination.page_size,
        pages=math.ceil(len(analyses) / pagination.page_size) if analyses else 1,
    )


# ── Background task ───────────────────────────────────────────────────────────

async def run_analysis_background(
    analysis_id: str,
    repo_full_name: str,
    commit_sha: str,
) -> None:
    """
    Ejecuta el análisis en background con su propia sesión de BD.

    Función pública (sin underscore) para que los tests puedan
    parchearla con patch() sin romper el ciclo de vida del request.

    Args:
        analysis_id: UUID del análisis a ejecutar.
        repo_full_name: Nombre del repositorio.
        commit_sha: SHA del commit a analizar.
    """
    from src.db.database import AsyncSessionFactory

    logger.info(
        "background_analysis_start",
        analysis_id=analysis_id,
        repo=repo_full_name,
    )

    async with AsyncSessionFactory() as session:
        agent = build_auditor_agent()
        service = AnalysisService(session=session, agent=agent)
        await service.execute_analysis(
            analysis_id=analysis_id,
            repo_full_name=repo_full_name,
            commit_sha=commit_sha,
        )