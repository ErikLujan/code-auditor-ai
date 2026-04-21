"""
Schemas Pydantic para repositorios y análisis de código.

Define los contratos de entrada/salida para los endpoints
de gestión de repositorios y ejecución de análisis.
"""

from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from src.core.security import validate_github_url
from src.db.models import AnalysisStatus, FindingCategory, FindingSeverity


# ── Repository Schemas ────────────────────────────────────────────────────────

class RepositoryRegisterRequest(BaseModel):
    """
    Payload para registrar un repositorio GitHub.

    Attributes:
        github_url: URL pública del repositorio a auditar.
    """

    github_url: str = Field(min_length=10, max_length=500)

    @field_validator("github_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        """
        Valida que la URL sea un repositorio GitHub legítimo.

        Args:
            v: URL a validar.

        Returns:
            URL validada y normalizada.

        Raises:
            ValueError: Si la URL no cumple el patrón GitHub esperado.
        """
        try:
            return validate_github_url(v)
        except Exception as exc:
            raise ValueError(str(exc)) from exc


class RepositoryResponse(BaseModel):
    """
    Representación pública de un repositorio registrado.

    Attributes:
        id: UUID del repositorio.
        github_url: URL del repositorio en GitHub.
        full_name: Nombre completo en formato owner/repo.
        default_branch: Rama principal del repositorio.
        is_active: Estado del registro.
        created_at: Fecha de registro.
    """

    id: str
    github_url: str
    full_name: str
    default_branch: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Analysis Schemas ──────────────────────────────────────────────────────────

class AnalysisCreateRequest(BaseModel):
    """
    Payload para iniciar un análisis manual.

    Attributes:
        repository_id: UUID del repositorio a analizar.
        commit_sha: SHA del commit a analizar (opcional, usa HEAD si no se provee).
    """

    repository_id: str = Field(min_length=36, max_length=36)
    commit_sha: str | None = Field(default=None, min_length=7, max_length=40)

    @field_validator("commit_sha")
    @classmethod
    def validate_commit_sha(cls, v: str | None) -> str | None:
        """
        Valida que el SHA del commit sea hexadecimal válido.

        Args:
            v: SHA a validar o None.

        Returns:
            SHA validado o None.

        Raises:
            ValueError: Si el SHA contiene caracteres no hexadecimales.
        """
        if v is not None and not all(c in "0123456789abcdefABCDEF" for c in v):
            raise ValueError("commit_sha debe ser un hash hexadecimal válido")
        return v


class FindingResponse(BaseModel):
    """
    Representación de un hallazgo individual de análisis.

    Attributes:
        id: UUID del hallazgo.
        category: Categoría del hallazgo.
        severity: Nivel de severidad.
        title: Título descriptivo.
        description: Descripción detallada del problema.
        file_path: Ruta relativa del archivo afectado.
        line_start: Línea de inicio (opcional).
        line_end: Línea de fin (opcional).
        rule_id: Identificador de la regla que lo detectó.
        recommendation: Acción sugerida para resolverlo.
        is_false_positive: Marcado como falso positivo.
    """

    id: str
    category: FindingCategory
    severity: FindingSeverity
    title: str
    description: str
    file_path: str
    line_start: int | None
    line_end: int | None
    rule_id: str | None
    recommendation: str
    is_false_positive: bool

    model_config = {"from_attributes": True}


class AnalysisResponse(BaseModel):
    """
    Representación de un análisis de código.

    Attributes:
        id: UUID del análisis.
        repository_id: UUID del repositorio analizado.
        commit_sha: SHA del commit analizado.
        status: Estado actual del análisis.
        triggered_by: Origen del análisis.
        started_at: Timestamp de inicio.
        completed_at: Timestamp de finalización.
        duration_seconds: Duración total en segundos.
        total_findings: Total de hallazgos.
        critical_count: Hallazgos críticos.
        high_count: Hallazgos de severidad alta.
        error_message: Mensaje de error si falló.
        created_at: Fecha de creación.
    """

    id: str
    repository_id: str
    commit_sha: str
    status: AnalysisStatus
    triggered_by: str
    started_at: datetime | None
    completed_at: datetime | None
    duration_seconds: float | None
    total_findings: int
    critical_count: int
    high_count: int
    error_message: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class AnalysisDetailResponse(AnalysisResponse):
    """
    Análisis con sus hallazgos completos incluidos.

    Extiende AnalysisResponse agregando la lista de findings.

    Attributes:
        findings: Lista completa de hallazgos del análisis.
    """

    findings: list[FindingResponse] = []


# ── Paginación ────────────────────────────────────────────────────────────────

class PaginatedResponse(BaseModel):
    """
    Wrapper genérico para respuestas paginadas.

    Attributes:
        items: Lista de items de la página actual.
        total: Total de items en todas las páginas.
        page: Número de página actual (base 1).
        page_size: Cantidad de items por página.
        pages: Total de páginas.
    """

    items: list
    total: int
    page: int
    page_size: int
    pages: int