"""
Modelos ORM de la aplicación.

Define las entidades principales del dominio:
- User: Usuarios autenticados del sistema.
- Repository: Repositorios GitHub registrados para análisis.
- Analysis: Ejecuciones de análisis sobre un repositorio.
- Finding: Hallazgo individual dentro de un análisis.
"""

from datetime import datetime
from enum import StrEnum

from sqlalchemy import Boolean, Float, ForeignKey, Integer, String, Text
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


# ── Enums ─────────────────────────────────────────────────────────────────────

class AnalysisStatus(StrEnum):
    """Estado del ciclo de vida de un análisis."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


class FindingSeverity(StrEnum):
    """Severidad de un hallazgo de análisis."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(StrEnum):
    """Categoría del hallazgo según tipo de análisis."""

    SECURITY = "security"
    ARCHITECTURE = "architecture"
    QUALITY = "quality"
    IMPROVEMENT = "improvement"


# ── Modelos ───────────────────────────────────────────────────────────────────

class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """
    Usuario autenticado del sistema.

    Attributes:
        email: Email único del usuario (usado como login).
        hashed_password: Hash bcrypt de la contraseña.
        is_active: Indica si la cuenta está habilitada.
        is_superuser: Indica si tiene permisos de administrador.
        repositories: Repos registrados por este usuario.
    """

    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    repositories: Mapped[list["Repository"]] = relationship(
        "Repository", back_populates="owner", cascade="all, delete-orphan"
    )


class Repository(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """
    Repositorio GitHub registrado para auditoría.

    Attributes:
        owner_id: FK al usuario propietario.
        github_url: URL canónica del repositorio en GitHub.
        full_name: Nombre completo en formato owner/repo.
        default_branch: Rama principal del repositorio.
        is_active: Indica si el repo está habilitado para análisis.
        owner: Relación al usuario propietario.
        analyses: Análisis ejecutados sobre este repositorio.
    """

    __tablename__ = "repositories"

    owner_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    github_url: Mapped[str] = mapped_column(String(500), nullable=False, unique=True)
    full_name: Mapped[str] = mapped_column(String(200), nullable=False)
    default_branch: Mapped[str] = mapped_column(String(100), default="main", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    owner: Mapped["User"] = relationship("User", back_populates="repositories")
    analyses: Mapped[list["Analysis"]] = relationship(
        "Analysis", back_populates="repository", cascade="all, delete-orphan"
    )


class Analysis(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """
    Ejecución de análisis sobre un repositorio en un commit específico.

    Attributes:
        repository_id: FK al repositorio analizado.
        commit_sha: SHA del commit analizado (40 chars).
        status: Estado actual del análisis.
        triggered_by: Origen del análisis ('manual' o 'webhook').
        started_at: Timestamp de inicio del análisis.
        completed_at: Timestamp de finalización.
        duration_seconds: Duración total en segundos.
        total_findings: Cantidad total de hallazgos.
        critical_count: Hallazgos de severidad crítica.
        high_count: Hallazgos de severidad alta.
        error_message: Mensaje de error si el análisis falló.
        repository: Relación al repositorio.
        findings: Hallazgos generados por este análisis.
    """

    __tablename__ = "analyses"

    repository_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False, index=True
    )
    commit_sha: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[AnalysisStatus] = mapped_column(
        SAEnum(AnalysisStatus), default=AnalysisStatus.PENDING, nullable=False, index=True
    )
    triggered_by: Mapped[str] = mapped_column(String(50), default="manual", nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    total_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    critical_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    high_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    repository: Mapped["Repository"] = relationship("Repository", back_populates="analyses")
    findings: Mapped[list["Finding"]] = relationship(
        "Finding", back_populates="analysis", cascade="all, delete-orphan"
    )


class Finding(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """
    Hallazgo individual detectado durante un análisis.

    Attributes:
        analysis_id: FK al análisis padre.
        category: Categoría del hallazgo (security, architecture, etc).
        severity: Nivel de severidad del hallazgo.
        title: Título corto descriptivo.
        description: Descripción detallada del problema.
        file_path: Ruta relativa del archivo afectado.
        line_start: Línea de inicio del problema (opcional).
        line_end: Línea de fin del problema (opcional).
        rule_id: Identificador de la regla que generó el hallazgo.
        recommendation: Acción sugerida para resolver el problema.
        is_false_positive: Marcado manualmente como falso positivo.
        analysis: Relación al análisis padre.
    """

    __tablename__ = "findings"

    analysis_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False, index=True
    )
    category: Mapped[FindingCategory] = mapped_column(SAEnum(FindingCategory), nullable=False, index=True)
    severity: Mapped[FindingSeverity] = mapped_column(SAEnum(FindingSeverity), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    line_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    line_end: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    analysis: Mapped["Analysis"] = relationship("Analysis", back_populates="findings")