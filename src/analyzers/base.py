"""
Interfaces y estructuras de datos base para el sistema de análisis.

Define los contratos que todos los analizadores deben cumplir (ISP, DIP),
y los dataclasses que representan los resultados del análisis.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from src.db.models import FindingCategory, FindingSeverity


@dataclass
class RawFinding:
    """
    Hallazgo crudo antes de persistir en base de datos.

    Attributes:
        category: Categoría del hallazgo (security, architecture, etc).
        severity: Nivel de severidad del hallazgo.
        title: Título corto descriptivo.
        description: Descripción detallada del problema.
        file_path: Ruta relativa del archivo afectado.
        line_start: Línea de inicio del problema.
        line_end: Línea de fin del problema.
        rule_id: Identificador de la regla que lo generó.
        recommendation: Acción sugerida para resolver el problema.
    """

    category: FindingCategory
    severity: FindingSeverity
    title: str
    description: str
    file_path: str
    line_start: int | None = None
    line_end: int | None = None
    rule_id: str | None = None
    recommendation: str = ""


@dataclass
class AnalysisContext:
    """
    Contexto de entrada para un análisis.

    Attributes:
        repo_path: Ruta local al repositorio clonado.
        repo_full_name: Nombre completo del repositorio (owner/repo).
        commit_sha: SHA del commit analizado.
        target_files: Lista de archivos a analizar (vacío = todos).
    """

    repo_path: Path
    repo_full_name: str
    commit_sha: str
    target_files: list[Path] = field(default_factory=list)


@dataclass
class AnalyzerResult:
    """
    Resultado de un analizador individual.

    Attributes:
        findings: Hallazgos detectados.
        analyzer_name: Nombre del analizador que generó el resultado.
        files_analyzed: Cantidad de archivos procesados.
        error: Error si el analizador falló parcialmente.
    """

    findings: list[RawFinding]
    analyzer_name: str
    files_analyzed: int = 0
    error: str | None = None


class BaseAnalyzer(ABC):
    """
    Contrato base para todos los analizadores del sistema.

    Cada analizador recibe un AnalysisContext y retorna un AnalyzerResult.
    Cumple Open/Closed: se extiende creando nuevas subclases sin modificar esta.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Nombre identificador del analizador."""
        ...

    @abstractmethod
    async def analyze(self, context: AnalysisContext) -> AnalyzerResult:
        """
        Ejecuta el análisis sobre el contexto dado.

        Args:
            context: Contexto con ruta del repo y metadata.

        Returns:
            Resultado con hallazgos y estadísticas.
        """
        ...

    def _make_finding(
        self,
        *,
        category: FindingCategory,
        severity: FindingSeverity,
        title: str,
        description: str,
        file_path: str,
        line_start: int | None = None,
        line_end: int | None = None,
        rule_id: str | None = None,
        recommendation: str = "",
    ) -> RawFinding:
        """
        Factory method para crear hallazgos de forma consistente.

        Centraliza la creación de RawFinding para evitar duplicación (DRY).
        """
        return RawFinding(
            category=category,
            severity=severity,
            title=title,
            description=description,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            rule_id=rule_id,
            recommendation=recommendation,
        )