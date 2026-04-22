"""
Agente orquestador del análisis de código.

Coordina el flujo completo de análisis:
1. Clonar el repositorio vía GitHub.
2. Ejecutar analizadores estáticos (AST, secretos).
3. Preparar snippets de código para el LLM.
4. Invocar el LLM para análisis de arquitectura.
5. Consolidar y deduplicar todos los hallazgos.
6. Retornar el resultado completo para persistencia.

CodeAuditorAgent orquesta pero no implementa análisis (SRP).
Cada tipo de análisis es responsabilidad de su analizador.
"""

import asyncio
from dataclasses import dataclass, field
from pathlib import Path

from src.agents.github_client import GitHubClient
from src.agents.llm_client import LLMClient, LLMAnalysisResult
from src.analyzers.ast_analyzer import ASTAnalyzer
from src.analyzers.base import AnalysisContext, RawFinding
from src.analyzers.secret_detector import SecretDetector
from src.core.logging import get_logger
from src.db.models import FindingCategory, FindingSeverity

logger = get_logger(__name__)

_MAX_FILES_FOR_LLM = 10

_MAX_CHARS_PER_FILE = 3000

@dataclass
class AuditResult:
    """
    Resultado completo de una auditoría de código.

    Attributes:
        findings: Todos los hallazgos consolidados.
        summary: Resumen ejecutivo del análisis.
        files_analyzed: Total de archivos analizados.
        tokens_used: Tokens de OpenAI consumidos.
        static_findings_count: Hallazgos del análisis estático.
        llm_findings_count: Hallazgos del análisis LLM.
        error: Mensaje de error si el análisis falló parcialmente.
    """

    findings: list[RawFinding] = field(default_factory=list)
    summary: str = ""
    files_analyzed: int = 0
    tokens_used: int = 0
    static_findings_count: int = 0
    llm_findings_count: int = 0
    error: str | None = None


class CodeAuditorAgent:
    """
    Agente principal que orquesta el análisis completo de un repositorio.

    Combina análisis estático (AST + secretos) con análisis semántico (LLM)
    para generar un reporte comprehensivo.

    Args:
        github_client: Cliente de integración con GitHub.
        llm_client: Cliente de OpenAI para análisis semántico.
        temp_clone_dir: Directorio base para clonar repositorios.
        analysis_timeout_seconds: Timeout máximo para el análisis completo.
    """

    def __init__(
        self,
        github_client: GitHubClient,
        llm_client: LLMClient,
        temp_clone_dir: Path = Path("/tmp/code-auditor/repos"),
        analysis_timeout_seconds: int = 300,
    ) -> None:
        self._github = github_client
        self._llm = llm_client
        self._temp_dir = temp_clone_dir
        self._timeout = analysis_timeout_seconds

        self._static_analyzers = [
            ASTAnalyzer(max_function_lines=20, max_cyclomatic_complexity=10),
            SecretDetector(),
        ]

    async def run_analysis(
        self,
        repo_full_name: str,
        commit_sha: str,
    ) -> AuditResult:
        """
        Ejecuta el análisis completo del repositorio con timeout global.

        Args:
            repo_full_name: Nombre del repositorio en formato 'owner/repo'.
            commit_sha: SHA del commit a analizar.

        Returns:
            AuditResult con todos los hallazgos consolidados.
        """
        try:
            return await asyncio.wait_for(
                self._execute_analysis(repo_full_name, commit_sha),
                timeout=self._timeout,
            )
        except asyncio.TimeoutError:
            logger.error(
                "analysis_timeout",
                repo=repo_full_name,
                timeout=self._timeout,
            )
            return AuditResult(
                error=f"Análisis cancelado: superó el timeout de {self._timeout}s"
            )

    async def _execute_analysis(
        self,
        repo_full_name: str,
        commit_sha: str,
    ) -> AuditResult:
        """
        Flujo de análisis sin timeout externo.

        Args:
            repo_full_name: Nombre del repositorio.
            commit_sha: SHA del commit.

        Returns:
            AuditResult con resultados consolidados.
        """
        clone_path: Path | None = None
        result = AuditResult()

        try:
            if commit_sha == "HEAD":
                commit_sha = await self._github.resolve_commit_sha(
                    repo_full_name, "HEAD"
                )
                logger.info("commit_sha_resolved", sha=commit_sha[:8])

            self._temp_dir.mkdir(parents=True, exist_ok=True)
            clone_path = await self._github.clone_repository(
                full_name=repo_full_name,
                commit_sha=commit_sha,
                target_dir=self._temp_dir,
            )

            context = AnalysisContext(
                repo_path=clone_path,
                repo_full_name=repo_full_name,
                commit_sha=commit_sha,
            )

            static_findings, files_analyzed = await self._run_static_analyzers(context)
            result.static_findings_count = len(static_findings)
            result.files_analyzed = files_analyzed

            llm_result = await self._run_llm_analysis(clone_path, repo_full_name)
            llm_findings = self._convert_llm_findings(llm_result.findings)
            result.llm_findings_count = len(llm_findings)
            result.tokens_used = llm_result.tokens_used
            result.summary = llm_result.summary

            all_findings = static_findings + llm_findings
            result.findings = self._deduplicate_findings(all_findings)

            logger.info(
                "analysis_complete",
                repo=repo_full_name,
                total_findings=len(result.findings),
                static=result.static_findings_count,
                llm=result.llm_findings_count,
                tokens=result.tokens_used,
            )

        except Exception as exc:
            logger.error(
                "analysis_execution_error",
                repo=repo_full_name,
                error=str(exc),
            )
            result.error = str(exc)
        finally:
            if clone_path and clone_path.exists():
                self._github.cleanup_clone(clone_path)

        return result

    async def _run_static_analyzers(
        self, context: AnalysisContext
    ) -> tuple[list[RawFinding], int]:
        """
        Ejecuta todos los analizadores estáticos en paralelo.

        Args:
            context: Contexto del análisis.

        Returns:
            Tupla (lista de hallazgos, total de archivos analizados).
        """
        tasks = [analyzer.analyze(context) for analyzer in self._static_analyzers]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_findings: list[RawFinding] = []
        total_files = 0

        for i, result in enumerate(results):
            analyzer_name = self._static_analyzers[i].name
            if isinstance(result, Exception):
                logger.error(
                    "static_analyzer_error",
                    analyzer=analyzer_name,
                    error=str(result),
                )
                continue
            all_findings.extend(result.findings)
            total_files = max(total_files, result.files_analyzed)

            if result.error:
                logger.warning(
                    "static_analyzer_partial_error",
                    analyzer=analyzer_name,
                    error=result.error,
                )

        return all_findings, total_files

    async def _run_llm_analysis(
        self, clone_path: Path, repo_full_name: str
    ) -> LLMAnalysisResult:
        """
        Selecciona archivos clave y los envía al LLM para análisis semántico.

        Prioriza archivos de la carpeta src/ y excluye tests, migraciones
        y archivos de configuración sin lógica de negocio.

        Args:
            clone_path: Ruta al repositorio clonado.
            repo_full_name: Nombre del repositorio.

        Returns:
            Resultado del análisis LLM.
        """
        python_files = self._select_files_for_llm(clone_path)

        if not python_files:
            logger.info("llm_analysis_skipped_no_files")
            return LLMAnalysisResult(findings=[], summary="", tokens_used=0, model="")

        snippets: dict[str, str] = {}
        for file_path in python_files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
                relative = str(file_path.relative_to(clone_path))
                snippets[relative] = content[:_MAX_CHARS_PER_FILE]
            except OSError:
                continue

        if not snippets:
            return LLMAnalysisResult(findings=[], summary="", tokens_used=0, model="")

        try:
            return await self._llm.analyze_code_architecture(snippets, repo_full_name)
        except Exception as exc:
            logger.error("llm_analysis_error", error=str(exc))
            return LLMAnalysisResult(
                findings=[],
                summary=f"Análisis LLM no disponible: {str(exc)[:100]}",
                tokens_used=0,
                model="",
            )

    def _select_files_for_llm(self, repo_path: Path) -> list[Path]:
        """
        Selecciona los archivos más relevantes para enviar al LLM.

        Prioriza: src/ > rutas sin tests > archivos más grandes.
        Excluye: tests, migraciones, __init__.py sin contenido significativo.

        Args:
            repo_path: Ruta al repositorio clonado.

        Returns:
            Lista de hasta _MAX_FILES_FOR_LLM archivos seleccionados.
        """
        exclude_patterns = {
            "test_", "tests", "migration", "migrations",
            "__pycache__", ".git", "venv", ".venv",
        }

        candidates: list[tuple[int, Path]] = []
        for path in repo_path.rglob("*.py"):
            parts_lower = [p.lower() for p in path.parts]
            if any(
                any(excl in part for excl in exclude_patterns)
                for part in parts_lower
            ):
                continue

            try:
                size = path.stat().st_size
                candidates.append((size, path))
            except OSError:
                continue

        candidates.sort(key=lambda x: x[0], reverse=True)
        return [path for _, path in candidates[:_MAX_FILES_FOR_LLM]]

    def _convert_llm_findings(
        self, llm_findings: list[dict]
    ) -> list[RawFinding]:
        """
        Convierte los hallazgos del LLM (dicts) a objetos RawFinding.

        Args:
            llm_findings: Lista de dicts ya validados por LLMClient.

        Returns:
            Lista de RawFinding listos para persistir.
        """
        findings: list[RawFinding] = []
        for f in llm_findings:
            try:
                findings.append(RawFinding(
                    category=FindingCategory(f["category"]),
                    severity=FindingSeverity(f["severity"]),
                    title=f["title"],
                    description=f["description"],
                    file_path=f["file_path"],
                    line_start=f.get("line_start"),
                    line_end=f.get("line_end"),
                    rule_id=f.get("rule_id", "LLM-001"),
                    recommendation=f.get("recommendation", ""),
                ))
            except (KeyError, ValueError) as exc:
                logger.warning("llm_finding_conversion_error", error=str(exc))
                continue
        return findings

    @staticmethod
    def _deduplicate_findings(findings: list[RawFinding]) -> list[RawFinding]:
        """
        Deduplica hallazgos con la misma clave (file, line, rule_id).

        Mantiene el hallazgo de mayor severidad cuando hay duplicados.
        Los hallazgos del análisis estático tienen prioridad sobre LLM.

        Args:
            findings: Lista de hallazgos con posibles duplicados.

        Returns:
            Lista de hallazgos únicos.
        """
        _SEVERITY_ORDER = {
            FindingSeverity.CRITICAL: 0,
            FindingSeverity.HIGH: 1,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.LOW: 3,
            FindingSeverity.INFO: 4,
        }

        seen: dict[tuple, RawFinding] = {}
        for finding in findings:
            key = (finding.file_path, finding.line_start, finding.rule_id)
            if key not in seen:
                seen[key] = finding
            else:
                existing = seen[key]
                if _SEVERITY_ORDER[finding.severity] < _SEVERITY_ORDER[existing.severity]:
                    seen[key] = finding

        return list(seen.values())