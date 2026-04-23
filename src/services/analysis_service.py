"""
Capa de servicio para análisis de código.

Responsabilidades:
- Orquestar el flujo de análisis desde el endpoint hasta la persistencia.
- Gestionar el ciclo de vida del análisis (PENDING → RUNNING → COMPLETED/FAILED).
- Persistir los findings generados por CodeAuditorAgent.
- Actualizar métricas del análisis (counts, duración).

AnalysisService conecta el router (HTTP) con el agente (lógica de negocio).
No contiene lógica de análisis — solo coordinación (SRP).
"""

import time
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.code_auditor_agent import AuditResult, CodeAuditorAgent
from src.agents.github_client import GitHubClient
from src.agents.llm_client import LLMClient
from src.api.schemas.analysis_schemas import AnalysisDetailResponse, FindingResponse
from src.core.config import get_settings
from src.core.cache import set_cached_analysis
from src.core.logging import get_logger
from src.db.models import Analysis, AnalysisStatus, Finding
from src.db.repositories import AnalysisRepository, FindingRepository

logger = get_logger(__name__)


def build_auditor_agent() -> CodeAuditorAgent:
    """
    Factory que construye el CodeAuditorAgent con las dependencias configuradas.

    Lee la configuración desde settings para inyectar clientes correctamente.
    Se usa como dependency de FastAPI para facilitar mocking en tests.

    Returns:
        Instancia configurada de CodeAuditorAgent.
    """
    settings = get_settings()
    github_client = GitHubClient(
        token=settings.github.github_webhook_secret,
        api_timeout=settings.github.github_api_timeout,
        max_repo_size_mb=settings.analysis.max_repo_size_mb,
    )
    llm_client = LLMClient(
        api_key=settings.openai.openai_api_key,
        base_url=settings.openai.openai_base_url,
        model=settings.openai.openai_model,
        max_tokens=settings.openai.openai_max_tokens,
        timeout_seconds=settings.openai.openai_timeout_seconds,
        max_code_chars=settings.analysis.max_code_snippet_tokens * 4,
    )
    return CodeAuditorAgent(
        github_client=github_client,
        llm_client=llm_client,
        temp_clone_dir=settings.analysis.temp_clone_dir,
        analysis_timeout_seconds=settings.analysis.analysis_timeout_seconds,
    )


class AnalysisService:
    """
    Servicio de análisis que coordina el agente con la base de datos.

    Args:
        session: Sesión async de SQLAlchemy.
        agent: Agente de auditoría de código.
    """

    def __init__(self, session: AsyncSession, agent: CodeAuditorAgent) -> None:
        self._session = session
        self._agent = agent
        self._analysis_repo = AnalysisRepository(session)
        self._finding_repo = FindingRepository(session)

    async def execute_analysis(
        self,
        analysis_id: str,
        repo_full_name: str,
        commit_sha: str,
    ) -> Analysis:
        """
        Ejecuta el análisis completo y persiste los resultados.

        Flujo:
        1. Actualizar estado a RUNNING.
        2. Ejecutar CodeAuditorAgent.
        3. Persistir findings.
        4. Actualizar análisis con métricas.
        5. Marcar como COMPLETED o FAILED.

        Args:
            analysis_id: UUID del análisis en base de datos.
            repo_full_name: Nombre del repositorio 'owner/repo'.
            commit_sha: SHA del commit a analizar.

        Returns:
            Analysis actualizado con estado final.
        """
        logger.info(
            "analysis_service_start",
            analysis_id=analysis_id,
            repo=repo_full_name,
            commit=commit_sha[:8] if len(commit_sha) >= 8 else commit_sha,
        )

        analysis = await self._analysis_repo.update_status(
            analysis_id, AnalysisStatus.RUNNING
        )
        analysis.started_at = datetime.now()
        await self._session.commit()

        start_time = time.monotonic()

        try:
            audit_result: AuditResult = await self._agent.run_analysis(
                repo_full_name=repo_full_name,
                commit_sha=commit_sha,
            )

            duration = time.monotonic() - start_time

            if audit_result.error and not audit_result.findings:
                await self._mark_failed(analysis, audit_result.error, duration)
                return analysis

            if audit_result.findings:
                db_findings = self._build_db_findings(audit_result, analysis_id)
                await self._finding_repo.bulk_create(db_findings)

            await self._mark_completed(analysis, audit_result, duration)

        except Exception as exc:
            duration = time.monotonic() - start_time
            logger.error(
                "analysis_service_unexpected_error",
                analysis_id=analysis_id,
                error=str(exc),
            )
            await self._mark_failed(analysis, str(exc), duration)

        return analysis

    async def _mark_completed(
        self,
        analysis: Analysis,
        result: AuditResult,
        duration_seconds: float,
    ) -> None:
        """
        Actualiza el análisis como completado con métricas.

        Args:
            analysis: Instancia ORM del análisis.
            result: Resultado del agente.
            duration_seconds: Duración del análisis.
        """
        from src.db.models import FindingSeverity

        critical_count = sum(
            1 for f in result.findings
            if f.severity == FindingSeverity.CRITICAL
        )
        high_count = sum(
            1 for f in result.findings
            if f.severity == FindingSeverity.HIGH
        )

        analysis.status = AnalysisStatus.COMPLETED
        analysis.completed_at = datetime.now()
        analysis.duration_seconds = round(duration_seconds, 2)
        analysis.total_findings = len(result.findings)
        analysis.critical_count = critical_count
        analysis.high_count = high_count

        await self._session.commit()
        await self._session.refresh(analysis)

        logger.info(
            "analysis_completed",
            analysis_id=analysis.id,
            total=len(result.findings),
            critical=critical_count,
            high=high_count,
            duration=round(duration_seconds, 2),
        )

        try:
            from src.core.cache import set_cached_analysis
            from src.api.schemas.analysis_schemas import AnalysisDetailResponse, FindingResponse

            db_findings = await self._finding_repo.list_by_analysis(analysis.id)

            finding_dicts = [FindingResponse.model_validate(f).model_dump(mode="json") for f in db_findings]
            analysis_dict = AnalysisDetailResponse(
                **analysis.__dict__,
                findings=finding_dicts
            ).model_dump(mode="json")
            await set_cached_analysis(str(analysis.repository_id), analysis.commit_sha, analysis_dict)
            
        except Exception as cache_exc:
            logger.error("failed_to_serialize_cache", error=str(cache_exc), analysis_id=analysis.id)
        # ---------------------------------------------

    async def _mark_failed(
        self,
        analysis: Analysis,
        error_message: str,
        duration_seconds: float,
    ) -> None:
        """
        Actualiza el análisis como fallido con mensaje de error.

        Args:
            analysis: Instancia ORM del análisis.
            error_message: Descripción del error.
            duration_seconds: Duración hasta el fallo.
        """
        analysis.status = AnalysisStatus.FAILED
        analysis.completed_at = datetime.now()
        analysis.duration_seconds = round(duration_seconds, 2)
        analysis.error_message = error_message[:1000]
        await self._session.commit()

        logger.error(
            "analysis_failed",
            analysis_id=analysis.id,
            error=error_message[:200],
        )

    @staticmethod
    def _build_db_findings(result: AuditResult, analysis_id: str) -> list[Finding]:
        """
        Convierte RawFinding a instancias ORM Finding.

        Args:
            result: Resultado del agente con hallazgos.
            analysis_id: UUID del análisis padre.

        Returns:
            Lista de instancias Finding listas para persistir.
        """
        findings: list[Finding] = []
        for raw in result.findings:
            findings.append(Finding(
                analysis_id=analysis_id,
                category=raw.category,
                severity=raw.severity,
                title=raw.title[:300],
                description=raw.description,
                file_path=raw.file_path[:500],
                line_start=raw.line_start,
                line_end=raw.line_end,
                rule_id=raw.rule_id,
                recommendation=raw.recommendation,
            ))
        return findings