"""
Tareas de Celery para procesamiento en background.
"""

import asyncio
from src.core.celery_app import celery_app
from src.core.logging import get_logger

logger = get_logger(__name__)

@celery_app.task(name="run_analysis_task", bind=True, max_retries=3)
def run_analysis_task(self, analysis_id: str, repo_full_name: str, commit_sha: str):
    """
    Tarea de Celery que ejecuta el análisis de código.
    Actúa como puente síncrono hacia nuestro servicio asíncrono.
    """
    logger.info("celery_analysis_task_started", analysis_id=analysis_id, repo=repo_full_name)
    
    try:
        asyncio.run(_run_async_analysis(analysis_id, repo_full_name, commit_sha))
    except Exception as exc:
        logger.error("celery_analysis_task_failed", analysis_id=analysis_id, error=str(exc))
        raise self.retry(exc=exc, countdown=60)


async def _run_async_analysis(analysis_id: str, repo_full_name: str, commit_sha: str) -> None:
    """Función asíncrona real que levanta la sesión de BD y llama al servicio."""
    from src.db.database import AsyncSessionFactory
    from src.services.analysis_service import AnalysisService, build_auditor_agent

    async with AsyncSessionFactory() as session:
        agent = build_auditor_agent()
        service = AnalysisService(session=session, agent=agent)
        await service.execute_analysis(
            analysis_id=analysis_id,
            repo_full_name=repo_full_name,
            commit_sha=commit_sha,
        )