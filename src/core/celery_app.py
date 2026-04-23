"""
Configuración central de Celery.

Conecta Celery con Redis para manejar las colas de tareas asíncronas,
liberando a la API de FastAPI del procesamiento pesado (clonar, AST, LLM).
"""

from celery import Celery
from src.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "code_auditor",
    broker=settings.celery.celery_broker_url,
    backend=settings.celery.celery_result_backend,
    include=["src.tasks.analysis_tasks"]
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_time_limit=settings.celery.celery_task_timeout + 60,
    task_soft_time_limit=settings.celery.celery_task_timeout,
)