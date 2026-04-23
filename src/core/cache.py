"""
Gestor de caché distribuida utilizando Redis.

Provee funciones para almacenar y recuperar resultados de análisis
previamente ejecutados, evitando consumo innecesario de recursos y tokens LLM.
"""

import json
from typing import Any
import redis.asyncio as redis

from src.core.config import get_settings
from src.core.logging import get_logger

settings = get_settings()
logger = get_logger(__name__)

redis_client = redis.from_url(str(settings.redis.redis_url), decode_responses=True)

async def get_cached_analysis(repository_id: str, commit_sha: str) -> dict[str, Any] | None:
    """
    Busca un análisis previamente completado en la caché de Redis.
    
    Args:
        repository_id (str): UUID del repositorio.
        commit_sha (str): Hash del commit analizado.
        
    Returns:
        dict[str, Any] | None: Diccionario con los datos del análisis o None si no existe.
    """
    key = f"analysis:cache:{repository_id}:{commit_sha}"
    try:
        data = await redis_client.get(key)
        if data:
            logger.info("cache_hit", repository_id=repository_id, commit_sha=commit_sha)
            return json.loads(data)
        return None
    except Exception as exc:
        logger.error("redis_cache_read_error", error=str(exc))
        return None

async def set_cached_analysis(repository_id: str, commit_sha: str, data: dict[str, Any]) -> None:
    """
    Guarda el resultado de un análisis completado en Redis con un tiempo de vida (TTL).
    
    Args:
        repository_id (str): UUID del repositorio.
        commit_sha (str): Hash del commit analizado.
        data (dict[str, Any]): Datos serializados del análisis (incluyendo findings).
        
    Returns:
        None
    """
    key = f"analysis:cache:{repository_id}:{commit_sha}"
    ttl_seconds = 86400
    try:
        await redis_client.setex(key, ttl_seconds, json.dumps(data))
        logger.info("cache_set", repository_id=repository_id, commit_sha=commit_sha)
    except Exception as exc:
        logger.error("redis_cache_write_error", error=str(exc))