"""
Tests de integración para los Webhooks de GitHub.

Verifica la validación criptográfica HMAC-SHA256, el filtrado
de repositorios no registrados y el correcto encolado de tareas en Celery.
"""

import hmac
import hashlib
import json
from unittest.mock import patch

import pytest
from httpx import AsyncClient

from src.core.config import get_settings
from src.db.models import Repository

settings = get_settings()

def generate_signature(payload: bytes, secret: str) -> str:
    """Genera una firma HMAC-SHA256 válida como lo haría GitHub."""
    mac = hmac.new(secret.encode("utf-8"), msg=payload, digestmod=hashlib.sha256)
    return f"sha256={mac.hexdigest()}"

@pytest.mark.asyncio
async def test_webhook_missing_signature(client: AsyncClient):
    """Peticiones sin el header X-Hub-Signature-256 deben ser rechazadas (403)."""
    response = await client.post("/api/v1/webhooks/github", json={"ping": "pong"})
    
    assert response.status_code == 403
    assert response.json()["detail"] == "Falta firma de GitHub"

@pytest.mark.asyncio
async def test_webhook_invalid_signature(client: AsyncClient):
    """Peticiones con firma falsa o manipulada deben ser rechazadas (403)."""
    headers = {"X-Hub-Signature-256": "sha256=fakehash123456789"}
    response = await client.post("/api/v1/webhooks/github", json={"ping": "pong"}, headers=headers)
    
    assert response.status_code == 403
    assert response.json()["detail"] == "Firma de GitHub inválida"

@pytest.mark.asyncio
async def test_webhook_unregistered_repo(client: AsyncClient):
    """Webhooks de repositorios no registrados en la BD se ignoran silenciosamente (202)."""
    payload = {"repository": {"html_url": "https://github.com/hacker/malicious-repo"}}
    payload_bytes = json.dumps(payload).encode("utf-8")
    signature = generate_signature(payload_bytes, settings.github.github_webhook_secret)

    headers = {
        "X-Hub-Signature-256": signature,
        "X-GitHub-Event": "push"
    }

    response = await client.post("/api/v1/webhooks/github", content=payload_bytes, headers=headers)
    
    assert response.status_code == 202
    assert response.json()["message"] == "Repositorio no registrado."

@pytest.mark.asyncio
@patch("src.api.routers.webhook_router.run_analysis_task.delay")
async def test_webhook_success_queues_analysis(
    mock_delay, client: AsyncClient, test_repository: Repository
):
    """Un webhook válido de un repositorio registrado debe crear un análisis y encolarlo."""
    payload = {
        "repository": {"html_url": test_repository.github_url},
        "after": "newcommitsha123456789"
    }
    payload_bytes = json.dumps(payload).encode("utf-8")
    signature = generate_signature(payload_bytes, settings.github.github_webhook_secret)

    headers = {
        "X-Hub-Signature-256": signature,
        "X-GitHub-Event": "push"
    }

    response = await client.post("/api/v1/webhooks/github", content=payload_bytes, headers=headers)
    
    assert response.status_code == 202
    assert response.json()["message"] == "Análisis encolado"

    mock_delay.assert_called_once()