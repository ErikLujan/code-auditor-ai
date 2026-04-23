"""
Router para la gestión de Webhooks de GitHub.
Permite la automatización de análisis ante eventos de push o pull request.
"""

import hmac
import hashlib
import json
from fastapi import APIRouter, Header, HTTPException, Request, status, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import RateLimiter
from src.core.config import get_settings
from src.core.logging import get_logger
from src.db.database import get_db_session
from src.db.repositories import AnalysisRepository, RepositoryRepository
from src.tasks.analysis_tasks import run_analysis_task

logger = get_logger(__name__)
settings = get_settings()

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])

def verify_github_signature(payload_body: bytes, signature_header: str | None) -> None:
    """
    Verifica que el payload provenga de GitHub comparando el hash HMAC-SHA256.
    
    Args:
        payload_body (bytes): Cuerpo de la petición en formato bytes.
        signature_header (str | None): Valor del header X-Hub-Signature-256.
        
    Returns:
        None
        
    Raises:
        HTTPException 403: Si la firma falta, es inválida o tiene formato incorrecto.
    """
    if not signature_header:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Falta firma de GitHub")

    hash_parts = signature_header.split("=")
    if len(hash_parts) != 2 or hash_parts[0] != "sha256":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Formato de firma inválido")

    mac = hmac.new(
        settings.github.github_webhook_secret.encode("utf-8"),
        msg=payload_body,
        digestmod=hashlib.sha256,
    )
    expected_signature = mac.hexdigest()

    if not hmac.compare_digest(expected_signature, hash_parts[1]):
        logger.warning("invalid_webhook_signature", received=hash_parts[1])
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Firma de GitHub inválida")


@router.post(
    "/github",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Procesar webhook de GitHub",
    dependencies=[Depends(RateLimiter(requests=10, window_seconds=60))]
)
async def github_webhook(
    request: Request,
    x_github_event: str | None = Header(default=None),
    x_hub_signature_256: str | None = Header(default=None),
    session: AsyncSession = Depends(get_db_session)
):
    """
    Recibe eventos push/pull_request, valida seguridad y encola el análisis en Celery.
    
    Args:
        request (Request): Objeto de petición de FastAPI.
        x_github_event (str | None): Tipo de evento enviado por GitHub.
        x_hub_signature_256 (str | None): Firma para validación HMAC.
        session (AsyncSession): Sesión de base de datos inyectada.
        
    Returns:
        dict: Mensaje de confirmación con el ID del análisis creado.
        
    Raises:
        HTTPException 400: Si el payload no es un JSON válido.
    """
    payload_body = await request.body()
    verify_github_signature(payload_body, x_hub_signature_256)

    if x_github_event not in ["push", "pull_request"]:
        return {"message": f"Evento {x_github_event} ignorado."}

    try:
        payload = json.loads(payload_body)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="JSON inválido") from exc

    github_url = payload.get("repository", {}).get("html_url")
    if not github_url:
        return {"message": "Payload sin URL de repositorio."}

    if x_github_event == "push":
        commit_sha = payload.get("after")
        if commit_sha == "0000000000000000000000000000000000000000":
            return {"message": "Borrado de rama ignorado."}
    else:
        commit_sha = payload.get("pull_request", {}).get("head", {}).get("sha")

    repo_db = RepositoryRepository(session)
    repository = await repo_db.get_by_url(github_url)

    if not repository:
        logger.info("webhook_ignored_unregistered_repo", url=github_url)
        return {"message": "Repositorio no registrado."}

    analysis_db = AnalysisRepository(session)
    analysis = await analysis_db.create(
        repository_id=repository.id,
        commit_sha=commit_sha,
    )
    await session.commit()

    run_analysis_task.delay(
        analysis_id=analysis.id,
        repo_full_name=repository.full_name,
        commit_sha=analysis.commit_sha,
    )

    logger.info("webhook_analysis_queued", analysis_id=analysis.id)
    return {"message": "Análisis encolado", "analysis_id": analysis.id}