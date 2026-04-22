"""
Módulo central de seguridad de la aplicación.

Provee utilidades para:
- Hashing y verificación de contraseñas (bcrypt)
- Generación y validación de tokens JWT
- Sanitización de inputs para prevenir inyección de prompts
- Validación de URLs de repositorios GitHub
"""

import re
import unicodedata
from datetime import UTC, datetime, timedelta
from typing import Any

from jose import JWTError, jwt
from passlib.context import CryptContext

from src.core.config import get_settings
from src.core.exceptions import (
    AuthenticationError,
    InvalidRepositoryURLError,
    TokenExpiredError,
    ValidationError,
)
from src.core.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12, bcrypt__ident="2b")

_GITHUB_URL_PATTERN = re.compile(
    r"^https://github\.com/[a-zA-Z0-9]([a-zA-Z0-9\-]{0,37}[a-zA-Z0-9])?/[a-zA-Z0-9_\-\.]{1,100}$"
)

_PROMPT_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"ignore\s+(previous|above|all)\s+instructions?", re.IGNORECASE),
    re.compile(r"you\s+are\s+now", re.IGNORECASE),
    re.compile(r"(system|assistant|user)\s*:", re.IGNORECASE),
    re.compile(r"<\s*(system|instruction|prompt)\s*>", re.IGNORECASE),
    re.compile(r"\[INST\]|\[/INST\]"),
    re.compile(r"#{3,}"),
]


# ── Contraseñas ───────────────────────────────────────────────────────────────

def hash_password(plain_password: str) -> str:
    """
    Genera hash bcrypt de una contraseña en texto plano.

    Args:
        plain_password: Contraseña sin hashear.

    Returns:
        Hash bcrypt listo para almacenar en base de datos.

    Raises:
        ValidationError: Si la contraseña está vacía.
    """
    if not plain_password:
        raise ValidationError("La contraseña no puede estar vacía", field="password")
    return _pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifica si una contraseña en texto plano coincide con su hash.

    Usa comparación en tiempo constante para prevenir timing attacks.

    Args:
        plain_password: Contraseña ingresada por el usuario.
        hashed_password: Hash almacenado en base de datos.

    Returns:
        True si coinciden, False en caso contrario.
    """
    return _pwd_context.verify(plain_password, hashed_password)


# ── JWT ───────────────────────────────────────────────────────────────────────

def create_access_token(subject: str, extra_claims: dict[str, Any] | None = None) -> str:
    """
    Genera un JWT de acceso firmado con HS256.

    Args:
        subject: Identificador del usuario (user_id como string).
        extra_claims: Claims adicionales a incluir en el payload (opcional).

    Returns:
        JWT firmado como string.
    """
    expiration = datetime.now(UTC) + timedelta(hours=settings.jwt.jwt_expiration_hours)
    payload: dict[str, Any] = {
        "sub": subject,
        "exp": expiration,
        "iat": datetime.now(UTC),
        "type": "access",
    }
    if extra_claims:
        payload.update(extra_claims)

    token = jwt.encode(payload, settings.jwt.jwt_secret_key, algorithm=settings.jwt.jwt_algorithm)
    logger.info("access_token_created", user_id=subject)
    return token


def create_refresh_token(subject: str) -> str:
    """
    Genera un JWT de refresh con expiración extendida.

    Args:
        subject: Identificador del usuario (user_id como string).

    Returns:
        JWT de refresh firmado como string.
    """
    expiration = datetime.now(UTC) + timedelta(days=settings.jwt.jwt_refresh_expiration_days)
    payload: dict[str, Any] = {
        "sub": subject,
        "exp": expiration,
        "iat": datetime.now(UTC),
        "type": "refresh",
    }
    return jwt.encode(payload, settings.jwt.jwt_secret_key, algorithm=settings.jwt.jwt_algorithm)


def decode_token(token: str, expected_type: str = "access") -> dict[str, Any]:
    """
    Decodifica y valida un JWT.

    Verifica firma, expiración y tipo de token.

    Args:
        token: JWT a decodificar.
        expected_type: Tipo esperado del token ('access' o 'refresh').

    Returns:
        Payload decodificado como diccionario.

    Raises:
        TokenExpiredError: Si el token expiró.
        AuthenticationError: Si el token es inválido o el tipo no coincide.
    """
    try:
        payload = jwt.decode(
            token,
            settings.jwt.jwt_secret_key,
            algorithms=[settings.jwt.jwt_algorithm],
        )
    except JWTError as exc:
        if "expired" in str(exc).lower():
            raise TokenExpiredError() from exc
        raise AuthenticationError("Token JWT inválido") from exc

    if payload.get("type") != expected_type:
        raise AuthenticationError(f"Tipo de token incorrecto. Esperado: {expected_type}")

    return payload


def extract_user_id(token: str) -> str:
    """
    Extrae el user_id del payload de un access token.

    Args:
        token: JWT de acceso válido.

    Returns:
        User ID como string.

    Raises:
        AuthenticationError: Si el subject está ausente en el payload.
    """
    payload = decode_token(token, expected_type="access")
    subject = payload.get("sub")
    if not subject:
        raise AuthenticationError("Token sin subject válido")
    return str(subject)


# ── Validación de URLs ────────────────────────────────────────────────────────

def validate_github_url(url: str) -> str:
    """
    Valida que una URL corresponda a un repositorio GitHub legítimo.

    Verifica formato, esquema HTTPS y patrón de owner/repo.
    Previene SSRF y acceso a hosts arbitrarios.

    Args:
        url: URL a validar.

    Returns:
        URL validada y normalizada (sin trailing slash).

    Raises:
        InvalidRepositoryURLError: Si la URL no cumple el patrón esperado.
    """
    if not url or not isinstance(url, str):
        raise InvalidRepositoryURLError(str(url))

    normalized = url.strip().rstrip("/")

    if not _GITHUB_URL_PATTERN.match(normalized):
        logger.warning("invalid_github_url_attempt", url=normalized)
        raise InvalidRepositoryURLError(normalized)

    return normalized


# ── Sanitización para LLM ─────────────────────────────────────────────────────

def sanitize_code_for_prompt(code: str, max_tokens: int = 4000) -> str:
    """
    Sanitiza un fragmento de código antes de enviarlo al LLM.

    Aplica:
    1. Normalización unicode para evitar caracteres de control ocultos.
    2. Detección de patrones de inyección de prompts.
    3. Truncado por aproximación de tokens (1 token ≈ 4 chars).

    Args:
        code: Código fuente a sanitizar.
        max_tokens: Límite máximo de tokens aproximado (default: 4000).

    Returns:
        Código sanitizado y truncado si corresponde.

    Raises:
        ValidationError: Si se detectan patrones de inyección de prompts.
    """
    if not code:
        return ""

    normalized = unicodedata.normalize("NFKC", code)

    for pattern in _PROMPT_INJECTION_PATTERNS:
        if pattern.search(normalized):
            logger.warning("prompt_injection_attempt_detected", pattern=pattern.pattern)
            raise ValidationError(
                "El código contiene patrones no permitidos para análisis",
                field="code_content",
            )

    max_chars = max_tokens * 4
    if len(normalized) > max_chars:
        logger.info("code_truncated_for_prompt", original_chars=len(normalized), max_chars=max_chars)
        normalized = normalized[:max_chars] + "\n# [TRUNCADO: fragmento excede límite de tokens]"

    return normalized


def sanitize_string_input(value: str, max_length: int = 500, field_name: str = "input") -> str:
    """
    Sanitiza un string genérico de input del usuario.

    Elimina caracteres de control, normaliza unicode y valida longitud.

    Args:
        value: String a sanitizar.
        max_length: Longitud máxima permitida.
        field_name: Nombre del campo para mensajes de error.

    Returns:
        String sanitizado.

    Raises:
        ValidationError: Si el valor excede la longitud máxima.
    """
    if not value:
        return ""

    cleaned = "".join(
        ch for ch in value
        if unicodedata.category(ch) not in {"Cc", "Cf"} or ch in {"\n", "\t"}
    )
    cleaned = unicodedata.normalize("NFKC", cleaned).strip()

    if len(cleaned) > max_length:
        raise ValidationError(
            f"{field_name} excede la longitud máxima de {max_length} caracteres",
            field=field_name,
        )

    return cleaned