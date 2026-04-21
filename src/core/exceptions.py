"""
Excepciones personalizadas del dominio de la aplicación.

Define una jerarquía clara de errores para permitir manejo
granular en capas superiores (API, servicios, tareas Celery).
"""


class CodeAuditorError(Exception):
    """
    Excepción base de la aplicación.

    Todas las excepciones del dominio heredan de esta clase
    para permitir captura genérica cuando sea necesario.

    Args:
        message: Descripción legible del error.
        code: Código interno de error para logging/monitoreo.
    """

    def __init__(self, message: str, code: str = "INTERNAL_ERROR") -> None:
        self.message = message
        self.code = code
        super().__init__(self.message)


# ── Autenticación / Autorización ──────────────────────────────────────────────

class AuthenticationError(CodeAuditorError):
    """Credenciales inválidas o token ausente."""

    def __init__(self, message: str = "Autenticación fallida") -> None:
        super().__init__(message, code="AUTH_ERROR")


class AuthorizationError(CodeAuditorError):
    """Usuario autenticado sin permisos suficientes."""

    def __init__(self, message: str = "Permisos insuficientes") -> None:
        super().__init__(message, code="FORBIDDEN")


class TokenExpiredError(AuthenticationError):
    """JWT expirado."""

    def __init__(self) -> None:
        super().__init__("Token expirado")
        self.code = "TOKEN_EXPIRED"


# ── Validación ────────────────────────────────────────────────────────────────

class ValidationError(CodeAuditorError):
    """
    Input inválido recibido por la aplicación.

    Args:
        message: Descripción del error de validación.
        field: Campo específico que falló validación (opcional).
    """

    def __init__(self, message: str, field: str | None = None) -> None:
        self.field = field
        super().__init__(message, code="VALIDATION_ERROR")


class InvalidRepositoryURLError(ValidationError):
    """URL de repositorio GitHub inválida o no permitida."""

    def __init__(self, url: str) -> None:
        super().__init__(f"URL de repositorio inválida: {url}", field="repository_url")
        self.code = "INVALID_REPO_URL"


# ── GitHub ────────────────────────────────────────────────────────────────────

class GitHubError(CodeAuditorError):
    """Error base de integración con GitHub API."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="GITHUB_ERROR")


class GitHubRateLimitError(GitHubError):
    """Rate limit de GitHub API alcanzado."""

    def __init__(self, reset_at: str = "") -> None:
        msg = f"GitHub API rate limit alcanzado. Reset: {reset_at}" if reset_at else "GitHub API rate limit alcanzado"
        super().__init__(msg)
        self.code = "GITHUB_RATE_LIMIT"
        self.reset_at = reset_at


class RepositoryNotFoundError(GitHubError):
    """Repositorio no encontrado o sin acceso."""

    def __init__(self, repo: str) -> None:
        super().__init__(f"Repositorio no encontrado: {repo}")
        self.code = "REPO_NOT_FOUND"


class RepositoryTooLargeError(GitHubError):
    """Repositorio supera el límite de tamaño configurado."""

    def __init__(self, size_mb: float, limit_mb: int) -> None:
        super().__init__(f"Repositorio demasiado grande: {size_mb:.1f}MB (límite: {limit_mb}MB)")
        self.code = "REPO_TOO_LARGE"


# ── Análisis ──────────────────────────────────────────────────────────────────

class AnalysisError(CodeAuditorError):
    """Error base durante el proceso de análisis de código."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="ANALYSIS_ERROR")


class AnalysisTimeoutError(AnalysisError):
    """Análisis superó el tiempo máximo permitido."""

    def __init__(self, timeout_seconds: int) -> None:
        super().__init__(f"Análisis cancelado por timeout ({timeout_seconds}s)")
        self.code = "ANALYSIS_TIMEOUT"


class AnalysisNotFoundError(AnalysisError):
    """Análisis solicitado no existe en la base de datos."""

    def __init__(self, analysis_id: str) -> None:
        super().__init__(f"Análisis no encontrado: {analysis_id}")
        self.code = "ANALYSIS_NOT_FOUND"


# ── LLM ───────────────────────────────────────────────────────────────────────

class LLMError(CodeAuditorError):
    """Error base de integración con el LLM."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="LLM_ERROR")


class LLMRateLimitError(LLMError):
    """Rate limit del proveedor LLM alcanzado."""

    def __init__(self) -> None:
        super().__init__("Rate limit LLM alcanzado")
        self.code = "LLM_RATE_LIMIT"


class LLMInvalidResponseError(LLMError):
    """Respuesta del LLM no cumple el esquema esperado."""

    def __init__(self, reason: str = "") -> None:
        msg = f"Respuesta LLM inválida: {reason}" if reason else "Respuesta LLM inválida"
        super().__init__(msg)
        self.code = "LLM_INVALID_RESPONSE"


# ── Rate Limiting (aplicación) ────────────────────────────────────────────────

class RateLimitExceededError(CodeAuditorError):
    """
    Usuario superó el rate limit de la aplicación.

    Args:
        limit_type: Tipo de límite excedido (minute, day, month).
        retry_after: Segundos hasta que el límite se resetea.
    """

    def __init__(self, limit_type: str, retry_after: int = 0) -> None:
        super().__init__(
            f"Rate limit excedido ({limit_type}). Reintentar en {retry_after}s",
            code="RATE_LIMIT_EXCEEDED",
        )
        self.limit_type = limit_type
        self.retry_after = retry_after


# ── Base de Datos ─────────────────────────────────────────────────────────────

class DatabaseError(CodeAuditorError):
    """Error de operación en base de datos."""

    def __init__(self, message: str = "Error de base de datos") -> None:
        super().__init__(message, code="DATABASE_ERROR")