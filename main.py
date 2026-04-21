"""
Punto de entrada de la aplicación FastAPI.

Configura la app con middlewares de seguridad, CORS, rate limiting,
manejo centralizado de excepciones y registro de routers.
"""

import uuid

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from src.api.routers.auth_router import router as auth_router
from src.api.routers.analysis_router import analysis_router, repos_router
from src.core.config import get_settings
from src.core.exceptions import (
    AuthenticationError,
    AuthorizationError,
    CodeAuditorError,
    RateLimitExceededError,
    ValidationError,
)
from src.core.logging import get_logger, set_request_context, clear_request_context, setup_logging

settings = get_settings()
setup_logging(
    log_level=settings.app.log_level,
    environment=settings.app.environment,
)
logger = get_logger(__name__)

# Rate limiter global basado en IP
limiter = Limiter(key_func=get_remote_address)


def create_app() -> FastAPI:
    """
    Factory que construye y configura la aplicación FastAPI.

    Separa la construcción de la app del punto de entrada para
    facilitar testing (se puede instanciar sin levantar servidor).

    Returns:
        Aplicación FastAPI completamente configurada.
    """
    app = FastAPI(
        title="Code Auditor API",
        description="Agente IA para auditoría automática de repositorios GitHub",
        version="0.1.0",
        docs_url="/docs" if settings.app.environment != "production" else None,
        redoc_url="/redoc" if settings.app.environment != "production" else None,
    )

    _register_middlewares(app)
    _register_exception_handlers(app)
    _register_routers(app)

    logger.info("app_started", environment=settings.app.environment)
    return app


def _register_middlewares(app: FastAPI) -> None:
    """
    Registra todos los middlewares de la aplicación.

    Args:
        app: Instancia de FastAPI a configurar.
    """
    # Rate limiting (debe ir antes de CORS)
    app.state.limiter = limiter
    app.add_middleware(SlowAPIMiddleware)

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.api.allowed_origins_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )

    # Middleware de request ID y contexto de logging
    @app.middleware("http")
    async def request_context_middleware(request: Request, call_next):
        """
        Inyecta request_id único en cada request para trazabilidad.

        Args:
            request: Request HTTP entrante.
            call_next: Siguiente handler en la cadena.

        Returns:
            Response con header X-Request-ID agregado.
        """
        request_id = str(uuid.uuid4())
        set_request_context(request_id=request_id)
        try:
            response = await call_next(request)
            response.headers["X-Request-ID"] = request_id
            return response
        finally:
            clear_request_context()

    # Headers de seguridad
    @app.middleware("http")
    async def security_headers_middleware(request: Request, call_next):
        """
        Agrega headers de seguridad HTTP a todas las respuestas.

        Args:
            request: Request HTTP entrante.
            call_next: Siguiente handler en la cadena.

        Returns:
            Response con headers de seguridad agregados.
        """
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=()"
        return response


def _register_exception_handlers(app: FastAPI) -> None:
    """
    Registra handlers centralizados para excepciones del dominio.

    Convierte excepciones internas en respuestas JSON con formato
    consistente para el cliente.

    Args:
        app: Instancia de FastAPI a configurar.
    """
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    @app.exception_handler(AuthenticationError)
    async def authentication_error_handler(request: Request, exc: AuthenticationError):
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": exc.message, "code": exc.code},
            headers={"WWW-Authenticate": "Bearer"},
        )

    @app.exception_handler(AuthorizationError)
    async def authorization_error_handler(request: Request, exc: AuthorizationError):
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"detail": exc.message, "code": exc.code},
        )

    @app.exception_handler(ValidationError)
    async def validation_error_handler(request: Request, exc: ValidationError):
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"detail": exc.message, "code": exc.code, "field": exc.field},
        )

    @app.exception_handler(RateLimitExceededError)
    async def rate_limit_error_handler(request: Request, exc: RateLimitExceededError):
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"detail": exc.message, "code": exc.code},
            headers={"Retry-After": str(exc.retry_after)},
        )

    @app.exception_handler(CodeAuditorError)
    async def generic_domain_error_handler(request: Request, exc: CodeAuditorError):
        logger.error("unhandled_domain_error", code=exc.code, message=exc.message)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Error interno del servidor", "code": exc.code},
        )


def _register_routers(app: FastAPI) -> None:
    """
    Registra todos los routers bajo el prefijo de la API.

    Args:
        app: Instancia de FastAPI a configurar.
    """
    prefix = settings.api.api_v1_prefix

    app.include_router(auth_router, prefix=prefix)
    app.include_router(repos_router, prefix=prefix)
    app.include_router(analysis_router, prefix=prefix)

    @app.get("/health", tags=["Health"])
    async def health_check():
        """
        Endpoint de health check para load balancers y monitoreo.

        Returns:
            Estado de la aplicación.
        """
        return {"status": "ok", "version": "0.1.0"}


app = create_app()