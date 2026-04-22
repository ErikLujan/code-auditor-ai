"""
Módulo de configuración central de la aplicación.

Carga y valida todas las variables de entorno usando Pydantic Settings.
Es la única fuente de verdad para configuración en todo el proyecto.
"""

from functools import lru_cache
from pathlib import Path

from pydantic import Field, PostgresDsn, RedisDsn, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppSettings(BaseSettings):
    """Configuración general de la aplicación."""

    app_name: str = "code-auditor"
    environment: str = Field(default="development", pattern="^(development|staging|production)$")
    debug: bool = False
    log_level: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    secret_key: str = Field(min_length=32)

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


class APISettings(BaseSettings):
    """Configuración del servidor API."""

    api_host: str = "0.0.0.0"
    api_port: int = Field(default=8000, ge=1024, le=65535)
    api_v1_prefix: str = "/api/v1"
    allowed_origins: str = "http://localhost:3000,http://localhost:8000"

    @property
    def allowed_origins_list(self) -> list[str]:
        """
        Parsea el string CSV de orígenes CORS a lista.

        Returns:
            Lista de URLs permitidas como strings.
        """
        return [origin.strip() for origin in self.allowed_origins.split(",") if origin.strip()]

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


class DatabaseSettings(BaseSettings):
    """Configuración de PostgreSQL."""

    database_url: PostgresDsn
    database_pool_size: int = Field(default=20, ge=1, le=100)
    database_max_overflow: int = Field(default=40, ge=0, le=200)
    database_echo: bool = False

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


class RedisSettings(BaseSettings):
    """Configuración de Redis."""

    redis_url: RedisDsn
    redis_password: str = ""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


class CelerySettings(BaseSettings):
    """Configuración de Celery + Redis broker."""

    celery_broker_url: str
    celery_result_backend: str
    celery_task_timeout: int = Field(default=300, ge=30, le=3600)

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


class JWTSettings(BaseSettings):
    """Configuración de autenticación JWT."""

    jwt_secret_key: str = Field(min_length=32)
    jwt_algorithm: str = "HS256"
    jwt_expiration_hours: int = Field(default=24, ge=1, le=720)
    jwt_refresh_expiration_days: int = Field(default=7, ge=1, le=30)

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


class OpenAISettings(BaseSettings):
    """Configuración del cliente OpenAI (o alternativas compatibles como Groq)."""

    openai_api_key: str = Field(min_length=10)
    openai_base_url: str | None = None
    openai_model: str = "gpt-3.5-turbo"
    openai_max_tokens: int = Field(default=8000, ge=100, le=16000)
    openai_timeout_seconds: int = Field(default=60, ge=10, le=300)

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


class GitHubSettings(BaseSettings):
    """Configuración de integración con GitHub."""

    github_app_id: str = ""
    github_app_private_key_path: Path = Path("./secrets/github_app.pem")
    github_webhook_secret: str = Field(min_length=16)
    github_api_timeout: int = Field(default=30, ge=5, le=120)

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


class RateLimitSettings(BaseSettings):
    """Configuración de rate limiting."""

    rate_limit_requests_per_minute: int = Field(default=5, ge=1, le=100)
    rate_limit_requests_per_day: int = Field(default=100, ge=1, le=10000)
    rate_limit_tokens_per_month: int = Field(default=100_000, ge=1000)

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


class AnalysisSettings(BaseSettings):
    """Configuración de límites del motor de análisis."""

    max_repo_size_mb: int = Field(default=500, ge=1, le=5000)
    max_files_to_analyze: int = Field(default=1000, ge=1, le=50000)
    analysis_timeout_seconds: int = Field(default=300, ge=30, le=3600)
    max_code_snippet_tokens: int = Field(default=4000, ge=100, le=8000)
    temp_clone_dir: Path = Path("/tmp/code-auditor/repos")

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


class MetricsSettings(BaseSettings):
    """Configuración de Prometheus."""

    metrics_enabled: bool = True
    metrics_port: int = Field(default=9090, ge=1024, le=65535)

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


class Settings:
    """
    Agregador de todas las configuraciones del proyecto.

    Centraliza el acceso a cada grupo de settings para evitar
    instanciar múltiples veces los mismos objetos Pydantic.
    """

    def __init__(self) -> None:
        self.app = AppSettings()
        self.api = APISettings()
        self.database = DatabaseSettings()
        self.redis = RedisSettings()
        self.celery = CelerySettings()
        self.jwt = JWTSettings()
        self.openai = OpenAISettings()
        self.github = GitHubSettings()
        self.rate_limit = RateLimitSettings()
        self.analysis = AnalysisSettings()
        self.metrics = MetricsSettings()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Retorna la instancia singleton de Settings.

    Usa lru_cache para garantizar una única instancia durante
    todo el ciclo de vida de la aplicación.

    Returns:
        Instancia cacheada de Settings con toda la configuración.
    """
    return Settings()