"""
Configuración de logging estructurado para la aplicación.

Usa structlog para generar logs en formato JSON en producción
y formato legible en desarrollo. Incluye context vars para
propagar request_id y user_id automáticamente en cada log.
"""

import logging
import sys
from contextvars import ContextVar
from typing import Any

import structlog
from structlog.types import EventDict, Processor

# Context vars propagadas automáticamente en cada log
_request_id_var: ContextVar[str] = ContextVar("request_id", default="")
_user_id_var: ContextVar[str] = ContextVar("user_id", default="")


def set_request_context(request_id: str, user_id: str = "") -> None:
    """
    Establece el contexto de la request actual en las context vars.

    Debe llamarse al inicio de cada request HTTP para que todos
    los logs generados durante esa request incluyan los IDs.

    Args:
        request_id: Identificador único de la request (UUID).
        user_id: ID del usuario autenticado (vacío si anónimo).
    """
    _request_id_var.set(request_id)
    _user_id_var.set(user_id)


def clear_request_context() -> None:
    """
    Limpia el contexto de request al finalizar.

    Debe llamarse en el finally de los middlewares para evitar
    filtración de contexto entre requests en workers async.
    """
    _request_id_var.set("")
    _user_id_var.set("")


def _add_request_context(_: Any, __: str, event_dict: EventDict) -> EventDict:
    """
    Processor de structlog que inyecta request_id y user_id.

    Args:
        _: Logger (no usado).
        __: Nombre del método de log (no usado).
        event_dict: Diccionario del evento a enriquecer.

    Returns:
        EventDict enriquecido con request_id y user_id.
    """
    request_id = _request_id_var.get()
    user_id = _user_id_var.get()

    if request_id:
        event_dict["request_id"] = request_id
    if user_id:
        event_dict["user_id"] = user_id

    return event_dict


def _drop_color_message(_: Any, __: str, event_dict: EventDict) -> EventDict:
    """
    Elimina el campo color_message agregado por uvicorn.

    Evita duplicación de mensajes en logs estructurados.

    Args:
        _: Logger (no usado).
        __: Nombre del método de log (no usado).
        event_dict: Diccionario del evento.

    Returns:
        EventDict sin el campo color_message.
    """
    event_dict.pop("color_message", None)
    return event_dict


def setup_logging(log_level: str = "INFO", environment: str = "development") -> None:
    """
    Configura structlog y el logging estándar de Python.

    En desarrollo usa ConsoleRenderer (legible).
    En producción usa JSONRenderer (parseable por herramientas como Loki).

    Args:
        log_level: Nivel de logging (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        environment: Entorno de ejecución ('development' o 'production').
    """
    shared_processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        _add_request_context,
        _drop_color_message,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]

    if environment == "production":
        renderer: Processor = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(log_level.upper())

    # Silenciar loggers ruidosos de librerías externas
    for noisy_logger in ("uvicorn.access", "httpx", "httpcore"):
        logging.getLogger(noisy_logger).setLevel(logging.WARNING)


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """
    Retorna un logger estructurado con el nombre del módulo.

    Uso recomendado al inicio de cada módulo:
        logger = get_logger(__name__)

    Args:
        name: Nombre del logger, típicamente __name__ del módulo.

    Returns:
        BoundLogger de structlog listo para usar.
    """
    return structlog.get_logger(name)