"""
Dependencies de FastAPI reutilizables.

Provee funciones de dependencia para inyección en endpoints:
autenticación JWT, obtención de usuario activo y paginación.
"""
import time

from fastapi import Depends, Header, Query, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.exceptions import AuthenticationError, AuthorizationError, RateLimitExceededError
from src.core.security import extract_user_id
from src.db.database import get_db_session
from src.db.models import User
from src.db.repositories import UserRepository

_bearer_scheme = HTTPBearer(auto_error=False)
_rate_limits = {}

async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    session: AsyncSession = Depends(get_db_session),
) -> User:
    """
    Extrae y valida el usuario autenticado desde el JWT Bearer.

    Args:
        credentials: Credenciales HTTP Bearer del header Authorization.
        session: Sesión de base de datos inyectada.

    Returns:
        Usuario autenticado y activo.

    Raises:
        AuthenticationError: Si el token es inválido, expirado o ausente.
        AuthorizationError: Si la cuenta del usuario está desactivada.
    """
    if not credentials:
        raise AuthenticationError("Token de autenticación requerido")

    user_id = extract_user_id(credentials.credentials)

    repo = UserRepository(session)
    user = await repo.get_by_id(user_id)

    if not user:
        raise AuthenticationError("Usuario no encontrado")
    if not user.is_active:
        raise AuthorizationError("Cuenta de usuario desactivada")

    return user


async def get_current_superuser(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Valida que el usuario autenticado sea superusuario.

    Args:
        current_user: Usuario autenticado inyectado.

    Returns:
        Usuario superusuario.

    Raises:
        AuthorizationError: Si el usuario no tiene permisos de administrador.
    """
    if not current_user.is_superuser:
        raise AuthorizationError("Se requieren permisos de administrador")
    return current_user


class PaginationParams:
    """
    Parámetros de paginación reutilizables para endpoints de listado.

    Attributes:
        page: Número de página (base 1).
        page_size: Cantidad de items por página.
        offset: Desplazamiento calculado para queries SQL.
    """

    def __init__(
        self,
        page: int = Query(default=1, ge=1, description="Número de página"),
        page_size: int = Query(default=20, ge=1, le=100, description="Items por página"),
    ) -> None:
        self.page = page
        self.page_size = page_size
        self.offset = (page - 1) * page_size

class RateLimiter:
    """
    Dependencia de FastAPI para limitar la cantidad de peticiones.
    """
    def __init__(self, requests: int, window_seconds: int):
        self.requests = requests
        self.window_seconds = window_seconds

    async def __call__(self, request: Request):
        client_ip = request.client.host if request.client else "127.0.0.1"
        key = f"rate_limit:{request.url.path}:{client_ip}"
        
        now = time.time()
        
        if key not in _rate_limits:
            _rate_limits[key] = []
            
        _rate_limits[key] = [t for t in _rate_limits[key] if now - t < self.window_seconds]
        
        if len(_rate_limits[key]) >= self.requests:
            retry_after = int(self.window_seconds - (now - _rate_limits[key][0]))
            limit_type = f"{self.requests} peticiones por {self.window_seconds}s"
            
            raise RateLimitExceededError(limit_type=limit_type, retry_after=retry_after)
            
        _rate_limits[key].append(now)