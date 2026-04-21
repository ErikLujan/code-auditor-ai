"""
Endpoints de autenticación.

Provee registro de usuarios, login con JWT y renovación
de tokens. Todos los endpoints son públicos (sin auth requerida).
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.schemas.auth_schemas import (
    TokenRefreshRequest,
    TokenResponse,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
)
from src.core.exceptions import AuthenticationError, DatabaseError
from src.core.logging import get_logger
from src.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from src.db.database import get_db_session
from src.db.repositories import UserRepository

logger = get_logger(__name__)
router = APIRouter(prefix="/auth", tags=["Autenticación"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Registrar nuevo usuario",
)
async def register(
    payload: UserRegisterRequest,
    session: AsyncSession = Depends(get_db_session),
) -> UserResponse:
    """
    Registra un nuevo usuario en el sistema.

    Args:
        payload: Email y contraseña del nuevo usuario.
        session: Sesión de base de datos inyectada.

    Returns:
        Datos públicos del usuario creado.

    Raises:
        HTTPException 409: Si el email ya está registrado.
        HTTPException 500: Si ocurre un error interno.
    """
    repo = UserRepository(session)

    if await repo.exists_by_email(payload.email):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="El email ya está registrado",
        )

    try:
        user = await repo.create(
            email=payload.email,
            hashed_password=hash_password(payload.password),
        )
    except DatabaseError as exc:
        logger.error("register_error", email=payload.email, error=exc.message)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al crear el usuario",
        ) from exc

    logger.info("user_registered", user_id=user.id)
    return UserResponse.model_validate(user)


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Iniciar sesión",
)
async def login(
    payload: UserLoginRequest,
    session: AsyncSession = Depends(get_db_session),
) -> TokenResponse:
    """
    Autentica un usuario y retorna tokens JWT.

    Usa mensaje genérico en error para evitar user enumeration.

    Args:
        payload: Credenciales del usuario.
        session: Sesión de base de datos inyectada.

    Returns:
        Access token y refresh token JWT.

    Raises:
        HTTPException 401: Si las credenciales son inválidas.
    """
    repo = UserRepository(session)
    user = await repo.get_by_email(payload.email)

    # Mensaje genérico para evitar user enumeration attack
    invalid_credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciales inválidas",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not user or not verify_password(payload.password, user.hashed_password):
        logger.warning("login_failed", email=payload.email)
        raise invalid_credentials_error

    if not user.is_active:
        logger.warning("login_inactive_user", user_id=user.id)
        raise invalid_credentials_error

    access_token = create_access_token(subject=user.id)
    refresh_token = create_refresh_token(subject=user.id)

    logger.info("user_logged_in", user_id=user.id)
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Renovar access token",
)
async def refresh_token(
    payload: TokenRefreshRequest,
    session: AsyncSession = Depends(get_db_session),
) -> TokenResponse:
    """
    Genera un nuevo access token a partir de un refresh token válido.

    Args:
        payload: Refresh token JWT.
        session: Sesión de base de datos inyectada.

    Returns:
        Nuevo access token y refresh token.

    Raises:
        HTTPException 401: Si el refresh token es inválido o expirado.
    """
    try:
        token_data = decode_token(payload.refresh_token, expected_type="refresh")
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=exc.message,
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    repo = UserRepository(session)
    user = await repo.get_by_id(token_data["sub"])

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario no válido",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return TokenResponse(
        access_token=create_access_token(subject=user.id),
        refresh_token=create_refresh_token(subject=user.id),
    )