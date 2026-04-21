"""
Schemas Pydantic para autenticación y gestión de usuarios.

Define los contratos de entrada/salida para los endpoints
de registro, login y perfil de usuario.
"""

import re

from pydantic import BaseModel, EmailStr, Field, field_validator


# ── Requests ──────────────────────────────────────────────────────────────────

class UserRegisterRequest(BaseModel):
    """
    Payload para registro de nuevo usuario.

    Attributes:
        email: Email válido del usuario.
        password: Contraseña con requisitos mínimos de seguridad.
    """

    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """
        Valida que la contraseña cumpla requisitos mínimos de seguridad.

        Requiere al menos: 1 mayúscula, 1 minúscula, 1 número.

        Args:
            v: Contraseña a validar.

        Returns:
            Contraseña validada.

        Raises:
            ValueError: Si no cumple los requisitos.
        """
        if not re.search(r"[A-Z]", v):
            raise ValueError("La contraseña debe contener al menos una mayúscula")
        if not re.search(r"[a-z]", v):
            raise ValueError("La contraseña debe contener al menos una minúscula")
        if not re.search(r"\d", v):
            raise ValueError("La contraseña debe contener al menos un número")
        return v


class UserLoginRequest(BaseModel):
    """
    Payload para autenticación de usuario existente.

    Attributes:
        email: Email registrado.
        password: Contraseña en texto plano.
    """

    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class TokenRefreshRequest(BaseModel):
    """
    Payload para renovar el access token usando un refresh token.

    Attributes:
        refresh_token: JWT de refresh válido.
    """

    refresh_token: str = Field(min_length=10)


# ── Responses ─────────────────────────────────────────────────────────────────

class UserResponse(BaseModel):
    """
    Representación pública de un usuario (sin datos sensibles).

    Attributes:
        id: UUID del usuario.
        email: Email del usuario.
        is_active: Estado de la cuenta.
    """

    id: str
    email: str
    is_active: bool

    model_config = {"from_attributes": True}


class TokenResponse(BaseModel):
    """
    Respuesta de autenticación con tokens JWT.

    Attributes:
        access_token: JWT de acceso de corta duración.
        refresh_token: JWT de refresh de larga duración.
        token_type: Tipo de token (siempre 'bearer').
    """

    access_token: str
    refresh_token: str
    token_type: str = "bearer"