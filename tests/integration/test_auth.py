"""
Tests de integración para endpoints de autenticación.

Prueba el flujo completo de register, login y refresh
a través del cliente HTTP de test.
"""

import pytest
from httpx import AsyncClient

from src.db.models import User


class TestRegister:
    """Tests para POST /api/v1/auth/register."""

    async def test_register_success(self, client: AsyncClient):
        """Registro con datos válidos debe retornar 201 y datos del usuario."""
        response = await client.post("/api/v1/auth/register", json={
            "email": "newuser@example.com",
            "password": "SecurePass123",
        })
        assert response.status_code == 201
        data = response.json()
        assert data["email"] == "newuser@example.com"
        assert data["is_active"] is True
        assert "id" in data
        assert "hashed_password" not in data

    async def test_register_duplicate_email(self, client: AsyncClient, test_user: User):
        """Registro con email duplicado debe retornar 409."""
        response = await client.post("/api/v1/auth/register", json={
            "email": test_user.email,
            "password": "SecurePass123",
        })
        assert response.status_code == 409

    async def test_register_invalid_email(self, client: AsyncClient):
        """Email inválido debe retornar 422."""
        response = await client.post("/api/v1/auth/register", json={
            "email": "not-an-email",
            "password": "SecurePass123",
        })
        assert response.status_code == 422

    async def test_register_weak_password_no_uppercase(self, client: AsyncClient):
        """Contraseña sin mayúscula debe retornar 422."""
        response = await client.post("/api/v1/auth/register", json={
            "email": "user@example.com",
            "password": "weakpass123",
        })
        assert response.status_code == 422

    async def test_register_weak_password_no_number(self, client: AsyncClient):
        """Contraseña sin número debe retornar 422."""
        response = await client.post("/api/v1/auth/register", json={
            "email": "user@example.com",
            "password": "WeakPassword",
        })
        assert response.status_code == 422

    async def test_register_short_password(self, client: AsyncClient):
        """Contraseña menor a 8 caracteres debe retornar 422."""
        response = await client.post("/api/v1/auth/register", json={
            "email": "user@example.com",
            "password": "Ab1",
        })
        assert response.status_code == 422


class TestLogin:
    """Tests para POST /api/v1/auth/login."""

    async def test_login_success(self, client: AsyncClient, test_user: User):
        """Login con credenciales correctas debe retornar tokens JWT."""
        response = await client.post("/api/v1/auth/login", json={
            "email": test_user.email,
            "password": "TestPass123",
        })
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"

    async def test_login_wrong_password(self, client: AsyncClient, test_user: User):
        """Login con contraseña incorrecta debe retornar 401."""
        response = await client.post("/api/v1/auth/login", json={
            "email": test_user.email,
            "password": "WrongPassword123",
        })
        assert response.status_code == 401

    async def test_login_nonexistent_user(self, client: AsyncClient):
        """Login con email inexistente debe retornar 401 (no 404)."""
        response = await client.post("/api/v1/auth/login", json={
            "email": "ghost@example.com",
            "password": "SomePass123",
        })
        assert response.status_code == 401

    async def test_login_generic_error_message(self, client: AsyncClient):
        """Error de login debe usar mensaje genérico para evitar user enumeration."""
        response = await client.post("/api/v1/auth/login", json={
            "email": "ghost@example.com",
            "password": "SomePass123",
        })
        assert response.json()["detail"] == "Credenciales inválidas"


class TestRefreshToken:
    """Tests para POST /api/v1/auth/refresh."""

    async def test_refresh_success(self, client: AsyncClient, test_user: User):
        """Refresh con token válido debe retornar nuevos tokens."""
        login = await client.post("/api/v1/auth/login", json={
            "email": test_user.email,
            "password": "TestPass123",
        })
        refresh_token = login.json()["refresh_token"]

        response = await client.post("/api/v1/auth/refresh", json={
            "refresh_token": refresh_token,
        })
        assert response.status_code == 200
        assert "access_token" in response.json()

    async def test_refresh_with_access_token_fails(self, client: AsyncClient, test_user: User):
        """Usar access token en el endpoint refresh debe retornar 401."""
        from src.core.security import create_access_token
        access_token = create_access_token(test_user.id)

        response = await client.post("/api/v1/auth/refresh", json={
            "refresh_token": access_token,
        })
        assert response.status_code == 401

    async def test_refresh_invalid_token(self, client: AsyncClient):
        """Token inválido debe retornar 401."""
        response = await client.post("/api/v1/auth/refresh", json={
            "refresh_token": "invalid.token.here",
        })
        assert response.status_code == 401