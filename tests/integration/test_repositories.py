"""
Tests de integración para endpoints de repositorios y análisis.

Prueba CRUD de repositorios y creación de análisis
con autenticación y validaciones de ownership.
"""

import pytest
from httpx import AsyncClient

from src.db.models import Repository, User


class TestRepositoryEndpoints:
    """Tests para endpoints de /api/v1/repositories."""

    async def test_register_repository_success(
        self, client: AsyncClient, test_user: User, auth_headers: dict
    ):
        """Registro de repo válido debe retornar 201."""
        response = await client.post(
            "/api/v1/repositories",
            json={"github_url": "https://github.com/owner/myrepo"},
            headers=auth_headers,
        )
        assert response.status_code == 201
        data = response.json()
        assert data["github_url"] == "https://github.com/owner/myrepo"
        assert data["full_name"] == "owner/myrepo"

    async def test_register_repository_invalid_url(
        self, client: AsyncClient, auth_headers: dict
    ):
        """URL no GitHub debe retornar 422."""
        response = await client.post(
            "/api/v1/repositories",
            json={"github_url": "https://gitlab.com/owner/repo"},
            headers=auth_headers,
        )
        assert response.status_code == 422

    async def test_register_repository_duplicate(
        self, client: AsyncClient, test_repository: Repository, auth_headers: dict
    ):
        """Registrar repo duplicado debe retornar 409."""
        response = await client.post(
            "/api/v1/repositories",
            json={"github_url": test_repository.github_url},
            headers=auth_headers,
        )
        assert response.status_code == 409

    async def test_register_repository_unauthenticated(self, client: AsyncClient):
        """Request sin token debe retornar 401."""
        response = await client.post(
            "/api/v1/repositories",
            json={"github_url": "https://github.com/owner/repo"},
        )
        assert response.status_code == 401

    async def test_list_repositories(
        self, client: AsyncClient, test_repository: Repository, auth_headers: dict
    ):
        """Listar repos debe retornar el repositorio del usuario."""
        response = await client.get("/api/v1/repositories", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 1
        assert any(r["id"] == test_repository.id for r in data["items"])

    async def test_get_repository_success(
        self, client: AsyncClient, test_repository: Repository, auth_headers: dict
    ):
        """GET por ID debe retornar el repositorio correcto."""
        response = await client.get(
            f"/api/v1/repositories/{test_repository.id}",
            headers=auth_headers,
        )
        assert response.status_code == 200
        assert response.json()["id"] == test_repository.id

    async def test_get_repository_not_found(
        self, client: AsyncClient, auth_headers: dict
    ):
        """GET con ID inexistente debe retornar 404."""
        response = await client.get(
            "/api/v1/repositories/00000000-0000-0000-0000-000000000000",
            headers=auth_headers,
        )
        assert response.status_code == 404

    async def test_cannot_access_other_users_repository(
        self,
        client: AsyncClient,
        test_repository: Repository,
        test_superuser: User,
    ):
        """Usuario no propietario no debe poder ver el repositorio."""
        from src.core.security import create_access_token
        other_headers = {"Authorization": f"Bearer {create_access_token(test_superuser.id)}"}

        response = await client.get(
            f"/api/v1/repositories/{test_repository.id}",
            headers=other_headers,
        )
        assert response.status_code == 404


class TestAnalysisEndpoints:
    """Tests para endpoints de /api/v1/analyses."""

    async def test_create_analysis_success(
        self,
        client: AsyncClient,
        test_repository: Repository,
        auth_headers: dict,
    ):
        """Crear análisis sobre repo propio debe retornar 201 en estado PENDING."""
        response = await client.post(
            "/api/v1/analyses",
            json={
                "repository_id": test_repository.id,
                "commit_sha": "abc1234",
            },
            headers=auth_headers,
        )
        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "pending"
        assert data["repository_id"] == test_repository.id
        assert data["commit_sha"] == "abc1234"

    async def test_create_analysis_invalid_commit_sha(
        self,
        client: AsyncClient,
        test_repository: Repository,
        auth_headers: dict,
    ):
        """SHA con caracteres no hexadecimales debe retornar 422."""
        response = await client.post(
            "/api/v1/analyses",
            json={
                "repository_id": test_repository.id,
                "commit_sha": "xyz-invalid!",
            },
            headers=auth_headers,
        )
        assert response.status_code == 422

    async def test_create_analysis_unauthorized_repo(
        self,
        client: AsyncClient,
        test_repository: Repository,
        test_superuser: User,
    ):
        """Crear análisis sobre repo ajeno debe retornar 404."""
        from src.core.security import create_access_token
        other_headers = {"Authorization": f"Bearer {create_access_token(test_superuser.id)}"}

        response = await client.post(
            "/api/v1/analyses",
            json={"repository_id": test_repository.id},
            headers=other_headers,
        )
        assert response.status_code == 404

    async def test_get_analysis_success(
        self,
        client: AsyncClient,
        test_repository: Repository,
        auth_headers: dict,
    ):
        """GET análisis debe retornar detalle con findings vacíos."""
        create = await client.post(
            "/api/v1/analyses",
            json={"repository_id": test_repository.id},
            headers=auth_headers,
        )
        analysis_id = create.json()["id"]

        response = await client.get(
            f"/api/v1/analyses/{analysis_id}",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == analysis_id
        assert data["findings"] == []

    async def test_list_analyses(
        self,
        client: AsyncClient,
        test_repository: Repository,
        auth_headers: dict,
    ):
        """Listar análisis debe retornar los análisis del repositorio."""
        await client.post(
            "/api/v1/analyses",
            json={"repository_id": test_repository.id},
            headers=auth_headers,
        )

        response = await client.get(
            f"/api/v1/analyses?repository_id={test_repository.id}",
            headers=auth_headers,
        )
        assert response.status_code == 200
        assert response.json()["total"] >= 1