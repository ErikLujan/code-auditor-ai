"""
Tests de integración para endpoints de repositorios y análisis.

NOTA IMPORTANTE: Los tests de create_analysis mockean run_analysis_background
para evitar que el background task intente conectarse a GitHub/OpenAI durante
los tests. El análisis real se testea en test_analysis_service.py.
"""

import math
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient

from src.db.models import Repository


class TestRepositoryEndpoints:
    """Tests de endpoints CRUD de repositorios."""

    async def test_register_repository_success(
        self,
        client: AsyncClient,
        auth_headers: dict,
    ):
        """Registrar repositorio válido debe retornar 201 con datos del repo."""
        response = await client.post(
            "/api/v1/repositories",
            json={"github_url": "https://github.com/testowner/testrepo"},
            headers=auth_headers,
        )
        assert response.status_code == 201
        data = response.json()
        assert data["github_url"] == "https://github.com/testowner/testrepo"
        assert data["full_name"] == "testowner/testrepo"
        assert "id" in data

    async def test_register_duplicate_repository_returns_409(
        self,
        client: AsyncClient,
        auth_headers: dict,
    ):
        """Registrar el mismo repositorio dos veces debe retornar 409."""
        payload = {"github_url": "https://github.com/owner/duplicate-repo"}
        await client.post("/api/v1/repositories", json=payload, headers=auth_headers)
        response = await client.post("/api/v1/repositories", json=payload, headers=auth_headers)
        assert response.status_code == 409

    async def test_register_repository_invalid_url_returns_422(
        self,
        client: AsyncClient,
        auth_headers: dict,
    ):
        """URL que no es de GitHub debe retornar 422."""
        response = await client.post(
            "/api/v1/repositories",
            json={"github_url": "https://gitlab.com/owner/repo"},
            headers=auth_headers,
        )
        assert response.status_code == 422

    async def test_register_repository_requires_auth(self, client: AsyncClient):
        """Sin token JWT debe retornar 401."""
        response = await client.post(
            "/api/v1/repositories",
            json={"github_url": "https://github.com/owner/repo"},
        )
        assert response.status_code == 401

    async def test_list_repositories_success(
        self,
        client: AsyncClient,
        test_repository: Repository,
        auth_headers: dict,
    ):
        """Listar repositorios debe retornar el repo de prueba."""
        response = await client.get("/api/v1/repositories", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert data["total"] >= 1
        ids = [r["id"] for r in data["items"]]
        assert test_repository.id in ids

    async def test_get_repository_by_id_success(
        self,
        client: AsyncClient,
        test_repository: Repository,
        auth_headers: dict,
    ):
        """GET repositorio por ID debe retornar datos correctos."""
        response = await client.get(
            f"/api/v1/repositories/{test_repository.id}",
            headers=auth_headers,
        )
        assert response.status_code == 200
        assert response.json()["id"] == test_repository.id

    async def test_get_repository_not_found_returns_404(
        self,
        client: AsyncClient,
        auth_headers: dict,
    ):
        """Repositorio inexistente debe retornar 404."""
        response = await client.get(
            "/api/v1/repositories/00000000-0000-0000-0000-000000000000",
            headers=auth_headers,
        )
        assert response.status_code == 404


class TestAnalysisEndpoints:
    """Tests de endpoints de análisis."""

    async def test_create_analysis_success(
        self,
        client: AsyncClient,
        test_repository: Repository,
        auth_headers: dict,
    ):
        """
        Crear análisis sobre repo propio debe retornar 201 en estado PENDING.

        El background task se mockea para evitar ejecución real durante tests.
        """
        with patch(
            "src.api.routers.analysis_router.run_analysis_background",
            new=AsyncMock(),
        ):
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

    async def test_create_analysis_for_unknown_repo_returns_404(
        self,
        client: AsyncClient,
        auth_headers: dict,
    ):
        """Análisis sobre repositorio inexistente debe retornar 404."""
        with patch(
            "src.api.routers.analysis_router.run_analysis_background",
            new=AsyncMock(),
        ):
            response = await client.post(
                "/api/v1/analyses",
                json={"repository_id": "00000000-0000-0000-0000-000000000000"},
                headers=auth_headers,
            )
        assert response.status_code == 404

    async def test_get_analysis_success(
        self,
        client: AsyncClient,
        test_repository: Repository,
        auth_headers: dict,
    ):
        """GET análisis debe retornar detalle con findings vacíos."""
        # Crear análisis sin ejecutarlo (background mockeado)
        with patch(
            "src.api.routers.analysis_router.run_analysis_background",
            new=AsyncMock(),
        ):
            create = await client.post(
                "/api/v1/analyses",
                json={"repository_id": test_repository.id},
                headers=auth_headers,
            )
        assert create.status_code == 201
        analysis_id = create.json()["id"]

        response = await client.get(
            f"/api/v1/analyses/{analysis_id}",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == analysis_id
        assert data["status"] == "pending"
        assert data["findings"] == []

    async def test_get_analysis_not_found_returns_404(
        self,
        client: AsyncClient,
        auth_headers: dict,
    ):
        """Análisis inexistente debe retornar 404."""
        response = await client.get(
            "/api/v1/analyses/00000000-0000-0000-0000-000000000000",
            headers=auth_headers,
        )
        assert response.status_code == 404

    async def test_list_analyses(
        self,
        client: AsyncClient,
        test_repository: Repository,
        auth_headers: dict,
    ):
        """Listar análisis debe retornar los análisis del repositorio."""
        # Crear un análisis sin ejecutarlo
        with patch(
            "src.api.routers.analysis_router.run_analysis_background",
            new=AsyncMock(),
        ):
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
        data = response.json()
        assert data["total"] >= 1

    async def test_create_analysis_default_commit_sha(
        self,
        client: AsyncClient,
        test_repository: Repository,
        auth_headers: dict,
    ):
        """Sin commit_sha explícito debe usar 'HEAD'."""
        with patch(
            "src.api.routers.analysis_router.run_analysis_background",
            new=AsyncMock(),
        ):
            response = await client.post(
                "/api/v1/analyses",
                json={"repository_id": test_repository.id},
                headers=auth_headers,
            )
        assert response.status_code == 201
        assert response.json()["commit_sha"] == "HEAD"