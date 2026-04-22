"""
Integración con GitHub para clonar repositorios y leer archivos.

Responsabilidades:
- Autenticar con PyGithub usando token OAuth.
- Validar permisos de acceso al repositorio.
- Clonar el repo de forma shallow a directorio temporal.
- Resolver el commit SHA actual de una rama.
- Limpiar el directorio temporal después del análisis.

Esta clase solo gestiona la integración con GitHub (SRP).
El análisis es responsabilidad de CodeAuditorAgent.
"""

import shutil
import subprocess
import tempfile
from pathlib import Path

from github import Github, GithubException, UnknownObjectException
from github.Repository import Repository as GithubRepository

from src.core.logging import get_logger

logger = get_logger(__name__)


class GitHubClient:
    """
    Cliente para interactuar con repositorios GitHub.

    Usa PyGithub para metadata y subprocess para clonar vía git.
    El clon es siempre shallow (--depth=1) para minimizar I/O.

    Args:
        token: Personal Access Token o OAuth token de GitHub.
        api_timeout: Timeout en segundos para requests a la API.
        max_repo_size_mb: Tamaño máximo del repositorio a clonar.
    """

    def __init__(
        self,
        token: str,
        api_timeout: int = 30,
        max_repo_size_mb: int = 500,
    ) -> None:
        self._github = Github(token, timeout=api_timeout)
        self._token = token
        self._max_repo_size_bytes = max_repo_size_mb * 1024 * 1024

    async def get_repository(self, full_name: str) -> GithubRepository:
        """
        Obtiene metadata de un repositorio GitHub.

        Args:
            full_name: Nombre en formato 'owner/repo'.

        Returns:
            Objeto Repository de PyGithub.

        Raises:
            ValueError: Si el repositorio no existe o no hay acceso.
        """
        try:
            repo = self._github.get_repo(full_name)
            _ = repo.default_branch
            return repo
        except UnknownObjectException:
            logger.warning("github_repo_not_found", full_name=full_name)
            raise ValueError(f"Repositorio '{full_name}' no encontrado o sin acceso")
        except GithubException as exc:
            logger.error("github_api_error", full_name=full_name, status=exc.status)
            raise ValueError(f"Error accediendo repositorio: {exc.data}") from exc

    async def resolve_commit_sha(
        self, full_name: str, ref: str = "HEAD"
    ) -> str:
        """
        Resuelve el SHA completo de un commit o referencia.

        Args:
            full_name: Nombre en formato 'owner/repo'.
            ref: Referencia a resolver ('HEAD', nombre de rama, o SHA).

        Returns:
            SHA completo del commit (40 chars).

        Raises:
            ValueError: Si la referencia no es válida.
        """
        try:
            repo = self._github.get_repo(full_name)

            if ref == "HEAD":
                ref = repo.default_branch

            # Si ya es un SHA de 40 chars, retornar directamente
            if len(ref) == 40 and all(c in "0123456789abcdef" for c in ref.lower()):
                return ref.lower()

            commit = repo.get_commit(ref)
            return commit.sha
        except GithubException as exc:
            logger.error("github_resolve_commit_error", ref=ref, error=str(exc))
            raise ValueError(f"No se pudo resolver referencia '{ref}': {exc}") from exc

    async def clone_repository(
        self,
        full_name: str,
        commit_sha: str,
        target_dir: Path | None = None,
    ) -> Path:
        """
        Clona un repositorio de forma shallow al directorio especificado.

        Realiza un clon con --depth=1 apuntando al commit específico.
        Si el target_dir es None, crea un directorio temporal.

        Args:
            full_name: Nombre en formato 'owner/repo'.
            commit_sha: SHA del commit a clonar.
            target_dir: Directorio destino (None = tempdir automático).

        Returns:
            Path al directorio del repositorio clonado.

        Raises:
            ValueError: Si el repositorio excede el tamaño máximo.
            RuntimeError: Si el clon falla.
        """
        await self._validate_repo_size(full_name)

        clone_dir = target_dir or Path(tempfile.mkdtemp(prefix="code-auditor-"))
        clone_path = clone_dir / full_name.replace("/", "_")

        clone_url = f"https://x-access-token:{self._token}@github.com/{full_name}.git"

        logger.info(
            "github_clone_start",
            full_name=full_name,
            commit=commit_sha[:8],
            target=str(clone_path),
        )

        try:
            result = subprocess.run(
                [
                    "git", "clone",
                    "--depth=1",
                    "--no-single-branch",
                    clone_url,
                    str(clone_path),
                ],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )

            if result.returncode != 0:
                safe_err = result.stderr.replace(self._token, "***")
                logger.error("github_clone_failed", error=safe_err)
                raise RuntimeError(f"git clone falló: {safe_err[:200]}")

            checkout_result = subprocess.run(
                ["git", "checkout", commit_sha],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                cwd=str(clone_path),
            )

            if checkout_result.returncode != 0:
                logger.warning(
                    "github_checkout_failed",
                    commit=commit_sha[:8],
                    error=checkout_result.stderr[:200],
                )

        except subprocess.TimeoutExpired as exc:
            logger.error("github_clone_timeout", full_name=full_name)
            self.cleanup_clone(clone_path)
            raise RuntimeError("Timeout clonando repositorio") from exc

        logger.info("github_clone_complete", path=str(clone_path))
        return clone_path

    def cleanup_clone(self, clone_path: Path) -> None:
        """
        Elimina el directorio del repositorio clonado.

        Args:
            clone_path: Ruta al directorio a eliminar.
        """
        if clone_path.exists():
            shutil.rmtree(clone_path, ignore_errors=True)
            logger.info("github_clone_cleanup", path=str(clone_path))

    async def _validate_repo_size(self, full_name: str) -> None:
        """
        Verifica que el repositorio no exceda el tamaño máximo configurado.

        Args:
            full_name: Nombre del repositorio.

        Raises:
            ValueError: Si el repositorio es demasiado grande.
        """
        try:
            repo = self._github.get_repo(full_name)
            size_bytes = (repo.size or 0) * 1024
            if size_bytes > self._max_repo_size_bytes:
                max_mb = self._max_repo_size_bytes / (1024 * 1024)
                actual_mb = size_bytes / (1024 * 1024)
                raise ValueError(
                    f"Repositorio demasiado grande: {actual_mb:.1f}MB (máximo {max_mb:.0f}MB)"
                )
        except GithubException as exc:
            logger.warning("github_size_check_failed", error=str(exc))

    def close(self) -> None:
        """Cierra la conexión con la API de GitHub."""
        self._github.close()