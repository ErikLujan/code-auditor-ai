"""
Tests de integración para AnalysisService.

Testea el flujo completo del servicio de análisis contra la BD de tests
(SQLite en memoria). GitHub y OpenAI se mockean completamente.

Usa el fixture `db_session` del conftest.py existente — NO crea
sesiones propias para evitar conflictos de event loop.
"""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient

from src.db.models import AnalysisStatus, FindingCategory, FindingSeverity
from src.db.repositories import AnalysisRepository, RepositoryRepository, UserRepository


# ── Fixtures locales ───────────────────────────────────────────────────────────

@pytest.fixture
def mock_github_client(tmp_path: Path):
    """
    GitHubClient mockeado que retorna un repo de prueba con vulnerabilidades reales.
    """
    repo_dir = tmp_path / "owner_testrepo"
    repo_dir.mkdir()

    (repo_dir / "vulnerable.py").write_text(
        "PASSWORD = 'hardcoded123'\n\n"
        "def get_user(user_id):\n"
        "    cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')\n\n"
        "def risky():\n"
        "    try:\n"
        "        pass\n"
        "    except:\n"
        "        pass\n"
    )
    (repo_dir / "clean.py").write_text(
        "def add(a: int, b: int) -> int:\n"
        '    """Retorna la suma."""\n'
        "    return a + b\n"
    )

    client_mock = MagicMock()
    client_mock.resolve_commit_sha = AsyncMock(
        return_value="abc123def456abc123def456abc123def456abc1"
    )
    client_mock.clone_repository = AsyncMock(return_value=repo_dir)
    client_mock.cleanup_clone = MagicMock()
    return client_mock


@pytest.fixture
def mock_llm_client():
    """LLMClient mockeado con hallazgo de arquitectura predefinido."""
    from src.agents.llm_client import LLMAnalysisResult

    llm_mock = MagicMock()
    llm_mock.analyze_code_architecture = AsyncMock(
        return_value=LLMAnalysisResult(
            findings=[
                {
                    "category": "architecture",
                    "severity": "medium",
                    "title": "Acoplamiento alto detectado",
                    "description": "El módulo tiene demasiadas dependencias.",
                    "file_path": "vulnerable.py",
                    "line_start": 1,
                    "line_end": None,
                    "rule_id": "LLM-A001",
                    "recommendation": "Usar inyección de dependencias.",
                }
            ],
            summary="Repositorio con problemas de seguridad.",
            tokens_used=450,
            model="gpt-3.5-turbo",
        )
    )
    return llm_mock


@pytest.fixture
def auditor_agent(mock_github_client, mock_llm_client):
    """CodeAuditorAgent con dependencias mockeadas."""
    from src.agents.code_auditor_agent import CodeAuditorAgent

    return CodeAuditorAgent(
        github_client=mock_github_client,
        llm_client=mock_llm_client,
    )


# ── Tests de AnalysisService ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_execute_analysis_completes_successfully(
    db_session,
    test_user,
    auditor_agent,
):
    """
    execute_analysis debe actualizar estado a COMPLETED y persistir findings.

    Usa db_session del conftest para operar sobre la misma BD de tests.
    """
    from src.services.analysis_service import AnalysisService

    # Crear repositorio y análisis directamente en BD
    repo_db = RepositoryRepository(db_session)
    repo = await repo_db.create(
        owner_id=test_user.id,
        github_url="https://github.com/owner/testrepo",
        full_name="owner/testrepo",
    )

    analysis_db = AnalysisRepository(db_session)
    analysis = await analysis_db.create(
        repository_id=repo.id,
        commit_sha="abc123",
    )
    await db_session.flush()

    service = AnalysisService(session=db_session, agent=auditor_agent)
    result = await service.execute_analysis(
        analysis_id=analysis.id,
        repo_full_name="owner/testrepo",
        commit_sha="abc123",
    )

    assert result.status == AnalysisStatus.COMPLETED
    assert result.total_findings > 0
    assert result.duration_seconds is not None
    assert result.duration_seconds >= 0
    assert result.completed_at is not None


@pytest.mark.asyncio
async def test_execute_analysis_persists_findings(
    db_session,
    test_user,
    auditor_agent,
):
    """Los findings deben estar persistidos en BD después del análisis."""
    from src.db.repositories import FindingRepository
    from src.services.analysis_service import AnalysisService

    repo_db = RepositoryRepository(db_session)
    repo = await repo_db.create(
        owner_id=test_user.id,
        github_url="https://github.com/owner/repo-findings",
        full_name="owner/repo-findings",
    )

    analysis_db = AnalysisRepository(db_session)
    analysis = await analysis_db.create(
        repository_id=repo.id,
        commit_sha="def456",
    )
    await db_session.flush()

    service = AnalysisService(session=db_session, agent=auditor_agent)
    await service.execute_analysis(
        analysis_id=analysis.id,
        repo_full_name="owner/repo-findings",
        commit_sha="def456",
    )

    finding_db = FindingRepository(db_session)
    findings = await finding_db.list_by_analysis(analysis.id)

    assert len(findings) > 0
    for f in findings:
        assert f.analysis_id == analysis.id
        assert f.title
        assert f.description
        assert f.recommendation


@pytest.mark.asyncio
async def test_execute_analysis_marks_failed_on_github_error(
    db_session,
    test_user,
):
    """Si GitHub falla, el análisis debe quedar en estado FAILED."""
    from src.agents.code_auditor_agent import CodeAuditorAgent
    from src.agents.llm_client import LLMAnalysisResult
    from src.services.analysis_service import AnalysisService

    failing_github = MagicMock()
    failing_github.resolve_commit_sha = AsyncMock(
        side_effect=RuntimeError("GitHub API error: rate limit exceeded")
    )

    failing_github.clone_repository = AsyncMock(
        side_effect=RuntimeError("GitHub clone error")
    )

    failing_github.cleanup_clone = MagicMock()

    mock_llm = MagicMock()
    mock_llm.analyze_code_architecture = AsyncMock(
        return_value=LLMAnalysisResult(findings=[], summary="", tokens_used=0, model="")
    )

    agent = CodeAuditorAgent(
        github_client=failing_github,
        llm_client=mock_llm,
    )

    repo_db = RepositoryRepository(db_session)
    repo = await repo_db.create(
        owner_id=test_user.id,
        github_url="https://github.com/owner/failing-repo",
        full_name="owner/failing-repo",
    )

    analysis_db = AnalysisRepository(db_session)
    analysis = await analysis_db.create(
        repository_id=repo.id,
        commit_sha="abc123",
    )
    await db_session.flush()

    service = AnalysisService(session=db_session, agent=agent)
    result = await service.execute_analysis(
        analysis_id=analysis.id,
        repo_full_name="owner/failing-repo",
        commit_sha="abc123",
    )

    assert result.status == AnalysisStatus.FAILED
    assert result.error_message is not None
    assert "GitHub" in result.error_message or "rate limit" in result.error_message.lower()


@pytest.mark.asyncio
async def test_execute_analysis_counts_critical_and_high(
    db_session,
    test_user,
):
    """critical_count y high_count deben reflejar los findings persistidos."""
    from src.agents.code_auditor_agent import CodeAuditorAgent
    from src.agents.llm_client import LLMAnalysisResult
    from src.services.analysis_service import AnalysisService

    mock_llm = MagicMock()
    mock_llm.analyze_code_architecture = AsyncMock(
        return_value=LLMAnalysisResult(
            findings=[
                {
                    "category": "security",
                    "severity": "critical",
                    "title": "Critical LLM finding",
                    "description": "Very bad",
                    "file_path": "app.py",
                    "line_start": 1,
                    "rule_id": "LLM-001",
                    "recommendation": "Fix now",
                },
                {
                    "category": "quality",
                    "severity": "low",
                    "title": "Low LLM finding",
                    "description": "Minor",
                    "file_path": "app.py",
                    "line_start": 2,
                    "rule_id": "LLM-002",
                    "recommendation": "Fix eventually",
                },
            ],
            summary="Mixed findings",
            tokens_used=200,
            model="gpt-3.5-turbo",
        )
    )

    tmp_repo = MagicMock()
    import tempfile, os
    tmpdir = Path(tempfile.mkdtemp())
    (tmpdir / "app.py").write_text(
        "PASSWORD = 'hardcoded'\n"
        "def bad():\n"
        "    try: pass\n"
        "    except: pass\n"
    )
    mock_github = MagicMock()
    mock_github.resolve_commit_sha = AsyncMock(return_value="a" * 40)
    mock_github.clone_repository = AsyncMock(return_value=tmpdir)
    mock_github.cleanup_clone = MagicMock()

    agent = CodeAuditorAgent(github_client=mock_github, llm_client=mock_llm)

    repo_db = RepositoryRepository(db_session)
    repo = await repo_db.create(
        owner_id=test_user.id,
        github_url="https://github.com/owner/counts-repo",
        full_name="owner/counts-repo",
    )

    analysis_db = AnalysisRepository(db_session)
    analysis = await analysis_db.create(
        repository_id=repo.id,
        commit_sha="HEAD",
    )
    await db_session.flush()

    service = AnalysisService(session=db_session, agent=agent)
    result = await service.execute_analysis(
        analysis_id=analysis.id,
        repo_full_name="owner/counts-repo",
        commit_sha="HEAD",
    )

    assert result.status == AnalysisStatus.COMPLETED
    assert result.critical_count >= 1
    assert result.total_findings >= 2


# ── Tests de endpoint HTTP con background mockeado ────────────────────────────

@pytest.mark.asyncio
async def test_create_analysis_endpoint_queues_background_task(
    client: AsyncClient,
    test_repository,
    auth_headers: dict,
):
    """
    POST /analyses debe retornar 201 PENDING y encolar el background task.

    El background task se mockea para no ejecutar análisis real.
    """
    with patch(
        "src.api.routers.analysis_router.run_analysis_background",
        new=AsyncMock(),
    ) as mock_bg:
        response = await client.post(
            "/api/v1/analyses",
            json={
                "repository_id": str(test_repository.id),
                "commit_sha": "abcdef123456",
            },
            headers=auth_headers,
        )

    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "pending"
    assert data["commit_sha"] == "abcdef123456"