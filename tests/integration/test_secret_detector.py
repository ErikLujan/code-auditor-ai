"""
Tests unitarios para SecretDetector.

Verifica la detección de cada tipo de secreto soportado
y que los falsos positivos comunes sean evitados.
"""

import textwrap
from pathlib import Path

import pytest

from src.analyzers.base import AnalysisContext
from src.analyzers.secret_detector import SecretDetector
from src.db.models import FindingSeverity


@pytest.fixture
def detector() -> SecretDetector:
    return SecretDetector()


@pytest.fixture
def make_context(tmp_path: Path):
    def _make(files: dict[str, str]) -> AnalysisContext:
        for filename, content in files.items():
            file_path = tmp_path / filename
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(textwrap.dedent(content))
        return AnalysisContext(
            repo_path=tmp_path,
            repo_full_name="owner/repo",
            commit_sha="abc123",
        )
    return _make


# ── Detección de secretos ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_detects_openai_api_key(detector, make_context):
    """OpenAI API key hardcodeada debe generar finding CRITICAL."""
    context = make_context({
        "config.py": 'OPENAI_KEY = "sk-abcdefghijklmnopqrstuvwxyz1234567890abcd"'
    })
    result = await detector.analyze(context)
    findings = [f for f in result.findings if f.rule_id == "SEC-S003"]
    assert len(findings) >= 1
    assert findings[0].severity == FindingSeverity.CRITICAL


@pytest.mark.asyncio
async def test_detects_aws_access_key(detector, make_context):
    """AWS Access Key ID debe generar finding CRITICAL."""
    context = make_context({
        "aws_config.py": 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'
    })
    result = await detector.analyze(context)
    findings = [f for f in result.findings if f.rule_id == "SEC-S001"]
    assert len(findings) >= 1
    assert findings[0].severity == FindingSeverity.CRITICAL


@pytest.mark.asyncio
async def test_detects_github_personal_access_token(detector, make_context):
    """GitHub PAT debe generar finding CRITICAL."""
    context = make_context({
        "github.py": 'TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz123456789012"'
    })
    result = await detector.analyze(context)
    findings = [f for f in result.findings if f.rule_id == "SEC-S004"]
    assert len(findings) >= 1


@pytest.mark.asyncio
async def test_detects_postgres_connection_string(detector, make_context):
    """Connection string con credenciales debe generar finding CRITICAL."""
    context = make_context({
        "settings.py": 'DB_URL = "postgresql://admin:supersecret123@db.example.com:5432/mydb"'
    })
    result = await detector.analyze(context)
    findings = [f for f in result.findings if f.rule_id == "SEC-S008"]
    assert len(findings) >= 1
    assert findings[0].severity == FindingSeverity.CRITICAL


@pytest.mark.asyncio
async def test_detects_hardcoded_password(detector, make_context):
    """Password hardcodeada debe generar finding HIGH."""
    context = make_context({
        "auth.py": 'ADMIN_PASSWORD = "mysupersecretpassword123"'
    })
    result = await detector.analyze(context)
    findings = [f for f in result.findings if f.rule_id == "SEC-S006"]
    assert len(findings) >= 1
    assert findings[0].severity == FindingSeverity.HIGH


@pytest.mark.asyncio
async def test_detects_private_key_pem(detector, make_context):
    """Bloque PEM de clave privada debe generar finding CRITICAL."""
    context = make_context({
        "keys.py": '"""-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"""'
    })
    result = await detector.analyze(context)
    findings = [f for f in result.findings if f.rule_id == "SEC-S007"]
    assert len(findings) >= 1


# ── Redacción de secretos ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_secret_values_are_redacted_in_description(detector, make_context):
    """El valor del secreto no debe aparecer completo en la descripción."""
    secret = "sk-abcdefghijklmnopqrstuvwxyz1234567890abcdefgh"
    context = make_context({"config.py": f'KEY = "{secret}"'})
    result = await detector.analyze(context)

    for finding in result.findings:
        assert secret not in finding.description, (
            "El secreto completo no debe aparecer en el reporte"
        )


# ── Archivos excluidos ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ignores_env_example_file(detector, make_context):
    """El archivo .env.example no debe ser escaneado."""
    context = make_context({
        ".env.example": "OPENAI_API_KEY=sk-your-api-key-here"
    })
    result = await detector.analyze(context)
    assert all(".env.example" not in f.file_path for f in result.findings)


@pytest.mark.asyncio
async def test_ignores_git_directory(detector, make_context):
    """El directorio .git no debe ser escaneado."""
    context = make_context({
        ".git/config": "[credential]\n    helper = store\npassword = supersecret"
    })
    result = await detector.analyze(context)
    assert all(".git" not in f.file_path for f in result.findings)


@pytest.mark.asyncio
async def test_scans_multiple_file_types(detector, make_context):
    """Debe escanear .py, .yaml y .env en el mismo análisis."""
    context = make_context({
        "app.py": 'api_key = "sk-testapikey12345678901234567890123456789012"',
        "config.yaml": "openai_key: sk-yamlkey123456789012345678901234567890",
        ".env": "SECRET_KEY=supersecretvalue123456789",
    })
    result = await detector.analyze(context)
    assert result.files_analyzed >= 2


# ── Redact helper (vía instancia) ──────────────────────────────────────────────

def test_redact_short_secret(detector):
    assert detector._redact_secret("abc") == "****"


def test_redact_long_secret(detector):
    result = detector._redact_secret("AKIAIOSFODNN7EXAMPLE")
    assert result.startswith("AKIA")
    assert result.endswith("MPLE")
    assert "AKIAIOSFODNN7EXAMPLE" not in result