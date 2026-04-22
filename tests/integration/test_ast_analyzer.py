"""
Tests unitarios para ASTAnalyzer.

Crea archivos Python en memoria y verifica que el analizador
detecte correctamente cada tipo de anti-patrón.
"""

import textwrap
from pathlib import Path

import pytest

from src.analyzers.ast_analyzer import ASTAnalyzer
from src.analyzers.base import AnalysisContext
from src.db.models import FindingCategory, FindingSeverity


@pytest.fixture
def analyzer() -> ASTAnalyzer:
    """ASTAnalyzer con umbrales bajos para facilitar el testing."""
    return ASTAnalyzer(max_function_lines=5, max_cyclomatic_complexity=3)


@pytest.fixture
def make_context(tmp_path: Path):
    """Factory de AnalysisContext que escribe archivos en tmp_path."""

    def _make(files: dict[str, str]) -> AnalysisContext:
        for filename, content in files.items():
            file_path = tmp_path / filename
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(textwrap.dedent(content), encoding="utf-8")
        return AnalysisContext(
            repo_path=tmp_path,
            repo_full_name="owner/repo",
            commit_sha="abc123",
        )

    return _make


# ── Función larga ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_detects_long_function(analyzer, make_context):
    """Función con más de max_function_lines debe generar finding MEDIUM."""
    context = make_context({
        "module.py": """
            def long_function():
                a = 1
                b = 2
                c = 3
                d = 4
                e = 5
                f = 6
                return a + b + c + d + e + f
        """
    })
    result = await analyzer.analyze(context)
    findings = [f for f in result.findings if f.rule_id == "AST-A001"]
    assert len(findings) >= 1
    assert findings[0].severity == FindingSeverity.MEDIUM
    assert findings[0].category == FindingCategory.ARCHITECTURE
    assert "long_function" in findings[0].title


@pytest.mark.asyncio
async def test_short_function_no_length_finding(analyzer, make_context):
    """Función corta no debe generar finding de longitud."""
    context = make_context({
        "module.py": """
            def short():
                return 42
        """
    })
    result = await analyzer.analyze(context)
    length_findings = [f for f in result.findings if f.rule_id == "AST-A001"]
    assert len(length_findings) == 0


# ── Docstring ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_detects_missing_docstring(analyzer, make_context):
    """Función pública sin docstring debe generar finding LOW."""
    context = make_context({
        "module.py": """
            def public_function(x: int) -> int:
                return x * 2
        """
    })
    result = await analyzer.analyze(context)
    doc_findings = [f for f in result.findings if f.rule_id == "AST-Q002"]
    assert len(doc_findings) >= 1
    assert doc_findings[0].severity == FindingSeverity.LOW


@pytest.mark.asyncio
async def test_private_function_no_docstring_finding(analyzer, make_context):
    """Función privada (_prefix) no debe generar finding de docstring."""
    context = make_context({
        "module.py": """
            def _private_helper(x):
                return x
        """
    })
    result = await analyzer.analyze(context)
    doc_findings = [f for f in result.findings if f.rule_id == "AST-Q002"]
    assert len(doc_findings) == 0


@pytest.mark.asyncio
async def test_function_with_docstring_no_finding(analyzer, make_context):
    """Función con docstring no debe generar finding AST-Q002."""
    context = make_context({
        "module.py": """
            def documented(x: int) -> int:
                \"\"\"Retorna el doble de x.\"\"\"
                return x * 2
        """
    })
    result = await analyzer.analyze(context)
    doc_findings = [f for f in result.findings if f.rule_id == "AST-Q002"]
    assert len(doc_findings) == 0


# ── Type hints ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_detects_missing_type_hints(analyzer, make_context):
    """Función sin type hints en parámetros debe generar finding LOW."""
    context = make_context({
        "module.py": """
            def no_hints(name, age):
                \"\"\"Función sin type hints.\"\"\"
                return f"{name}: {age}"
        """
    })
    result = await analyzer.analyze(context)
    hint_findings = [f for f in result.findings if f.rule_id == "AST-Q003"]
    assert len(hint_findings) >= 1
    assert "name" in hint_findings[0].description or "age" in hint_findings[0].description


@pytest.mark.asyncio
async def test_fully_annotated_function_no_hint_finding(analyzer, make_context):
    """Función completamente anotada no debe generar finding de type hints."""
    context = make_context({
        "module.py": """
            def annotated(name: str, age: int) -> str:
                \"\"\"Función anotada.\"\"\"
                return f"{name}: {age}"
        """
    })
    result = await analyzer.analyze(context)
    hint_findings = [f for f in result.findings if f.rule_id == "AST-Q003"]
    assert len(hint_findings) == 0


# ── Variables genéricas ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_detects_generic_variable_names(analyzer, make_context):
    """Variables con nombres genéricos deben generar finding LOW."""
    context = make_context({
        "module.py": """
            def process():
                \"\"\"Procesa datos.\"\"\"
                temp = get_data()
                data = transform(temp)
                return data
        """
    })
    result = await analyzer.analyze(context)
    generic_findings = [f for f in result.findings if f.rule_id == "AST-Q004"]
    assert len(generic_findings) >= 1


# ── Complejidad ciclomática ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_detects_high_cyclomatic_complexity(analyzer, make_context):
    """Función con complejidad > umbral debe generar finding HIGH."""
    context = make_context({
        "module.py": """
            def complex_func(a, b, c, d):
                \"\"\"Función muy compleja.\"\"\"
                if a:
                    if b:
                        if c:
                            if d:
                                return True
                return False
        """
    })
    result = await analyzer.analyze(context)
    complexity_findings = [f for f in result.findings if f.rule_id == "AST-Q005"]
    assert len(complexity_findings) >= 1
    assert complexity_findings[0].severity == FindingSeverity.HIGH


# ── Wildcard imports ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_detects_wildcard_import(analyzer, make_context):
    """Wildcard import debe generar finding MEDIUM."""
    context = make_context({
        "module.py": """
            from os.path import *
            from typing import Optional
        """
    })
    result = await analyzer.analyze(context)
    wildcard_findings = [f for f in result.findings if f.rule_id == "AST-Q001"]
    assert len(wildcard_findings) == 1
    assert wildcard_findings[0].severity == FindingSeverity.MEDIUM


# ── Bare except ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_detects_bare_except(analyzer, make_context):
    """Bare except debe generar finding HIGH de seguridad."""
    context = make_context({
        "module.py": """
            def risky():
                try:
                    do_something()
                except:
                    pass
        """
    })
    result = await analyzer.analyze(context)
    bare_findings = [f for f in result.findings if f.rule_id == "AST-S001"]
    assert len(bare_findings) == 1
    assert bare_findings[0].severity == FindingSeverity.HIGH
    assert bare_findings[0].category == FindingCategory.SECURITY


@pytest.mark.asyncio
async def test_specific_except_no_finding(analyzer, make_context):
    """Except específico no debe generar finding de bare except."""
    context = make_context({
        "module.py": """
            def safe():
                try:
                    do_something()
                except ValueError:
                    pass
        """
    })
    result = await analyzer.analyze(context)
    bare_findings = [f for f in result.findings if f.rule_id == "AST-S001"]
    assert len(bare_findings) == 0


# ── SQL injection ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_detects_sql_fstring_injection(analyzer, make_context):
    """f-string en cursor.execute debe generar finding CRITICAL."""
    context = make_context({
        "module.py": """
            def get_user(user_id):
                cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
        """
    })
    result = await analyzer.analyze(context)
    sql_findings = [f for f in result.findings if f.rule_id == "AST-S002"]
    assert len(sql_findings) >= 1
    assert sql_findings[0].severity == FindingSeverity.CRITICAL


@pytest.mark.asyncio
async def test_parameterized_query_no_finding(analyzer, make_context):
    """Query parametrizada no debe generar finding de SQL injection."""
    context = make_context({
        "module.py": """
            def get_user(user_id):
                cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        """
    })
    result = await analyzer.analyze(context)
    sql_findings = [f for f in result.findings if f.rule_id == "AST-S002"]
    assert len(sql_findings) == 0


# ── Archivos inválidos ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_skips_files_with_syntax_errors(analyzer, make_context):
    """Archivos con errores de sintaxis deben ser ignorados sin fallar."""
    context = make_context({
        "broken.py": "def broken(\n    # missing closing paren and body\n"
    })
    result = await analyzer.analyze(context)
    # No debe lanzar excepción; archivos rotos simplemente se omiten
    assert isinstance(result.findings, list)


@pytest.mark.asyncio
async def test_ignores_venv_directory(analyzer, tmp_path):
    """Archivos dentro de .venv no deben ser analizados."""
    venv_file = tmp_path / ".venv" / "lib" / "module.py"
    venv_file.parent.mkdir(parents=True)
    venv_file.write_text("from os.path import *\n")

    context = AnalysisContext(
        repo_path=tmp_path,
        repo_full_name="owner/repo",
        commit_sha="abc123",
    )
    result = await analyzer.analyze(context)
    # Findings deben ser 0 porque .venv está excluido
    assert all(".venv" not in f.file_path for f in result.findings)


# ── Resultado vacío ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_empty_repo_returns_empty_result(analyzer, tmp_path):
    """Repositorio sin archivos Python retorna resultado vacío sin error."""
    context = AnalysisContext(
        repo_path=tmp_path,
        repo_full_name="owner/empty",
        commit_sha="abc123",
    )
    result = await analyzer.analyze(context)
    assert result.findings == []
    assert result.files_analyzed == 0
    assert result.error is None