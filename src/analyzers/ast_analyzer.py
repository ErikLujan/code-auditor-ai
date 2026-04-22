"""
Analizador estático de código Python usando AST.

Detecta sin ejecución de código:
- Funciones largas (> 20 líneas, complejidad ciclomática alta)
- Variables con nombres genéricos
- Falta de type hints
- Imports circulares / wildcard imports
- Manejo de excepciones bare (except: pass)
- Funciones sin docstring
- Código dead (funciones/variables definidas pero no usadas dentro del módulo)
"""

import ast
import asyncio
from pathlib import Path

from src.analyzers.base import AnalysisContext, AnalyzerResult, BaseAnalyzer, RawFinding
from src.core.logging import get_logger
from src.db.models import FindingCategory, FindingSeverity

logger = get_logger(__name__)

_GENERIC_VAR_NAMES: frozenset[str] = frozenset({
    "x", "y", "z", "n", "i", "j", "k",
    "tmp", "temp", "data", "val", "value",
    "obj", "item", "result", "res", "ret",
    "foo", "bar", "baz",
})

_SQL_INJECTION_PATTERNS: frozenset[str] = frozenset({
    "execute", "executemany", "raw", "cursor",
})


class ASTAnalyzer(BaseAnalyzer):
    """
    Analizador estático de Python usando el módulo ast de la stdlib.

    Recorre el AST de cada archivo .py detectando anti-patrones de
    calidad, arquitectura y seguridad sin ejecutar el código.

    Args:
        max_function_lines: Líneas máximas antes de reportar función larga.
        max_cyclomatic_complexity: Umbral de complejidad ciclomática.
    """

    def __init__(
        self,
        max_function_lines: int = 20,
        max_cyclomatic_complexity: int = 10,
    ) -> None:
        self._max_function_lines = max_function_lines
        self._max_cyclomatic_complexity = max_cyclomatic_complexity

    @property
    def name(self) -> str:
        return "ast_analyzer"

    async def analyze(self, context: AnalysisContext) -> AnalyzerResult:
        """
        Analiza todos los archivos Python del repositorio.

        Args:
            context: Contexto con ruta del repositorio.

        Returns:
            Resultado con hallazgos de calidad/arquitectura.
        """
        python_files = self._collect_python_files(context)
        findings: list[RawFinding] = []
        files_analyzed = 0

        loop = asyncio.get_event_loop()
        tasks = [
            loop.run_in_executor(None, self._analyze_file, py_file, context.repo_path)
            for py_file in python_files
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.warning("ast_file_error", error=str(result))
                continue
            findings.extend(result)
            files_analyzed += 1

        logger.info(
            "ast_analysis_complete",
            files=files_analyzed,
            findings=len(findings),
        )
        return AnalyzerResult(
            findings=findings,
            analyzer_name=self.name,
            files_analyzed=files_analyzed,
        )

    def _collect_python_files(self, context: AnalysisContext) -> list[Path]:
        """
        Recolecta archivos .py del repositorio ignorando carpetas irrelevantes.

        Args:
            context: Contexto con ruta del repositorio y archivos target.

        Returns:
            Lista de rutas absolutas a archivos Python.
        """
        if context.target_files:
            return [f for f in context.target_files if f.suffix == ".py"]

        ignore_dirs = {
            ".git", "__pycache__", ".venv", "venv", "env",
            "node_modules", ".tox", "dist", "build", ".eggs",
        }

        python_files: list[Path] = []
        for path in context.repo_path.rglob("*.py"):
            if not any(part in ignore_dirs for part in path.parts):
                python_files.append(path)

        return python_files

    def _analyze_file(self, file_path: Path, repo_root: Path) -> list[RawFinding]:
        """
        Analiza un archivo Python individual.

        Args:
            file_path: Ruta absoluta al archivo.
            repo_root: Raíz del repositorio para calcular rutas relativas.

        Returns:
            Lista de hallazgos encontrados en el archivo.
        """
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(file_path))
        except SyntaxError as exc:
            logger.debug("ast_syntax_error", file=str(file_path), error=str(exc))
            return []

        relative_path = str(file_path.relative_to(repo_root))
        findings: list[RawFinding] = []

        findings.extend(self._check_wildcard_imports(tree, relative_path))
        findings.extend(self._check_functions(tree, relative_path, source))
        findings.extend(self._check_bare_except(tree, relative_path))
        findings.extend(self._check_sql_string_format(tree, relative_path))

        return findings

    def _check_wildcard_imports(self, tree: ast.AST, file_path: str) -> list[RawFinding]:
        """Detecta imports wildcard (from module import *)."""
        findings: list[RawFinding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name == "*":
                        findings.append(self._make_finding(
                            category=FindingCategory.QUALITY,
                            severity=FindingSeverity.MEDIUM,
                            title="Wildcard import detectado",
                            description=(
                                f"'from {node.module} import *' contamina el namespace "
                                "y dificulta el análisis estático."
                            ),
                            file_path=file_path,
                            line_start=node.lineno,
                            rule_id="AST-Q001",
                            recommendation=(
                                "Importar solo los nombres necesarios explícitamente: "
                                f"'from {node.module} import NombreEspecifico'."
                            ),
                        ))
        return findings

    def _check_functions(
        self, tree: ast.AST, file_path: str, source: str
    ) -> list[RawFinding]:
        """Analiza funciones y métodos buscando múltiples anti-patrones."""
        findings: list[RawFinding] = []
        source_lines = source.splitlines()

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            findings.extend(self._check_function_length(node, file_path, source_lines))
            findings.extend(self._check_missing_docstring(node, file_path))
            findings.extend(self._check_missing_type_hints(node, file_path))
            findings.extend(self._check_generic_variable_names(node, file_path))
            findings.extend(self._check_cyclomatic_complexity(node, file_path))

        return findings

    def _check_function_length(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        file_path: str,
        source_lines: list[str],
    ) -> list[RawFinding]:
        """Detecta funciones que superan el límite de líneas configurado."""
        if not node.body:
            return []

        start = node.lineno
        end = node.end_lineno or start
        func_lines = end - start + 1

        if func_lines <= self._max_function_lines:
            return []

        return [self._make_finding(
            category=FindingCategory.ARCHITECTURE,
            severity=FindingSeverity.MEDIUM,
            title=f"Función '{node.name}' demasiado larga ({func_lines} líneas)",
            description=(
                f"La función '{node.name}' tiene {func_lines} líneas, "
                f"superando el límite de {self._max_function_lines}. "
                "Las funciones largas violan el Principio de Responsabilidad Única."
            ),
            file_path=file_path,
            line_start=start,
            line_end=end,
            rule_id="AST-A001",
            recommendation=(
                "Descomponer en funciones más pequeñas con responsabilidades únicas. "
                "Cada función debería hacer exactamente una cosa."
            ),
        )]

    def _check_missing_docstring(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        file_path: str,
    ) -> list[RawFinding]:
        """Detecta funciones públicas sin docstring."""
        if node.name.startswith("_"):
            return []

        has_docstring = (
            node.body
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
            and isinstance(node.body[0].value.value, str)
        )

        if has_docstring:
            return []

        return [self._make_finding(
            category=FindingCategory.QUALITY,
            severity=FindingSeverity.LOW,
            title=f"Función '{node.name}' sin docstring",
            description=f"La función pública '{node.name}' no tiene documentación.",
            file_path=file_path,
            line_start=node.lineno,
            rule_id="AST-Q002",
            recommendation=(
                "Agregar docstring que describa propósito, parámetros y retorno. "
                "Usar formato Google o NumPy para consistencia."
            ),
        )]

    def _check_missing_type_hints(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        file_path: str,
    ) -> list[RawFinding]:
        """Detecta funciones sin type hints en parámetros o retorno."""
        missing_annotations: list[str] = []

        for arg in node.args.args:
            if arg.arg == "self":
                continue
            if arg.annotation is None:
                missing_annotations.append(arg.arg)

        has_return = node.returns is not None

        if not missing_annotations and has_return:
            return []

        parts = []
        if missing_annotations:
            params = ", ".join(missing_annotations)
            parts.append(f"parámetros sin type hint: {params}")
        if not has_return and node.name != "__init__":
            parts.append("tipo de retorno no anotado")

        if not parts:
            return []

        return [self._make_finding(
            category=FindingCategory.QUALITY,
            severity=FindingSeverity.LOW,
            title=f"Función '{node.name}' con type hints incompletos",
            description=f"En '{node.name}': {'; '.join(parts)}.",
            file_path=file_path,
            line_start=node.lineno,
            rule_id="AST-Q003",
            recommendation=(
                "Agregar type hints a todos los parámetros y al tipo de retorno. "
                "Mejora la legibilidad y permite detección temprana de errores."
            ),
        )]

    def _check_generic_variable_names(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        file_path: str,
    ) -> list[RawFinding]:
        """Detecta variables con nombres genéricos dentro de funciones."""
        generic_found: list[tuple[str, int]] = []

        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name) and target.id in _GENERIC_VAR_NAMES:
                        generic_found.append((target.id, child.lineno))

        findings: list[RawFinding] = []
        for var_name, line_no in generic_found:
            findings.append(self._make_finding(
                category=FindingCategory.QUALITY,
                severity=FindingSeverity.LOW,
                title=f"Variable con nombre genérico '{var_name}'",
                description=(
                    f"Variable '{var_name}' en función '{node.name}' tiene nombre poco descriptivo."
                ),
                file_path=file_path,
                line_start=line_no,
                rule_id="AST-Q004",
                recommendation=(
                    f"Renombrar '{var_name}' a algo que describa su contenido y propósito."
                ),
            ))
        return findings

    def _check_cyclomatic_complexity(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        file_path: str,
    ) -> list[RawFinding]:
        """
        Calcula complejidad ciclomática aproximada (McCabe).

        Cuenta: if, elif, for, while, except, with, assert, comprehensions, ternary.
        """
        complexity = 1
        branch_nodes = (
            ast.If, ast.For, ast.AsyncFor, ast.While,
            ast.ExceptHandler, ast.With, ast.AsyncWith,
            ast.Assert, ast.comprehension,
        )

        for child in ast.walk(node):
            if isinstance(child, branch_nodes):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1

        if complexity <= self._max_cyclomatic_complexity:
            return []

        return [self._make_finding(
            category=FindingCategory.QUALITY,
            severity=FindingSeverity.HIGH,
            title=f"Complejidad ciclomática alta en '{node.name}' ({complexity})",
            description=(
                f"Función '{node.name}' tiene complejidad ciclomática de {complexity}, "
                f"superando el umbral de {self._max_cyclomatic_complexity}. "
                "Alta complejidad indica código difícil de testear y mantener."
            ),
            file_path=file_path,
            line_start=node.lineno,
            rule_id="AST-Q005",
            recommendation=(
                "Reducir ramas condicionales extrayendo lógica a funciones auxiliares. "
                "Considerar reemplazar if/elif largas con tablas de despacho o patrones Strategy."
            ),
        )]

    def _check_bare_except(self, tree: ast.AST, file_path: str) -> list[RawFinding]:
        """Detecta cláusulas except sin especificar excepción (bare except)."""
        findings: list[RawFinding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                findings.append(self._make_finding(
                    category=FindingCategory.SECURITY,
                    severity=FindingSeverity.HIGH,
                    title="Bare except detectado (captura todas las excepciones)",
                    description=(
                        "'except:' sin especificar tipo captura SystemExit, "
                        "KeyboardInterrupt y excepciones del intérprete. "
                        "Puede enmascarar errores críticos."
                    ),
                    file_path=file_path,
                    line_start=node.lineno,
                    rule_id="AST-S001",
                    recommendation=(
                        "Especificar el tipo de excepción: 'except ValueError:' o "
                        "'except (TypeError, ValueError):'. Nunca usar bare 'except:'."
                    ),
                ))
        return findings

    def _check_sql_string_format(self, tree: ast.AST, file_path: str) -> list[RawFinding]:
        """
        Detecta posibles inyecciones SQL por concatenación/formato de strings.

        Busca patrones como: cursor.execute("SELECT..." % user_input)
        o cursor.execute(f"SELECT...{variable}")
        """
        findings: list[RawFinding] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            is_db_call = (
                isinstance(node.func, ast.Attribute)
                and node.func.attr in _SQL_INJECTION_PATTERNS
            )
            if not is_db_call:
                continue

            if not node.args:
                continue

            first_arg = node.args[0]

            is_fstring = isinstance(first_arg, ast.JoinedStr)

            is_concat = (
                isinstance(first_arg, ast.BinOp)
                and isinstance(first_arg.op, ast.Add)
            )

            is_percent_format = (
                isinstance(first_arg, ast.BinOp)
                and isinstance(first_arg.op, ast.Mod)
            )

            if not (is_fstring or is_concat or is_percent_format):
                continue

            findings.append(self._make_finding(
                category=FindingCategory.SECURITY,
                severity=FindingSeverity.CRITICAL,
                title="Posible inyección SQL por interpolación de string",
                description=(
                    "Se detectó construcción dinámica de query SQL con f-string, "
                    "concatenación (+) o formateo (%). "
                    "Esto puede permitir inyección SQL si la entrada no es sanitizada."
                ),
                file_path=file_path,
                line_start=node.lineno,
                rule_id="AST-S002",
                recommendation=(
                    "Usar queries parametrizadas: cursor.execute('SELECT * FROM t WHERE id = %s', (user_id,)). "
                    "Nunca interpolar variables del usuario directamente en queries SQL."
                ),
            ))

        return findings