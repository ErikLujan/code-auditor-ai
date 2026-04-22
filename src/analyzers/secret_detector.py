"""
Detector de secretos hardcodeados en código fuente.

Analiza archivos de texto buscando patrones que sugieren credenciales,
tokens o claves API expuestas directamente en el código.

No ejecuta el código — solo análisis estático basado en regex.
"""

import asyncio
import re
from dataclasses import dataclass
from pathlib import Path

from src.analyzers.base import AnalysisContext, AnalyzerResult, BaseAnalyzer, RawFinding
from src.core.logging import get_logger
from src.db.models import FindingCategory, FindingSeverity

logger = get_logger(__name__)


@dataclass(frozen=True)
class SecretPattern:
    """Define un patrón de secreto a detectar."""

    rule_id: str
    name: str
    pattern: re.Pattern[str]
    severity: FindingSeverity
    recommendation: str


_SECRET_PATTERNS: list[SecretPattern] = [
    SecretPattern(
        rule_id="SEC-S001",
        name="AWS Access Key",
        pattern=re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])", re.MULTILINE),
        severity=FindingSeverity.CRITICAL,
        recommendation="Revocar la key inmediatamente en AWS IAM y reemplazar por variable de entorno.",
    ),
    SecretPattern(
        rule_id="SEC-S002",
        name="AWS Secret Key",
        pattern=re.compile(
            r"(?i)(aws_secret_access_key|aws_secret)\s*[=:]\s*['\"]?([A-Za-z0-9/+]{40})['\"]?",
            re.MULTILINE,
        ),
        severity=FindingSeverity.CRITICAL,
        recommendation="Revocar en AWS IAM y usar AWS Secrets Manager o variable de entorno.",
    ),
    SecretPattern(
        rule_id="SEC-S003",
        name="OpenAI API Key",
        pattern=re.compile(r"sk-[A-Za-z0-9]{20,50}", re.MULTILINE),
        severity=FindingSeverity.CRITICAL,
        recommendation="Revocar en platform.openai.com y cargar desde variable de entorno OPENAI_API_KEY.",
    ),
    SecretPattern(
        rule_id="SEC-S004",
        name="GitHub Personal Access Token",
        pattern=re.compile(r"gh[pousr]_[A-Za-z0-9]{36,255}", re.MULTILINE),
        severity=FindingSeverity.CRITICAL,
        recommendation="Revocar token en GitHub Settings y usar secrets de repositorio/entorno.",
    ),
    SecretPattern(
        rule_id="SEC-S005",
        name="Generic API Key assignment",
        pattern=re.compile(
            r"(?i)(api[_\-]?key|apikey|access[_\-]?token|secret[_\-]?key)\s*[=:]\s*['\"]([A-Za-z0-9/+_\-]{16,})['\"]",
            re.MULTILINE,
        ),
        severity=FindingSeverity.HIGH,
        recommendation=(
            "Mover el valor a variable de entorno y cargarlo con os.environ.get() "
            "o pydantic-settings. Nunca hardcodear secretos en el código fuente."
        ),
    ),
    SecretPattern(
        rule_id="SEC-S006",
        name="Password hardcodeada",
        pattern=re.compile(
            r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{6,})['\"]",
            re.MULTILINE,
        ),
        severity=FindingSeverity.HIGH,
        recommendation=(
            "Nunca hardcodear contraseñas. Usar variables de entorno o un gestor de secretos."
        ),
    ),
    SecretPattern(
        rule_id="SEC-S007",
        name="Private key PEM block",
        pattern=re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", re.MULTILINE),
        severity=FindingSeverity.CRITICAL,
        recommendation=(
            "Remover la clave privada del código. Cargar desde archivo externo "
            "excluido del control de versiones (.gitignore)."
        ),
    ),
    SecretPattern(
        rule_id="SEC-S008",
        name="Database connection string con credenciales",
        pattern=re.compile(
            r"(?i)(postgres|postgresql|mysql|mongodb)://[A-Za-z0-9_\-]+:[^@\s\"']{3,}@",
            re.MULTILINE,
        ),
        severity=FindingSeverity.CRITICAL,
        recommendation=(
            "Mover la connection string completa a variable de entorno DATABASE_URL. "
            "Usar pydantic-settings para validar el formato."
        ),
    ),
    SecretPattern(
        rule_id="SEC-S009",
        name="JWT Secret hardcodeado",
        pattern=re.compile(
            r"(?i)(jwt[_\-]?secret|secret[_\-]?key)\s*[=:]\s*['\"]([A-Za-z0-9@#$%^&*_\-]{8,})['\"]",
            re.MULTILINE,
        ),
        severity=FindingSeverity.CRITICAL,
        recommendation=(
            "Generar un secret aleatorio con 'openssl rand -hex 32' "
            "y cargarlo desde variable de entorno JWT_SECRET_KEY."
        ),
    ),
    SecretPattern(
        rule_id="SEC-S010",
        name="Stripe API Key",
        pattern=re.compile(r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}", re.MULTILINE),
        severity=FindingSeverity.CRITICAL,
        recommendation="Revocar en dashboard.stripe.com y usar variables de entorno.",
    ),
]

_SCANNABLE_EXTENSIONS: frozenset[str] = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".env", ".yaml", ".yml", ".json", ".toml",
    ".cfg", ".ini", ".conf", ".sh", ".bash",
    ".tf", ".tfvars", ".rb", ".go", ".java",
})

_IGNORE_PATTERNS: frozenset[str] = frozenset({
    ".git", "__pycache__", ".venv", "venv",
    "node_modules", "dist", "build",
    ".env.example",
})

_MAX_FILE_SIZE_BYTES: int = 5 * 1024 * 1024


class SecretDetector(BaseAnalyzer):
    """
    Detector de secretos hardcodeados usando análisis de patrones regex.

    Escanea todos los archivos de texto del repositorio buscando
    credenciales, tokens y claves expuestas directamente en el código.

    Implementa BaseAnalyzer — completamente intercambiable con otros
    analizadores gracias al principio de sustitución de Liskov.
    """

    @property
    def name(self) -> str:
        return "secret_detector"

    async def analyze(self, context: AnalysisContext) -> AnalyzerResult:
        """
        Escanea el repositorio buscando secretos hardcodeados.

        Args:
            context: Contexto con ruta del repositorio.

        Returns:
            Resultado con hallazgos de seguridad encontrados.
        """
        scannable_files = self._collect_scannable_files(context)
        findings: list[RawFinding] = []
        files_analyzed = 0

        loop = asyncio.get_event_loop()
        tasks = [
            loop.run_in_executor(None, self._scan_file, file_path, context.repo_path)
            for file_path in scannable_files
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.warning("secret_scan_file_error", error=str(result))
                continue
            findings.extend(result)
            files_analyzed += 1

        logger.info(
            "secret_scan_complete",
            files=files_analyzed,
            findings=len(findings),
        )
        return AnalyzerResult(
            findings=findings,
            analyzer_name=self.name,
            files_analyzed=files_analyzed,
        )

    def _collect_scannable_files(self, context: AnalysisContext) -> list[Path]:
        """
        Recolecta archivos con extensiones de texto del repositorio.

        Args:
            context: Contexto con ruta del repositorio.

        Returns:
            Lista de rutas a archivos escaneables.
        """
        if context.target_files:
            return [
                f for f in context.target_files
                if f.suffix.lower() in _SCANNABLE_EXTENSIONS
            ]

        scannable: list[Path] = []
        for path in context.repo_path.rglob("*"):
            if not path.is_file():
                continue
            if any(part in _IGNORE_PATTERNS for part in path.parts):
                continue
            if path.suffix.lower() not in _SCANNABLE_EXTENSIONS:
                continue
            if path.stat().st_size > _MAX_FILE_SIZE_BYTES:
                continue
            scannable.append(path)

        return scannable

    def _scan_file(self, file_path: Path, repo_root: Path) -> list[RawFinding]:
        """
        Escanea un archivo individual buscando patrones de secretos.

        Args:
            file_path: Ruta absoluta al archivo.
            repo_root: Raíz del repositorio para calcular rutas relativas.

        Returns:
            Lista de hallazgos de seguridad encontrados.
        """
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.debug("secret_scan_read_error", file=str(file_path), error=str(exc))
            return []

        relative_path = str(file_path.relative_to(repo_root))
        findings: list[RawFinding] = []

        for pattern in _SECRET_PATTERNS:
            for match in pattern.pattern.finditer(content):
                line_number = content[: match.start()].count("\n") + 1
                matched_text = match.group(0)
                redacted = self._redact_secret(matched_text)

                findings.append(self._make_finding(
                    category=FindingCategory.SECURITY,
                    severity=pattern.severity,
                    title=f"{pattern.name} detectado",
                    description=(
                        f"Posible {pattern.name} encontrado en '{relative_path}' línea {line_number}. "
                        f"Valor (redactado): {redacted}"
                    ),
                    file_path=relative_path,
                    line_start=line_number,
                    rule_id=pattern.rule_id,
                    recommendation=pattern.recommendation,
                ))

        return findings

    @staticmethod
    def _redact_secret(secret: str) -> str:
        """
        Redacta un secreto mostrando solo los primeros y últimos 4 caracteres.

        Args:
            secret: Valor del secreto a redactar.

        Returns:
            Versión redactada del secreto.
        """
        if len(secret) <= 8:
            return "****"
        return f"{secret[:4]}{'*' * (len(secret) - 8)}{secret[-4:]}"