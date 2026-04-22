"""
Cliente OpenAI para análisis de arquitectura y calidad de código.

Encapsula toda la interacción con la API de OpenAI incluyendo:
- Sanitización de código antes de enviar (prevención prompt injection)
- Control de tokens y costos
- Validación de respuestas JSON
- Manejo de timeouts y reintentos
- Logging de auditoría completo

La clase respeta SRP: solo gestiona la comunicación con OpenAI.
La orquestación es responsabilidad de CodeAuditorAgent.
"""

import json
import re
import time
from typing import Any

from openai import AsyncOpenAI, APIConnectionError, APITimeoutError, RateLimitError
from openai.types.chat import ChatCompletion

from src.core.logging import get_logger
from src.db.models import FindingCategory, FindingSeverity

logger = get_logger(__name__)

# Patrones que indican intento de prompt injection en el código analizado
_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"ignore\s+previous\s+instructions", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+a", re.IGNORECASE),
    re.compile(r"system\s*:\s*you", re.IGNORECASE),
    re.compile(r"<\|im_start\|>|<\|im_end\|>", re.IGNORECASE),
    re.compile(r"\[INST\]|\[/INST\]"),
    re.compile(r"###\s*(instruction|system|prompt)", re.IGNORECASE),
]

# Schema esperado en la respuesta del LLM
_EXPECTED_FINDING_KEYS: frozenset[str] = frozenset({
    "category", "severity", "title", "description",
    "file_path", "recommendation",
})

_VALID_CATEGORIES: frozenset[str] = frozenset(
    {c.value for c in FindingCategory}
)
_VALID_SEVERITIES: frozenset[str] = frozenset(
    {s.value for s in FindingSeverity}
)

_SYSTEM_PROMPT = """Eres un experto en arquitectura de software y seguridad de código.
Analiza el código Python proporcionado y reporta hallazgos en formato JSON estricto.

FORMATO DE RESPUESTA (solo JSON, sin markdown ni texto adicional):
{
  "findings": [
    {
      "category": "security|architecture|quality|improvement",
      "severity": "critical|high|medium|low|info",
      "title": "Título corto del hallazgo (máx 80 chars)",
      "description": "Descripción detallada del problema",
      "file_path": "ruta/al/archivo.py",
      "line_start": 42,
      "recommendation": "Acción concreta para resolver el problema"
    }
  ],
  "summary": "Resumen ejecutivo del análisis en 2-3 oraciones"
}

REGLAS:
- Responder SOLO con JSON válido, sin markdown ni texto fuera del JSON.
- No incluir hallazgos triviales (nombres de variables cortos en iteradores son aceptables).
- Priorizar problemas de seguridad y arquitectura sobre estilo.
- Máximo 20 hallazgos por análisis.
- Si no hay hallazgos reales, retornar findings: [].
"""


class LLMAnalysisResult:
    """
    Resultado estructurado de un análisis LLM.

    Attributes:
        findings: Lista de hallazgos parseados.
        summary: Resumen ejecutivo del análisis.
        tokens_used: Tokens consumidos en la invocación.
        model: Modelo de OpenAI utilizado.
    """

    def __init__(
        self,
        findings: list[dict[str, Any]],
        summary: str,
        tokens_used: int,
        model: str,
    ) -> None:
        self.findings = findings
        self.summary = summary
        self.tokens_used = tokens_used
        self.model = model


class LLMClient:
    """
    Cliente wrapper de OpenAI con controles de seguridad y calidad.

    Args:
        api_key: API key de OpenAI.
        model: Modelo a usar (default: gpt-3.5-turbo).
        max_tokens: Máximo de tokens por invocación.
        timeout_seconds: Timeout por request.
        max_code_chars: Máximo de caracteres de código a enviar (anti-prompt-injection).
    """

    def __init__(
        self,
        api_key: str,
        base_url: str | None = None,
        model: str = "gpt-3.5-turbo",
        max_tokens: int = 8000,
        timeout_seconds: int = 60,
        max_code_chars: int = 12000,
    ) -> None:
        self._client = AsyncOpenAI(api_key=api_key, base_url=base_url, timeout=timeout_seconds)
        self._model = model
        self._max_tokens = max_tokens
        self._max_code_chars = max_code_chars

    async def analyze_code_architecture(
        self,
        code_snippets: dict[str, str],
        repo_full_name: str,
    ) -> LLMAnalysisResult:
        """
        Envía snippets de código al LLM para análisis de arquitectura.

        Args:
            code_snippets: Diccionario {ruta_archivo: contenido_código}.
            repo_full_name: Nombre del repositorio (owner/repo).

        Returns:
            LLMAnalysisResult con hallazgos y metadata.

        Raises:
            ValueError: Si los snippets están vacíos o exceden el límite.
            RuntimeError: Si la API de OpenAI falla tras reintentos.
        """
        if not code_snippets:
            raise ValueError("code_snippets no puede estar vacío")

        sanitized = self._sanitize_code_snippets(code_snippets)
        user_prompt = self._build_user_prompt(sanitized, repo_full_name)

        logger.info(
            "llm_analysis_start",
            repo=repo_full_name,
            files=len(sanitized),
            prompt_chars=len(user_prompt),
        )

        start_time = time.monotonic()
        try:
            response = await self._invoke_with_retry(user_prompt)
        except Exception as exc:
            logger.error("llm_analysis_failed", repo=repo_full_name, error=str(exc))
            raise

        elapsed = time.monotonic() - start_time
        raw_content = response.choices[0].message.content or ""
        tokens_used = response.usage.total_tokens if response.usage else 0

        logger.info(
            "llm_analysis_complete",
            repo=repo_full_name,
            tokens=tokens_used,
            elapsed_seconds=round(elapsed, 2),
        )

        parsed = self._parse_and_validate_response(raw_content)
        return LLMAnalysisResult(
            findings=parsed.get("findings", []),
            summary=parsed.get("summary", ""),
            tokens_used=tokens_used,
            model=self._model,
        )

    def _sanitize_code_snippets(
        self, snippets: dict[str, str]
    ) -> dict[str, str]:
        """
        Sanitiza snippets de código para prevenir prompt injection.

        - Trunca cada snippet a max_code_chars.
        - Detecta y marca patrones de inyección.
        - Escapa secuencias peligrosas.

        Args:
            snippets: Diccionario de snippets originales.

        Returns:
            Diccionario de snippets sanitizados.
        """
        sanitized: dict[str, str] = {}
        total_chars = 0

        for file_path, content in snippets.items():
            # Sanitizar ruta del archivo (solo alfanumérico, /, ., -)
            safe_path = re.sub(r"[^\w./\-]", "_", file_path)[:200]

            # Truncar contenido
            truncated = content[: self._max_code_chars]

            # Detectar intent de inyección
            for pattern in _INJECTION_PATTERNS:
                if pattern.search(truncated):
                    logger.warning(
                        "prompt_injection_attempt_detected",
                        file=safe_path,
                        pattern=pattern.pattern,
                    )
                    truncated = pattern.sub("[REDACTED]", truncated)

            sanitized[safe_path] = truncated
            total_chars += len(truncated)

            # Límite global de contexto (~16K chars para gpt-3.5-turbo)
            if total_chars >= self._max_code_chars * 3:
                logger.warning(
                    "llm_context_limit_reached",
                    files_included=len(sanitized),
                    total_files=len(snippets),
                )
                break

        return sanitized

    def _build_user_prompt(
        self, snippets: dict[str, str], repo_full_name: str
    ) -> str:
        """
        Construye el prompt de usuario con los snippets sanitizados.

        Args:
            snippets: Snippets ya sanitizados.
            repo_full_name: Nombre del repositorio.

        Returns:
            Prompt completo para enviar al LLM.
        """
        parts = [f"Analiza el siguiente código del repositorio '{repo_full_name}':\n"]
        for file_path, content in snippets.items():
            parts.append(f"\n--- ARCHIVO: {file_path} ---\n```python\n{content}\n```\n")
        parts.append("\nGenera el análisis en formato JSON según las instrucciones del sistema.")
        return "".join(parts)

    async def _invoke_with_retry(
        self, user_prompt: str, max_retries: int = 2
    ) -> ChatCompletion:
        """
        Invoca la API de OpenAI con reintentos ante errores transitorios.

        Reintenta solo ante RateLimitError y APIConnectionError.
        No reintenta ante errores de autenticación o contenido.

        Args:
            user_prompt: Prompt de usuario a enviar.
            max_retries: Cantidad máxima de reintentos.

        Returns:
            Respuesta de la API de OpenAI.

        Raises:
            RuntimeError: Si se agotan los reintentos.
        """
        last_error: Exception | None = None

        for attempt in range(max_retries + 1):
            try:
                return await self._client.chat.completions.create(
                    model=self._model,
                    max_tokens=self._max_tokens,
                    temperature=0.1,  # Baja temperatura para respuestas consistentes
                    messages=[
                        {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                    ],
                    response_format={"type": "json_object"},
                )
            except RateLimitError as exc:
                last_error = exc
                wait_seconds = 2 ** attempt
                logger.warning(
                    "llm_rate_limit",
                    attempt=attempt + 1,
                    wait_seconds=wait_seconds,
                )
                import asyncio
                await asyncio.sleep(wait_seconds)
            except APIConnectionError as exc:
                last_error = exc
                logger.warning("llm_connection_error", attempt=attempt + 1)
                import asyncio
                await asyncio.sleep(1)
            except APITimeoutError as exc:
                logger.error("llm_timeout")
                raise RuntimeError("OpenAI API timeout") from exc

        raise RuntimeError(
            f"OpenAI API falló tras {max_retries + 1} intentos: {last_error}"
        )

    def _parse_and_validate_response(self, raw_content: str) -> dict[str, Any]:
        """
        Parsea y valida la respuesta JSON del LLM.

        Verifica que:
        - Sea JSON válido.
        - Contenga la clave 'findings'.
        - Cada finding tenga las claves requeridas.
        - Los valores de category y severity sean válidos.

        Args:
            raw_content: String con la respuesta cruda del LLM.

        Returns:
            Diccionario con findings validados (inválidos son descartados).
        """
        # Limpiar posibles bloques markdown que el modelo incluya pese al prompt
        cleaned = re.sub(r"^```(?:json)?\s*", "", raw_content.strip(), flags=re.MULTILINE)
        cleaned = re.sub(r"\s*```$", "", cleaned, flags=re.MULTILINE)

        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError as exc:
            logger.error("llm_response_invalid_json", error=str(exc), raw=raw_content[:200])
            return {"findings": [], "summary": ""}

        if not isinstance(data, dict):
            logger.error("llm_response_not_dict", type=type(data).__name__)
            return {"findings": [], "summary": ""}

        raw_findings = data.get("findings", [])
        if not isinstance(raw_findings, list):
            logger.error("llm_findings_not_list")
            return {"findings": [], "summary": ""}

        valid_findings: list[dict[str, Any]] = []
        for i, finding in enumerate(raw_findings):
            validated = self._validate_finding(finding, index=i)
            if validated:
                valid_findings.append(validated)

        discarded = len(raw_findings) - len(valid_findings)
        if discarded > 0:
            logger.warning("llm_findings_discarded", count=discarded)

        return {
            "findings": valid_findings,
            "summary": str(data.get("summary", ""))[:1000],
        }

    def _validate_finding(
        self, finding: Any, index: int
    ) -> dict[str, Any] | None:
        """
        Valida un finding individual del LLM.

        Args:
            finding: Dict con los datos del hallazgo.
            index: Índice en la lista (para logging).

        Returns:
            Finding validado o None si es inválido.
        """
        if not isinstance(finding, dict):
            logger.debug("llm_finding_not_dict", index=index)
            return None

        # Verificar claves requeridas
        missing = _EXPECTED_FINDING_KEYS - finding.keys()
        if missing:
            logger.debug("llm_finding_missing_keys", index=index, missing=list(missing))
            return None

        # Validar valores enum
        category = str(finding.get("category", "")).lower()
        severity = str(finding.get("severity", "")).lower()

        if category not in _VALID_CATEGORIES:
            logger.debug("llm_finding_invalid_category", index=index, category=category)
            return None

        if severity not in _VALID_SEVERITIES:
            logger.debug("llm_finding_invalid_severity", index=index, severity=severity)
            return None

        # Normalizar y truncar strings
        return {
            "category": category,
            "severity": severity,
            "title": str(finding.get("title", ""))[:300],
            "description": str(finding.get("description", ""))[:2000],
            "file_path": str(finding.get("file_path", ""))[:500],
            "line_start": self._safe_int(finding.get("line_start")),
            "line_end": self._safe_int(finding.get("line_end")),
            "rule_id": str(finding.get("rule_id", "LLM-001"))[:100],
            "recommendation": str(finding.get("recommendation", ""))[:2000],
        }

    @staticmethod
    def _safe_int(value: Any) -> int | None:
        """Convierte un valor a int de forma segura."""
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None