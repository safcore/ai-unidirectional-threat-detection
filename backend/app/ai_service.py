"""
ai_service.py — NVIDIA Nemotron 3.5 AI enrichment layer for PS-145.

Architecture principle:
  Alert JSON → this service → NVIDIA NIM API → structured AI analysis JSON

This is an ENRICHMENT layer only.  It never replaces the detection pipeline.
All failures are caught and returned as controlled error responses.
The normal alert store / SSE pipeline is never affected by AI failures.

Configuration (via environment variables / .env):
  NVIDIA_API_KEY   — NIM API key from https://build.nvidia.com/
  NVIDIA_MODEL     — model name (default: nvidia/nemotron-3.5-lightning-30b-a3b)
  NVIDIA_BASE_URL  — NIM endpoint (default: https://integrate.api.nvidia.com/v1)
  AI_TIMEOUT_SECS  — HTTP timeout in seconds (default: 30)
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import Any, cast

logger = logging.getLogger(__name__)

# ── Defaults ──────────────────────────────────────────────────────────────────
_DEFAULT_MODEL   = "nvidia/nemotron-3.5-lightning-30b-a3b"
_DEFAULT_BASE_URL = "https://integrate.api.nvidia.com/v1"
_DEFAULT_TIMEOUT = 120


# ── AI Response Validation ────────────────────────────────────────────────────

VALID_RISK_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
VALID_PRIORITIES  = {"LOW", "MEDIUM", "HIGH", "IMMEDIATE"}

def _validate_ai_analysis(data: Any) -> list[str]:
    """Validate structured AI analysis response. Returns list of errors."""
    if not isinstance(data, dict):
        return ["AI response must be a JSON object"]

    payload: dict[str, Any] = cast(dict[str, Any], data)
    errors: list[str] = []
    required = [
        "ai_summary", "threat_assessment", "risk_level", "confidence",
        "why_suspicious", "attack_stage", "mitre_context",
        "recommended_actions", "investigation_priority",
    ]
    for f in required:
        if f not in payload:
            errors.append(f"Missing field in AI response: '{f}'")
    if errors:
        return errors
    if payload.get("risk_level") not in VALID_RISK_LEVELS:
        errors.append(f"Invalid risk_level: {payload.get('risk_level')!r}")
    conf = payload.get("confidence")
    if not isinstance(conf, (int, float)) or not (0.0 <= conf <= 1.0):
        errors.append("AI confidence must be a number 0.0–1.0")
    if not isinstance(payload.get("why_suspicious"), list):
        errors.append("'why_suspicious' must be a list")
    if not isinstance(payload.get("recommended_actions"), list):
        errors.append("'recommended_actions' must be a list")
    if not isinstance(payload.get("mitre_context"), dict):
        errors.append("'mitre_context' must be an object")
    if payload.get("investigation_priority") not in VALID_PRIORITIES:
        errors.append(f"Invalid investigation_priority: {payload.get('investigation_priority')!r}")
    return errors


def _validate_correlation(data: Any) -> list[str]:
    """Validate correlation response."""
    if not isinstance(data, dict):
        return ["Correlation response must be a JSON object"]

    payload: dict[str, Any] = cast(dict[str, Any], data)
    errors: list[str] = []
    for f in ["related", "confidence", "summary", "common_indicators",
              "possible_attack_chain", "recommended_actions"]:
        if f not in payload:
            errors.append(f"Missing field: '{f}'")
    if errors:
        return errors
    if not isinstance(payload.get("related"), bool):
        errors.append("'related' must be a boolean")
    conf = payload.get("confidence")
    if not isinstance(conf, (int, float)) or not (0.0 <= conf <= 1.0):
        errors.append("'confidence' must be 0.0–1.0")
    return errors


# ── Prompt builders ───────────────────────────────────────────────────────────

def _build_analysis_prompt(alert: dict[str, Any]) -> str:
    """Build a structured cybersecurity SOC analyst prompt for a single alert."""
    mitre: dict[str, Any] = alert.get("mitre", {})
    evidence: dict[str, Any] = alert.get("evidence", {})

    return f"""You are a defensive SOC (Security Operations Center) analyst assistant.
Analyze the following network security alert and provide a structured assessment.

ALERT DATA:
- Alert ID: {alert.get("alert_id")}
- Timestamp: {alert.get("timestamp")}
- Threat Type: {alert.get("threat")}
- Severity: {alert.get("severity")}
- Detection Confidence: {alert.get("confidence")}
- Source IP: {alert.get("source_ip")} : {alert.get("source_port")}
- Destination IP: {alert.get("destination_ip")} : {alert.get("destination_port")}
- Protocol: {alert.get("protocol")}
- MITRE ATT&CK Tactic: {mitre.get("tactic")}
- MITRE ATT&CK Technique: {mitre.get("technique")} — {mitre.get("technique_name")}
- Evidence: {json.dumps(evidence)}

STRICT RULES:
1. Base your analysis ONLY on the data provided above.
2. Do NOT invent IP reputation, malware names, CVEs, DNS records, or attribution.
3. Clearly separate confirmed evidence from analytical inference.
4. Your role is to help a human analyst prioritize and investigate — not to make final decisions.

Respond with ONLY a JSON object (no markdown, no explanation outside the JSON) with this exact structure:
{{
  "ai_summary": "One concise sentence describing the threat.",
  "threat_assessment": "2-3 sentence detailed assessment based on the evidence provided.",
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": <float 0.0-1.0 reflecting your analytical confidence>,
  "why_suspicious": ["Specific reason 1", "Specific reason 2", "Specific reason 3"],
  "attack_stage": "The stage of the attack lifecycle (e.g., Reconnaissance, Initial Access, Command and Control, Exfiltration)",
  "mitre_context": {{
    "tactic": "{mitre.get("tactic")}",
    "technique": "{mitre.get("technique")}",
    "technique_name": "{mitre.get("technique_name")}"
  }},
  "recommended_actions": ["Action 1", "Action 2", "Action 3"],
  "investigation_priority": "IMMEDIATE|HIGH|MEDIUM|LOW"
}}"""


def _build_correlation_prompt(alerts: list[dict[str, Any]]) -> str:
    """Build a prompt to correlate multiple alerts."""
    summaries: list[str] = []
    for a in alerts:
        m: dict[str, Any] = a.get("mitre", {})
        summaries.append(
            f"- {a.get('alert_id')}: {a.get('threat')} | "
            f"{a.get('source_ip')}→{a.get('destination_ip')} | "
            f"Protocol: {a.get('protocol')} | Severity: {a.get('severity')} | "
            f"MITRE: {m.get('tactic')}/{m.get('technique')} | "
            f"Evidence: {json.dumps(a.get('evidence', {}))}"
        )
    alerts_block = "\n".join(summaries)

    return f"""You are a defensive SOC analyst assistant.
Analyze whether the following alerts may be part of the same attack campaign or attack chain.

ALERTS:
{alerts_block}

STRICT RULES:
1. Base your analysis ONLY on the data provided above.
2. Do NOT invent facts, IPs, malware, or attribution.
3. Look for patterns: shared IPs, sequential MITRE techniques, timing, protocol overlap.

Respond with ONLY a JSON object (no markdown) with this exact structure:
{{
  "related": <true|false>,
  "confidence": <float 0.0-1.0>,
  "summary": "1-2 sentence explanation of whether and why these alerts may be correlated.",
  "common_indicators": ["Indicator 1", "Indicator 2"],
  "possible_attack_chain": ["Step 1 (alert id)", "Step 2 (alert id)"],
  "recommended_actions": ["Action 1", "Action 2"]
}}"""


# ── Main AI Service ───────────────────────────────────────────────────────────

class AIService:
    """
    NVIDIA Nemotron 3.5 AI enrichment service.

    - Reads config from environment variables (never from code).
    - Implements a simple in-memory analysis cache (per alert_id).
    - All failures return controlled error dicts — never raises to callers.
    - The detection/storage pipeline is completely isolated from this class.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # analysis cache: alert_id → {"result": dict, "cached_at": float}
        self._cache: dict[str, dict[str, Any]] = {}
        self._client: Any = None

    # ── Config ────────────────────────────────────────────────────────────────

    @property
    def _api_key(self) -> str | None:
        key = os.environ.get("NVIDIA_API_KEY", "").strip()
        return key if key else None

    @property
    def model(self) -> str:
        return os.environ.get("NVIDIA_MODEL", _DEFAULT_MODEL)

    @property
    def base_url(self) -> str:
        return os.environ.get("NVIDIA_BASE_URL", _DEFAULT_BASE_URL)

    @property
    def timeout(self) -> int:
        try:
            return int(os.environ.get("AI_TIMEOUT_SECS", _DEFAULT_TIMEOUT))
        except ValueError:
            return _DEFAULT_TIMEOUT

    @property
    def enabled(self) -> bool:
        """AI is enabled only if an API key is configured."""
        return bool(self._api_key)

    # ── OpenAI client (lazy, cached) ──────────────────────────────────────────

    def _get_client(self) -> Any | None:
        """Return a cached OpenAI client pointing at NVIDIA NIM, or None."""
        with self._lock:
            key = self._api_key
            if not key:
                logger.warning("AI: NVIDIA_API_KEY not set — AI features disabled")
                return None
            if self._client is not None:
                return self._client
            try:
                from openai import OpenAI   # imported here so missing dep is graceful
                self._client = OpenAI(
                    api_key=key,
                    base_url=self.base_url,
                    timeout=self.timeout,
                    max_retries=0,
                )
                logger.info("AI: NVIDIA NIM client initialised (model=%s)", self.model)
                return self._client
            except Exception as exc:
                logger.error("AI: Failed to initialise OpenAI client: %s", exc)
                return None

    # ── Cache helpers ─────────────────────────────────────────────────────────

    def _cache_get(self, key: str) -> dict[str, Any] | None:
        with self._lock:
            entry = self._cache.get(key)
        return entry

    def _cache_set(self, key: str, result: dict[str, Any]) -> None:
        with self._lock:
            self._cache[key] = {"result": result, "cached_at": time.time()}

    def _cache_clear(self, key: str) -> None:
        with self._lock:
            self._cache.pop(key, None)

    # ── Raw LLM call ──────────────────────────────────────────────────────────

    @staticmethod
    def _extract_json(raw_text: str | None) -> dict[str, Any] | None:
        """Extract and parse target JSON from raw LLM output, handling markdown and reasoning text."""
        if not raw_text:
            return None

        text = raw_text.strip()

        # 1. Direct parse
        try:
            data: Any = json.loads(text)
            if isinstance(data, dict):
                return cast(dict[str, Any], data)
        except Exception:
            pass

        # 2. Extract from markdown code fences
        if "```" in text:
            import re
            blocks = re.findall(r"```(?:json)?\s*([\s\S]*?)\s*```", text, re.IGNORECASE)
            for block in reversed(blocks):
                try:
                    data = json.loads(block.strip())
                    if isinstance(data, dict):
                        return cast(dict[str, Any], data)
                except Exception:
                    pass

        # 3. Search for JSON substring by bracket positions
        open_indices = [i for i, c in enumerate(text) if c == "{"]
        close_indices = [i for i, c in enumerate(text) if c == "}"]

        # Prioritize substrings containing target keys
        for close_idx in reversed(close_indices):
            for open_idx in open_indices:
                if open_idx < close_idx:
                    chunk = text[open_idx:close_idx + 1].strip()
                    if '"ai_summary"' in chunk or '"related"' in chunk or '"threat_assessment"' in chunk:
                        try:
                            data = json.loads(chunk)
                            if isinstance(data, dict):
                                return cast(dict[str, Any], data)
                        except Exception:
                            pass

        # Fallback: any valid JSON dict
        for close_idx in reversed(close_indices):
            for open_idx in reversed(open_indices):
                if open_idx < close_idx:
                    try:
                        data = json.loads(text[open_idx:close_idx + 1].strip())
                        if isinstance(data, dict):
                            dict_data = cast(dict[str, Any], data)
                            if len(dict_data) > 1:
                                return dict_data
                    except Exception:
                        pass

        return None

    def _call_llm(self, prompt: str) -> dict[str, Any] | None:
        """
        Call the NVIDIA NIM API and parse the JSON response.

        Returns parsed dict, or None on any failure.
        Never raises — all errors are logged and suppressed.
        """
        client = self._get_client()
        if client is None:
            return None

        try:
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "/no_think\nYou are a specialized defensive SOC analysis engine. Respond strictly and only with the requested JSON object, with no preamble or conversational text.",
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.1,   # lower temperature → more consistent structured output
                max_tokens=4096,
            )
            if not response or not getattr(response, "choices", None):
                logger.error("AI: No choices returned in LLM response")
                return None

            choice = response.choices[0] if len(response.choices) > 0 else None
            if not choice or not getattr(choice, "message", None):
                logger.error("AI: No message returned in LLM response choice")
                return None

            raw_text = getattr(choice.message, "content", None)
            if not raw_text:
                logger.error("AI: Empty content in LLM response")
                return None
            if not isinstance(raw_text, str):
                logger.error("AI: Non-string content in LLM response")
                return None

            raw_text = raw_text.strip()
            logger.debug("AI raw response: %s", raw_text[:200])

            parsed = self._extract_json(raw_text)
            if parsed is None:
                logger.error("AI: Could not parse JSON from LLM response")
                return None
            return parsed

        except Exception as exc:
            # Catches: APIConnectionError, AuthenticationError, RateLimitError, timeout
            err_type = type(exc).__name__
            # Never log the API key — just log the error type and message
            safe_msg = str(exc)
            if self._api_key and self._api_key in safe_msg:
                safe_msg = safe_msg.replace(self._api_key, "[REDACTED]")
            logger.error("AI: LLM call failed (%s): %s", err_type, safe_msg)
            return None

    # ── Public API ────────────────────────────────────────────────────────────

    def analyze_alert(self, alert: dict[str, Any], refresh: bool = False) -> dict[str, Any]:
        """
        Analyze a single alert with Nemotron.

        Returns a dict with either the AI analysis or an error structure.
        Never raises.
        """
        try:
            alert_id: str = str(alert.get("alert_id", "UNKNOWN"))

            # Check cache (unless refresh forced)
            if not refresh:
                cached = self._cache_get(alert_id)
                if cached:
                    result: dict[str, Any] = dict(cached["result"])
                    result["_cached"] = True
                    result["_cached_at"] = cached["cached_at"]
                    logger.info("AI: Returning cached analysis for %s", alert_id)
                    return result

            if not self.enabled:
                return {
                    "error": "AI service unavailable",
                    "reason": "NVIDIA_API_KEY not configured",
                    "fallback": True,
                }

            prompt = _build_analysis_prompt(alert)
            raw = self._call_llm(prompt)

            if raw is None:
                return {
                    "error": "AI service unavailable",
                    "reason": "LLM call failed or timed out",
                    "fallback": True,
                }

            # Validate the structured response
            errors = _validate_ai_analysis(raw)
            if errors:
                logger.warning("AI: Response failed validation for %s: %s", alert_id, errors)
                return {
                    "error": "AI returned malformed response",
                    "validation_errors": errors,
                    "fallback": True,
                }

            # Inject alert_id and cache
            raw["alert_id"] = alert_id
            raw["_cached"] = False
            self._cache_set(alert_id, raw)

            logger.info("AI: Analysis complete for %s (risk=%s)", alert_id, raw.get("risk_level"))
            return raw
        except Exception as exc:
            logger.error("AI: Unexpected error in analyze_alert: %s", exc)
            return {
                "error": "AI service encountered an unexpected error",
                "reason": str(exc),
                "fallback": True,
            }

    def correlate_alerts(self, alerts: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Correlate multiple alerts — detect possible attack chains.

        Returns structured correlation dict or error. Never raises.
        """
        try:
            if not self.enabled:
                return {
                    "error": "AI service unavailable",
                    "reason": "NVIDIA_API_KEY not configured",
                    "fallback": True,
                }

            if len(alerts) < 2:
                return {
                    "error": "At least 2 alerts required for correlation",
                    "fallback": False,
                }

            prompt = _build_correlation_prompt(alerts)
            raw = self._call_llm(prompt)

            if raw is None:
                return {
                    "error": "AI service unavailable",
                    "reason": "LLM call failed or timed out",
                    "fallback": True,
                }

            errors = _validate_correlation(raw)
            if errors:
                logger.warning("AI: Correlation response failed validation: %s", errors)
                return {
                    "error": "AI returned malformed correlation response",
                    "validation_errors": errors,
                    "fallback": True,
                }

            logger.info("AI: Correlation complete (related=%s, confidence=%.2f)",
                        raw.get("related"), raw.get("confidence", 0))
            return raw
        except Exception as exc:
            logger.error("AI: Unexpected error in correlate_alerts: %s", exc)
            return {
                "error": "AI correlation encountered an unexpected error",
                "reason": str(exc),
                "fallback": True,
            }

    def health(self) -> dict[str, Any]:
        """
        Return AI health info.

        Does NOT call the LLM — just checks config.
        """
        key_configured = bool(self._api_key)
        res: dict[str, Any] = {
            "ai_enabled": key_configured,
            "base_url": self.base_url,
            "model": self.model,
            "provider": "NVIDIA",
            "status": "available" if key_configured else "disabled",
        }
        if not key_configured:
            res["reason"] = "NVIDIA_API_KEY not set"
        return res
