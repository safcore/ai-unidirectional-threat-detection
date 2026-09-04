"""
NVIDIA Nemotron / NIM AI Investigation Client Module.

Provides an OpenAI-compatible API client connecting to NVIDIA NIM endpoints
(e.g., https://integrate.api.nvidia.com/v1) for automated SOC investigation analysis.

Strict Security & Guardrail Rules:
  1. Loads API key securely from environment variable NVIDIA_NIM_API_KEY.
  2. NEVER prints, logs, or returns API keys in responses or exceptions.
  3. Fail-safe: If API fails, returns status='AI_UNAVAILABLE' without breaking deterministic detection.
  4. Prompt Guardrails: LLM explains supplied evidence only; never invents telemetry or attribution.
"""

import os
import json
import logging
import urllib.request
import urllib.error
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


def load_env_file(force_reload: bool = True):
    """
    Authoritative .env file loader. Overwrites os.environ keys with values from .env.
    """
    env_path = Path(__file__).resolve().parent.parent.parent / ".env"
    if env_path.exists():
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        key = k.strip()
                        val = v.strip()
                        if force_reload or key not in os.environ:
                            os.environ[key] = val
        except Exception as e:
            logger.warning(f"Error loading .env file: {e}")


# Load on import
load_env_file()


SYSTEM_GUARDRAIL_PROMPT = """You are a Senior Cyber Threat Analyst.
Strict Rules:
1. Rely EXCLUSIVELY on supplied telemetry evidence.
2. DO NOT invent IP addresses, timestamps, attack techniques, or attribution.
3. Treat risk score as an explainable engineering score.
4. Mention uncertainty when evidence is incomplete.
Provide a concise SOC investigation briefing with key findings and recommendations."""


@dataclass
class NemotronAnalysisResult:
    """Structured Nemotron Analysis Result."""
    status: str                         # SUCCESS / AI_UNAVAILABLE
    analysis: Optional[str]
    key_findings: List[str]
    recommended_actions: List[str]
    limitations: List[str]
    model: str
    deterministic_detection_available: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class NemotronClient:
    """
    OpenAI-compatible NVIDIA NIM API Client.
    """

    def __init__(self):
        # Refresh environment variables authoritatively from .env
        load_env_file(force_reload=True)
        self.api_key = os.getenv("NVIDIA_NIM_API_KEY", "").strip()
        self.base_url = os.getenv("NVIDIA_NIM_BASE_URL", "https://integrate.api.nvidia.com/v1").rstrip("/")
        self.model = os.getenv("NVIDIA_NIM_MODEL", "nvidia/nemotron-3.5-lightning-30b-a3b").strip()
        self.enabled = os.getenv("NVIDIA_NIM_ENABLED", "true").lower() in ["true", "1", "yes"]
        try:
            self.timeout = int(os.getenv("NVIDIA_NIM_TIMEOUT", "60"))
        except ValueError:
            self.timeout = 60

    def is_configured(self) -> bool:
        return bool(self.enabled and self.api_key and not self.api_key.startswith("your_"))

    def get_safe_diagnostics(self) -> Dict[str, Any]:
        """Return safe diagnostics without exposing API keys."""
        return {
            "Configured": self.is_configured(),
            "Base URL": self.base_url,
            "Model": self.model,
        }

    def analyze_incident(self, incident_data: Dict[str, Any]) -> NemotronAnalysisResult:
        """
        Analyze structured incident evidence using NVIDIA NIM API with fail-safe fallback.
        """
        if not self.is_configured():
            logger.info("NVIDIA NIM API client is disabled or missing valid NVIDIA_NIM_API_KEY in environment.")
            return NemotronAnalysisResult(
                status="AI_UNAVAILABLE",
                analysis=None,
                key_findings=[],
                recommended_actions=[],
                limitations=["NVIDIA NIM API key is not configured in .env file."],
                model=self.model,
                deterministic_detection_available=True,
            )

        # Assemble prompt payload
        user_prompt = f"""Analyze the following security incident evidence and generate a concise SOC briefing:

Incident Data:
{json.dumps(incident_data, indent=2)}
"""

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_GUARDRAIL_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 256,
        }

        endpoint = f"{self.base_url}/chat/completions"

        try:
            req_data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(endpoint, data=req_data, headers=headers, method="POST")

            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                resp_bytes = response.read()
                resp_json = json.loads(resp_bytes.decode("utf-8"))

            content = resp_json["choices"][0]["message"]["content"]

            return NemotronAnalysisResult(
                status="SUCCESS",
                analysis=content,
                key_findings=["Structured evidence analyzed by NVIDIA NIM LLM layer."],
                recommended_actions=["Review host socket telemetry", "Inspect target network logs"],
                limitations=["LLM reasoning provides qualitative context over deterministic features."],
                model=self.model,
                deterministic_detection_available=True,
            )

        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="ignore")
            # Mask API key in log message
            logger.warning(f"NVIDIA NIM API HTTP error {e.code}: {e.reason}")
            return NemotronAnalysisResult(
                status="AI_UNAVAILABLE",
                analysis=None,
                key_findings=[],
                recommended_actions=[],
                limitations=[f"NVIDIA NIM request failed with HTTP error {e.code}: {err_body[:100]}"],
                model=self.model,
                deterministic_detection_available=True,
            )

        except Exception as e:
            logger.warning(f"NVIDIA NIM request failed: {type(e).__name__}")
            return NemotronAnalysisResult(
                status="AI_UNAVAILABLE",
                analysis=None,
                key_findings=[],
                recommended_actions=[],
                limitations=[f"NVIDIA NIM request failed: {type(e).__name__}"],
                model=self.model,
                deterministic_detection_available=True,
            )


_nemotron_client_instance = None


def get_nemotron_client() -> NemotronClient:
    global _nemotron_client_instance
    _nemotron_client_instance = NemotronClient()
    return _nemotron_client_instance
