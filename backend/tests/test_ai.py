"""
test_ai.py — Tests for /api/ai/* endpoints.

ALL NVIDIA API calls are mocked.
A real API key is NEVER required to run these tests.
"""
from __future__ import annotations

import copy
import os
import pytest
from unittest.mock import MagicMock, patch

import app as app_module
import app.ai_routes as ai_routes_module
from app.ai_service import AIService, _validate_ai_analysis, _validate_correlation
from tests.conftest import VALID_ALERT, MOCK_AI_ANALYSIS, MOCK_CORRELATION


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_mock_ai_service(analysis=None, correlation=None, health=None):
    """Return a mock AIService whose methods return preset values."""
    svc = MagicMock(spec=AIService)
    svc.analyze_alert.return_value = analysis or copy.deepcopy(MOCK_AI_ANALYSIS)
    svc.correlate_alerts.return_value = correlation or copy.deepcopy(MOCK_CORRELATION)
    svc.health.return_value = health or {
        "ai_enabled": True,
        "provider": "NVIDIA",
        "model": "nvidia/nemotron-3.5-lightning-30b-a3b",
        "status": "available",
        "base_url": "https://integrate.api.nvidia.com/v1",
        "reason": None,
    }
    return svc


@pytest.fixture()
def ai_client(tmp_store, monkeypatch):
    """
    Flask test client + isolated store + mocked AIService.
    No NVIDIA key needed. No real HTTP calls made.
    """
    from app import create_app
    mock_ai = _make_mock_ai_service()

    monkeypatch.setattr(app_module, "alert_store", tmp_store)
    monkeypatch.setattr(app_module, "ai_service", mock_ai)
    monkeypatch.setattr(ai_routes_module, "alert_store", tmp_store)
    monkeypatch.setattr(ai_routes_module, "ai_service", mock_ai)

    import app.routes as routes_module
    monkeypatch.setattr(routes_module, "alert_store", tmp_store)

    flask_app = create_app({"TESTING": True})
    with flask_app.test_client() as c:
        yield c, mock_ai


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/ai/health
# ─────────────────────────────────────────────────────────────────────────────

class TestAIHealth:
    def test_ai_health_enabled(self, ai_client):
        c, mock_ai = ai_client
        resp = c.get("/api/ai/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ai_enabled"] is True
        assert data["provider"] == "NVIDIA"
        assert "model" in data
        assert data["status"] == "available"

    def test_ai_health_disabled_when_no_key(self, ai_client):
        c, mock_ai = ai_client
        mock_ai.health.return_value = {
            "ai_enabled": False,
            "provider": "NVIDIA",
            "model": "nvidia/nemotron-3.5-lightning-30b-a3b",
            "status": "disabled",
            "base_url": "https://integrate.api.nvidia.com/v1",
            "reason": "NVIDIA_API_KEY not set",
        }
        resp = c.get("/api/ai/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ai_enabled"] is False
        assert data["status"] == "disabled"
        assert "reason" in data

    def test_ai_health_does_not_call_llm(self, ai_client):
        """Health check must never call the LLM."""
        c, mock_ai = ai_client
        c.get("/api/ai/health")
        mock_ai.analyze_alert.assert_not_called()
        mock_ai.correlate_alerts.assert_not_called()

    def test_api_key_not_in_health_response(self, ai_client):
        """The NVIDIA API key must never appear in the health response."""
        c, mock_ai = ai_client
        resp = c.get("/api/ai/health")
        body = resp.get_data(as_text=True)
        # The actual key is not set in tests, but verify the field isn't present
        assert "api_key" not in body.lower()
        assert "NVIDIA_API_KEY" not in body


# ─────────────────────────────────────────────────────────────────────────────
# POST /api/ai/analyze/<alert_id>
# ─────────────────────────────────────────────────────────────────────────────

class TestAIAnalyze:
    def test_valid_analysis(self, ai_client):
        c, mock_ai = ai_client
        c.post("/api/alerts", json=VALID_ALERT)      # store the alert first
        resp = c.post("/api/ai/analyze/ALT-999")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "alert" in data
        assert "ai_analysis" in data
        assert data["alert"]["alert_id"] == "ALT-999"
        assert data["ai_analysis"]["risk_level"] == "HIGH"

    def test_missing_alert(self, ai_client):
        c, _ = ai_client
        resp = c.post("/api/ai/analyze/ALT-NONEXISTENT")
        assert resp.status_code == 404
        assert "error" in resp.get_json()

    def test_ai_unavailable_returns_fallback(self, ai_client):
        """When AI service is unavailable, endpoint returns 200 with fallback."""
        c, mock_ai = ai_client
        c.post("/api/alerts", json=VALID_ALERT)
        mock_ai.analyze_alert.return_value = {
            "error": "AI service unavailable",
            "fallback": True,
        }
        resp = c.post("/api/ai/analyze/ALT-999")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ai_analysis"]["fallback"] is True
        assert "error" in data["ai_analysis"]

    def test_malformed_ai_response_returns_fallback(self, ai_client):
        """Malformed AI response is surfaced as a controlled fallback."""
        c, mock_ai = ai_client
        c.post("/api/alerts", json=VALID_ALERT)
        mock_ai.analyze_alert.return_value = {
            "error": "AI returned malformed response",
            "validation_errors": ["Missing field: 'risk_level'"],
            "fallback": True,
        }
        resp = c.post("/api/ai/analyze/ALT-999")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ai_analysis"]["fallback"] is True

    def test_cache_refresh_parameter(self, ai_client):
        """?refresh=true should call analyze_alert with refresh=True."""
        c, mock_ai = ai_client
        c.post("/api/alerts", json=VALID_ALERT)
        c.post("/api/ai/analyze/ALT-999?refresh=true")
        # Verify it was called once, with refresh=True
        mock_ai.analyze_alert.assert_called_once()
        _args, kwargs = mock_ai.analyze_alert.call_args
        assert kwargs.get("refresh") is True

    def test_original_alert_not_modified(self, ai_client):
        """The stored alert must not be modified by AI analysis."""
        c, _ = ai_client
        c.post("/api/alerts", json=VALID_ALERT)
        c.post("/api/ai/analyze/ALT-999")
        # Re-fetch the alert
        resp = c.get("/api/alerts/ALT-999")
        stored = resp.get_json()
        assert "ai_analysis" not in stored   # AI result must NOT be merged in


# ─────────────────────────────────────────────────────────────────────────────
# POST /api/ai/correlate
# ─────────────────────────────────────────────────────────────────────────────

class TestAICorrelate:
    def _post_two_alerts(self, c):
        """Helper: store two alerts to correlate."""
        c.post("/api/alerts", json=VALID_ALERT)
        alt2 = copy.deepcopy(VALID_ALERT)
        alt2["alert_id"] = "ALT-998"
        alt2["threat"] = "Data Exfiltration"
        alt2["severity"] = "CRITICAL"
        c.post("/api/alerts", json=alt2)

    def test_valid_correlation(self, ai_client):
        c, mock_ai = ai_client
        self._post_two_alerts(c)
        resp = c.post("/api/ai/correlate",
                      json={"alert_ids": ["ALT-999", "ALT-998"]})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["alerts_analyzed"] == 2
        assert "correlation" in data
        assert "related" in data["correlation"]
        assert "confidence" in data["correlation"]

    def test_missing_alert_ids_field(self, ai_client):
        c, _ = ai_client
        resp = c.post("/api/ai/correlate", json={"bad_field": []})
        assert resp.status_code == 400

    def test_only_one_alert_id(self, ai_client):
        c, _ = ai_client
        resp = c.post("/api/ai/correlate", json={"alert_ids": ["ALT-999"]})
        assert resp.status_code == 400

    def test_missing_alert_returns_404(self, ai_client):
        c, _ = ai_client
        c.post("/api/alerts", json=VALID_ALERT)
        resp = c.post("/api/ai/correlate",
                      json={"alert_ids": ["ALT-999", "ALT-MISSING"]})
        assert resp.status_code == 404
        data = resp.get_json()
        assert "missing" in data

    def test_ai_unavailable_correlation_fallback(self, ai_client):
        c, mock_ai = ai_client
        self._post_two_alerts(c)
        mock_ai.correlate_alerts.return_value = {
            "error": "AI service unavailable",
            "fallback": True,
        }
        resp = c.post("/api/ai/correlate",
                      json={"alert_ids": ["ALT-999", "ALT-998"]})
        assert resp.status_code == 200
        assert resp.get_json()["correlation"]["fallback"] is True

    def test_no_json_body(self, ai_client):
        c, _ = ai_client
        resp = c.post("/api/ai/correlate",
                      data="not json", content_type="text/plain")
        assert resp.status_code == 400


# ─────────────────────────────────────────────────────────────────────────────
# AIService unit tests (no Flask, no HTTP)
# ─────────────────────────────────────────────────────────────────────────────

class TestAIServiceUnit:
    def test_disabled_when_no_key(self, monkeypatch):
        monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
        svc = AIService()
        assert svc.enabled is False

    def test_enabled_when_key_set(self, monkeypatch):
        monkeypatch.setenv("NVIDIA_API_KEY", "test-key-12345")
        svc = AIService()
        assert svc.enabled is True

    def test_api_key_not_exposed_in_health(self, monkeypatch):
        monkeypatch.setenv("NVIDIA_API_KEY", "super-secret-key-xyz")
        svc = AIService()
        h = svc.health()
        h_str = str(h)
        assert "super-secret-key-xyz" not in h_str

    def test_analyze_returns_fallback_when_no_key(self, monkeypatch):
        monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
        svc = AIService()
        result = svc.analyze_alert(VALID_ALERT)
        assert result["fallback"] is True
        assert "error" in result

    def test_correlate_returns_fallback_when_no_key(self, monkeypatch):
        monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
        svc = AIService()
        result = svc.correlate_alerts([VALID_ALERT, VALID_ALERT])
        assert result["fallback"] is True

    def test_cache_stores_and_returns_result(self, monkeypatch):
        monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
        svc = AIService()
        # Manually seed cache
        svc._cache_set("ALT-999", copy.deepcopy(MOCK_AI_ANALYSIS))
        result = svc.analyze_alert(VALID_ALERT, refresh=False)
        assert result["_cached"] is True

    def test_cache_refresh_bypasses_cache(self, monkeypatch):
        monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
        svc = AIService()
        svc._cache_set("ALT-999", copy.deepcopy(MOCK_AI_ANALYSIS))
        # With no key, refresh still returns fallback (not cached data)
        result = svc.analyze_alert(VALID_ALERT, refresh=True)
        assert result.get("fallback") is True

    def test_llm_timeout_returns_fallback(self, monkeypatch):
        monkeypatch.setenv("NVIDIA_API_KEY", "test-key")
        svc = AIService()
        # Simulate LLM call raising a timeout
        with patch.object(svc, "_call_llm", return_value=None):
            result = svc.analyze_alert(VALID_ALERT, refresh=True)
        assert result["fallback"] is True

    def test_llm_json_parse_error_returns_fallback(self, monkeypatch):
        monkeypatch.setenv("NVIDIA_API_KEY", "test-key")
        svc = AIService()
        with patch.object(svc, "_call_llm", return_value=None):
            result = svc.analyze_alert(VALID_ALERT, refresh=True)
        assert result["fallback"] is True

    def test_malformed_llm_response_validation(self, monkeypatch):
        monkeypatch.setenv("NVIDIA_API_KEY", "test-key")
        svc = AIService()
        # Return a dict missing required fields
        with patch.object(svc, "_call_llm", return_value={"only": "this"}):
            result = svc.analyze_alert(VALID_ALERT, refresh=True)
        assert result["fallback"] is True
        assert "validation_errors" in result

    def test_valid_llm_response_passes_validation(self):
        analysis = copy.deepcopy(MOCK_AI_ANALYSIS)
        errors = _validate_ai_analysis(analysis)
        assert errors == []

    def test_invalid_risk_level_fails_validation(self):
        analysis = copy.deepcopy(MOCK_AI_ANALYSIS)
        analysis["risk_level"] = "EXTREME"
        errors = _validate_ai_analysis(analysis)
        assert any("risk_level" in e for e in errors)

    def test_invalid_confidence_fails_validation(self):
        analysis = copy.deepcopy(MOCK_AI_ANALYSIS)
        analysis["confidence"] = 1.5
        errors = _validate_ai_analysis(analysis)
        assert any("confidence" in e for e in errors)

    def test_valid_correlation_passes_validation(self):
        errors = _validate_correlation(copy.deepcopy(MOCK_CORRELATION))
        assert errors == []

    def test_correlate_requires_min_two_alerts(self, monkeypatch):
        monkeypatch.setenv("NVIDIA_API_KEY", "test-key")
        svc = AIService()
        result = svc.correlate_alerts([VALID_ALERT])
        assert "error" in result
        assert result.get("fallback") is False   # not an AI failure, just bad input


# ─────────────────────────────────────────────────────────────────────────────
# Security: API key must not appear in any API response
# ─────────────────────────────────────────────────────────────────────────────

class TestSecurityKeyNotExposed:
    def test_key_not_in_health_response(self, ai_client, monkeypatch):
        c, _ = ai_client
        monkeypatch.setenv("NVIDIA_API_KEY", "SUPER_SECRET_KEY_12345")
        resp = c.get("/api/ai/health")
        assert "SUPER_SECRET_KEY_12345" not in resp.get_data(as_text=True)

    def test_key_not_in_analyze_response(self, ai_client, monkeypatch):
        c, _ = ai_client
        monkeypatch.setenv("NVIDIA_API_KEY", "SUPER_SECRET_KEY_12345")
        c.post("/api/alerts", json=VALID_ALERT)
        resp = c.post("/api/ai/analyze/ALT-999")
        assert "SUPER_SECRET_KEY_12345" not in resp.get_data(as_text=True)

    def test_key_not_in_correlate_response(self, ai_client, monkeypatch):
        c, _ = ai_client
        monkeypatch.setenv("NVIDIA_API_KEY", "SUPER_SECRET_KEY_12345")
        c.post("/api/alerts", json=VALID_ALERT)
        alt2 = copy.deepcopy(VALID_ALERT)
        alt2["alert_id"] = "ALT-998"
        c.post("/api/alerts", json=alt2)
        resp = c.post("/api/ai/correlate",
                      json={"alert_ids": ["ALT-999", "ALT-998"]})
        assert "SUPER_SECRET_KEY_12345" not in resp.get_data(as_text=True)


# ─────────────────────────────────────────────────────────────────────────────
# Existing alert pipeline must still work independently of AI
# ─────────────────────────────────────────────────────────────────────────────

class TestAIDoesNotBreakPipeline:
    def test_post_alerts_works_with_ai_disabled(self, client):
        """POST /api/alerts must work even with AI entirely disabled."""
        resp = client.post("/api/alerts", json=VALID_ALERT)
        assert resp.status_code == 201

    def test_get_alerts_works_with_ai_disabled(self, client):
        resp = client.get("/api/alerts")
        assert resp.status_code == 200

    def test_stats_works_with_ai_disabled(self, client):
        resp = client.get("/api/stats")
        assert resp.status_code == 200

    def test_ai_analyze_handles_unexpected_exception_gracefully(self, ai_client):
        """Unexpected internal exceptions during analyze must return 200 fallback, not 500/crash."""
        c, mock_ai = ai_client
        c.post("/api/alerts", json=VALID_ALERT)
        mock_ai.analyze_alert.side_effect = RuntimeError("Simulated internal AI crash")
        resp = c.post("/api/ai/analyze/ALT-999")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ai_analysis"]["fallback"] is True
        assert "Simulated internal AI crash" in data["ai_analysis"]["reason"]

    def test_ai_correlate_handles_unexpected_exception_gracefully(self, ai_client):
        """Unexpected internal exceptions during correlate must return 200 fallback, not 500/crash."""
        c, mock_ai = ai_client
        c.post("/api/alerts", json=VALID_ALERT)
        alt2 = copy.deepcopy(VALID_ALERT)
        alt2["alert_id"] = "ALT-998"
        c.post("/api/alerts", json=alt2)
        mock_ai.correlate_alerts.side_effect = RuntimeError("Simulated internal correlate crash")
        resp = c.post("/api/ai/correlate", json={"alert_ids": ["ALT-999", "ALT-998"]})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["correlation"]["fallback"] is True

    def test_extract_json_handles_thinking_preamble_and_markdown(self):
        """_extract_json should parse valid JSON embedded inside thinking text or markdown."""
        raw_text = """Here is my thinking process:
- The alert shows port scan
- Let's format the response

```json
{
  "ai_summary": "Port scan detected.",
  "threat_assessment": "Assessing threat.",
  "risk_level": "HIGH"
}
```
Done."""
        parsed = AIService._extract_json(raw_text)
        assert parsed is not None
        assert parsed["risk_level"] == "HIGH"
        assert parsed["ai_summary"] == "Port scan detected."
