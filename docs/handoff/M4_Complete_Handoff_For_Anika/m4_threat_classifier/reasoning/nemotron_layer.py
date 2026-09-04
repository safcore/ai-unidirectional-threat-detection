"""
Nemotron Reasoning Layer Interface.

Provides an extensible provider interface for integrating LLM reasoning over structured threat predictions.
Target model: nvidia/nemotron-3-ultra-550b-a55b.

NOTE: As per project guidelines, this module implements an abstract interface and stub provider.
No weights are downloaded or executed during Phase 1.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class ThreatReasoningOutput(BaseModel):
    """Structured Pydantic schema for Nemotron analysis output."""
    threat_type: str = Field(description="Predicted threat type e.g., C2, DGA, DATA_EXFILTRATION, BENIGN")
    risk_level: str = Field(description="Assessed risk level e.g., HIGH, CRITICAL, MEDIUM, LOW, INFO")
    confidence: float = Field(description="Confidence score from baseline classifier [0.0 - 1.0]")
    reasoning: str = Field(description="Detailed natural language reasoning explanation")
    indicators: List[str] = Field(default_factory=list, description="Key supporting telemetry/feature evidence")
    recommended_investigation: List[str] = Field(default_factory=list, description="Actionable SOC investigation steps")
    mitre_techniques: List[Dict[str, str]] = Field(default_factory=list, description="MITRE ATT&CK mapping tags")


class BaseLLMProvider(ABC):
    """Abstract base class interface for Nemotron LLM providers."""

    @abstractmethod
    def generate_reasoning(
        self,
        prediction: str,
        confidence: float,
        features: Dict[str, Any],
        raw_telemetry: Optional[Dict[str, Any]] = None,
    ) -> ThreatReasoningOutput:
        """
        Generate structured threat analysis and investigation recommendation.

        Args:
            prediction: Baseline classifier prediction string.
            confidence: Numeric prediction confidence score.
            features: Dictionary of extracted numerical/categorical features.
            raw_telemetry: Optional raw packet or flow details.

        Returns:
            ThreatReasoningOutput: Structured reasoning report.
        """
        pass


class MockLLMProvider(BaseLLMProvider):
    """
    Mock LLM provider used for testing API routes and pipeline wiring before live Nemotron endpoint integration.
    """

    def generate_reasoning(
        self,
        prediction: str,
        confidence: float,
        features: Dict[str, Any],
        raw_telemetry: Optional[Dict[str, Any]] = None,
    ) -> ThreatReasoningOutput:
        """
        Return structured stub response matching the Nemotron interface.
        """
        risk_map = {
            "C2": "HIGH",
            "DATA_EXFILTRATION": "CRITICAL",
            "DGA": "MEDIUM",
            "BENIGN": "INFO",
        }
        
        risk = risk_map.get(prediction.upper(), "MEDIUM")

        mitre_map = {
            "C2": [{"tactic": "Command and Control", "technique_id": "T1071", "technique": "Application Layer Protocol"}],
            "DGA": [{"tactic": "Command and Control", "technique_id": "T1568.002", "technique": "Domain Generation Algorithms"}],
            "DATA_EXFILTRATION": [{"tactic": "Exfiltration", "technique_id": "T1041", "technique": "Exfiltration Over C2 Channel"}],
            "BENIGN": [],
        }

        indicators = [f"{k}: {v}" for k, v in list(features.items())[:5]]

        return ThreatReasoningOutput(
            threat_type=prediction,
            risk_level=risk if confidence > 0.5 else "LOW",
            confidence=confidence,
            reasoning=f"Interface stub analysis for prediction '{prediction}' with confidence {confidence:.2f}.",
            indicators=indicators,
            recommended_investigation=[
                "Verify host socket connections and process tree.",
                "Inspect DNS query history for high entropy subdomains.",
            ],
            mitre_techniques=mitre_map.get(prediction.upper(), []),
        )


class NemotronReasoningLayer:
    """
    High-level facade for Nemotron analysis layer.
    """

    def __init__(self, provider: Optional[BaseLLMProvider] = None):
        """
        Initialize reasoning layer with specified provider (defaults to MockLLMProvider in Phase 1).
        """
        self.provider = provider or MockLLMProvider()

    def analyze_threat(
        self,
        prediction: str,
        confidence: float,
        features: Dict[str, Any],
        raw_telemetry: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Invoke LLM provider and return analysis dict.
        """
        result = self.provider.generate_reasoning(
            prediction=prediction,
            confidence=confidence,
            features=features,
            raw_telemetry=raw_telemetry,
        )
        return result.model_dump()
