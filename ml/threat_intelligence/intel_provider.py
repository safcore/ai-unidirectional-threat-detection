"""
Threat Intelligence Provider Abstraction & Implementation Module.

Provides:
  - ThreatIntelProvider (Abstract Base Class)
  - LocalThreatIntelProvider (Offline demonstration datasets)
  - ExternalThreatIntelProvider (Optional API integration with graceful degradation)
"""

import os
import json
import logging
from pathlib import Path
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data" / "threat_intel"


class ThreatIntelProvider(ABC):
    """Abstract Base Class for Threat Intelligence Providers."""

    @abstractmethod
    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        pass


class LocalThreatIntelProvider(ThreatIntelProvider):
    """
    Offline local threat intelligence provider using data/threat_intel/ datasets.
    Serves as the primary demonstration intelligence provider.
    """

    def __init__(self):
        self.ips = self._load_json(DATA_DIR / "malicious_ips.json")
        self.domains = self._load_json(DATA_DIR / "malicious_domains.json")
        self.hashes = self._load_json(DATA_DIR / "known_iocs.json").get("known_hashes", {})

    def _load_json(self, path: Path) -> Dict[str, Any]:
        if not path.exists():
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Error loading threat intel file {path}: {e}")
            return {}

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        norm_ip = str(ip).strip()
        if norm_ip in self.ips:
            res = self.ips[norm_ip].copy()
            res["status"] = "found"
            return res
        return {
            "ip": norm_ip,
            "reputation": "UNKNOWN",
            "confidence": 0.0,
            "status": "not_found",
            "source": "LOCAL DEMONSTRATION INTELLIGENCE",
        }

    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        norm_domain = str(domain).strip().lower()
        if norm_domain in self.domains:
            res = self.domains[norm_domain].copy()
            res["status"] = "found"
            return res
        return {
            "domain": norm_domain,
            "reputation": "UNKNOWN",
            "confidence": 0.0,
            "status": "not_found",
            "source": "LOCAL DEMONSTRATION INTELLIGENCE",
        }

    def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        norm_hash = str(file_hash).strip().lower()
        if norm_hash in self.hashes:
            res = self.hashes[norm_hash].copy()
            res["status"] = "found"
            return res
        return {
            "hash": norm_hash,
            "reputation": "UNKNOWN",
            "confidence": 0.0,
            "status": "not_found",
            "source": "LOCAL DEMONSTRATION INTELLIGENCE",
        }


class ExternalThreatIntelProvider(ThreatIntelProvider):
    """
    Optional external Threat Intel API provider (VirusTotal / AbuseIPDB / AlienVault OTX).
    Gracefully returns status='unavailable' or reputation='UNAVAILABLE' if API keys are missing or API fails.
    """

    def __init__(self):
        self.vt_key = os.getenv("VT_API_KEY")
        self.abuse_key = os.getenv("ABUSEIPDB_API_KEY")

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        if not self.abuse_key and not self.vt_key:
            return {
                "ip": ip,
                "reputation": "UNAVAILABLE",
                "confidence": 0.0,
                "status": "api_key_missing",
                "source": "EXTERNAL API PROVIDER",
            }
        # Placeholder for external HTTP request if key present
        return {
            "ip": ip,
            "reputation": "UNKNOWN",
            "confidence": 0.0,
            "status": "external_lookup_unimplemented",
            "source": "EXTERNAL API PROVIDER",
        }

    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        return {
            "domain": domain,
            "reputation": "UNAVAILABLE",
            "confidence": 0.0,
            "status": "api_key_missing",
            "source": "EXTERNAL API PROVIDER",
        }

    def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        return {
            "hash": file_hash,
            "reputation": "UNAVAILABLE",
            "confidence": 0.0,
            "status": "api_key_missing",
            "source": "EXTERNAL API PROVIDER",
        }
