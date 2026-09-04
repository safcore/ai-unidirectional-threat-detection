"""
Threat Intelligence Enrichment Engine Module.

Combines IOC extraction, in-memory caching, and multi-provider lookups (offline local + optional external)
to enrich normalized threat events with contextual reputation data.
"""

import logging
from typing import Dict, Any, List, Optional
from ml.threat_intelligence.ioc_extractor import extract_iocs, IOC
from ml.threat_intelligence.cache import IntelCache
from ml.threat_intelligence.intel_provider import LocalThreatIntelProvider, ExternalThreatIntelProvider

logger = logging.getLogger(__name__)


class ThreatIntelEnrichmentEngine:
    """
    Threat Intelligence Enrichment Orchestrator.
    """

    def __init__(self, cache_ttl_seconds: int = 3600):
        self.cache = IntelCache(default_ttl_seconds=cache_ttl_seconds)
        self.local_provider = LocalThreatIntelProvider()
        self.external_provider = ExternalThreatIntelProvider()

    def enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract IOCs from event, query intelligence cache/providers, and return intelligence enrichment dict.
        """
        iocs = extract_iocs(event)
        enriched_iocs: List[Dict[str, Any]] = []
        reputations: List[Dict[str, Any]] = []

        highest_intel_confidence = 0.0
        overall_reputation = "UNKNOWN"

        for ioc in iocs:
            ioc_dict = ioc.to_dict()
            cache_key = f"{ioc.ioc_type}:{ioc.value}"

            # Check cache
            intel_res = self.cache.get(cache_key)
            if not intel_res:
                # Query local provider first (offline-first)
                if ioc.ioc_type in ["IPv4", "IPv6"]:
                    intel_res = self.local_provider.lookup_ip(ioc.value)
                elif ioc.ioc_type == "Domain":
                    intel_res = self.local_provider.lookup_domain(ioc.value)
                elif ioc.ioc_type == "Hash":
                    intel_res = self.local_provider.lookup_hash(ioc.value)
                else:
                    intel_res = {
                        "value": ioc.value,
                        "reputation": "UNKNOWN",
                        "confidence": 0.0,
                        "status": "not_applicable",
                        "source": "LOCAL DEMONSTRATION INTELLIGENCE",
                    }

                # Cache result
                self.cache.set(cache_key, intel_res)

            rep = intel_res.get("reputation", "UNKNOWN")
            conf = float(intel_res.get("confidence", 0.0))

            if rep in ["MALICIOUS", "SUSPICIOUS"]:
                if conf > highest_intel_confidence:
                    highest_intel_confidence = conf
                    overall_reputation = rep
            elif overall_reputation == "UNKNOWN" and rep == "BENIGN":
                overall_reputation = "BENIGN"

            ioc_dict["intel"] = intel_res
            enriched_iocs.append(ioc_dict)
            reputations.append(intel_res)

        return {
            "iocs": enriched_iocs,
            "overall_reputation": overall_reputation,
            "highest_intel_confidence": round(highest_intel_confidence, 4),
            "total_iocs_extracted": len(enriched_iocs),
            "sources": ["LOCAL DEMONSTRATION INTELLIGENCE"],
        }
