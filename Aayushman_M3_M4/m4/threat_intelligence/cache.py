"""
In-Memory TTL Threat Intelligence Cache Module.
"""

import time
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class IntelCache:
    """Simple thread-safe in-memory TTL cache for threat intelligence results."""

    def __init__(self, default_ttl_seconds: int = 3600):
        self._cache: Dict[str, Dict[str, Any]] = {}
        self.default_ttl = default_ttl_seconds

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Retrieve item from cache if not expired."""
        if key not in self._cache:
            return None
        entry = self._cache[key]
        if time.time() > entry["expires_at"]:
            del self._cache[key]
            return None
        return entry["value"]

    def set(self, key: str, value: Dict[str, Any], ttl_seconds: Optional[int] = None):
        """Store item in cache with TTL."""
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
        self._cache[key] = {
            "value": value,
            "expires_at": time.time() + ttl,
        }

    def clear(self):
        """Clear all cached entries."""
        self._cache.clear()
