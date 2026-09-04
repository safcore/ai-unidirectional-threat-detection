"""
alert_store.py — Thread-safe JSON-backed alert storage.

The storage layer is intentionally decoupled from Flask routes so it can be
swapped for SQLite or PostgreSQL later without touching the API layer.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from typing import Any, cast

logger = logging.getLogger(__name__)

# Default path relative to this file → backend/data/alerts.json
_DEFAULT_DATA_PATH = os.path.join(
    os.path.dirname(__file__), "..", "data", "alerts.json"
)


class AlertStore:
    """In-process, file-backed alert store with a threading lock."""

    def __init__(self, data_path: str = _DEFAULT_DATA_PATH) -> None:
        self._path = os.path.abspath(data_path)
        self._lock = threading.Lock()
        self._ensure_file()

    # ── Private helpers ───────────────────────────────────────────────────────

    def _ensure_file(self) -> None:
        """Create the JSON file with an empty list if it does not exist."""
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        if not os.path.exists(self._path):
            self._write([])
            logger.info("Initialised empty alert store at %s", self._path)

    def _read(self) -> list[dict[str, Any]]:
        """Read and return all alerts from disk. Returns [] on any error."""
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
                if isinstance(data, list):
                    alerts: list[dict[str, Any]] = []
                    items = cast(list[Any], data)
                    for item in items:
                        if isinstance(item, dict):
                            alerts.append(cast(dict[str, Any], item))
                    return alerts
                logger.warning("alerts.json does not contain a list — resetting")
                return []
        except (json.JSONDecodeError, OSError) as exc:
            logger.error("Failed to read alert store: %s", exc)
            return []

    def _write(self, alerts: list[dict[str, Any]]) -> None:
        """Write alerts list to disk atomically (write-then-rename)."""
        tmp_path = self._path + ".tmp"
        try:
            with open(tmp_path, "w", encoding="utf-8") as fh:
                json.dump(alerts, fh, indent=2, ensure_ascii=False)
            os.replace(tmp_path, self._path)
        except OSError as exc:
            logger.error("Failed to write alert store: %s", exc)
            raise

    # ── Public API ────────────────────────────────────────────────────────────

    def get_all(self) -> list[dict[str, Any]]:
        """Return all alerts (newest first)."""
        with self._lock:
            alerts = self._read()
        return list(reversed(alerts))

    def get_by_id(self, alert_id: str) -> dict[str, Any] | None:
        """Return a single alert by ID, or None if not found."""
        with self._lock:
            alerts = self._read()
        for alert in alerts:
            if alert.get("alert_id") == alert_id:
                return alert
        return None

    def id_exists(self, alert_id: str) -> bool:
        """Return True if an alert with this ID already exists."""
        return self.get_by_id(alert_id) is not None

    def add(self, alert: dict[str, Any]) -> dict[str, Any]:
        """
        Append a new alert and persist to disk.

        Raises ValueError on duplicate alert_id.
        Raises OSError on storage failure.
        """
        alert_id = alert.get("alert_id")
        with self._lock:
            alerts = self._read()
            if any(a.get("alert_id") == alert_id for a in alerts):
                raise ValueError(f"Duplicate alert_id: {alert_id}")
            alerts.append(alert)
            self._write(alerts)
        logger.info("Stored alert %s (severity=%s, threat=%s)",
                    alert_id, alert.get("severity"), alert.get("threat"))
        return alert

    def get_stats(self) -> dict[str, Any]:
        """Compute SOC statistics from stored alerts."""
        with self._lock:
            alerts = self._read()

        stats: dict[str, Any] = {
            "total_alerts": len(alerts),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "threat_types": {},
        }

        for alert in alerts:
            sev = alert.get("severity", "").upper()
            if sev == "CRITICAL":
                stats["critical"] += 1
            elif sev == "HIGH":
                stats["high"] += 1
            elif sev == "MEDIUM":
                stats["medium"] += 1
            elif sev == "LOW":
                stats["low"] += 1

            threat = alert.get("threat", "Unknown")
            stats["threat_types"][threat] = stats["threat_types"].get(threat, 0) + 1

        return stats

    def reset(self, alerts: list[dict[str, Any]] | None = None) -> None:
        """
        Reset the store to the given list of alerts (or an empty list).
        Useful for loading mock data and for test teardown.
        """
        with self._lock:
            self._write(alerts or [])
        logger.info("Alert store reset (%d alerts loaded)", len(alerts or []))
