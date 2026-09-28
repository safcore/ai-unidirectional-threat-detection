"""
M5 — Alert Engine
==================
Central alert dispatcher:
  1. Receives raw alert dicts from all detector modules.
  2. Wraps them into structured Alert objects (schema.py).
  3. Enriches with MITRE ATT&CK context (mitre_mapper.py).
  4. Persists to SQLite database.
  5. Pushes to an async callback queue for the Flask dashboard (SSE).
  6. Records StreamMonitor metric.

Thread-safe — called from multiple detector threads simultaneously.
"""

import sqlite3
import threading
import time
import queue
import logging
import os
from typing import Callable, List, Optional

from m5_alerts.schema import Alert
from m5_alerts.mitre_mapper import MitreMapper

logger = logging.getLogger(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "alerts.db")


class AlertEngine:
    """
    Central alert bus.

    Usage:
        engine = AlertEngine()
        engine.start()

        # Register a live-push callback (e.g., Flask SSE queue)
        engine.add_live_handler(my_sse_queue.put)

        # Feed raw detector dicts
        engine.ingest(raw_alert_dict)
    """

    def __init__(
        self,
        db_path: str = DB_PATH,
        monitor=None,          # StreamMonitor
        max_live_queue: int = 1000,
    ):
        self.db_path = db_path
        self.monitor = monitor
        self._mapper = MitreMapper()
        self._lock = threading.Lock()
        self._live_handlers: List[Callable] = []

        # In-memory queue for SSE / WebSocket delivery
        self.live_queue: queue.Queue = queue.Queue(maxsize=max_live_queue)

        # Total alert count
        self.total_alerts = 0

        self._setup_db()

    # ── Setup ─────────────────────────────────────────────────────────────────

    def _setup_db(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id       TEXT PRIMARY KEY,
                timestamp      REAL,
                timestamp_iso  TEXT,
                flow_id        TEXT,
                src_ip         TEXT,
                dst_ip         TEXT,
                src_port       INTEGER,
                dst_port       INTEGER,
                protocol       TEXT,
                threat_class   TEXT,
                threat_subtype TEXT,
                severity       TEXT,
                confidence     REAL,
                evidence_json  TEXT,
                mitre_tactic   TEXT,
                mitre_technique TEXT,
                mitre_technique_id TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ts ON alerts(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_class ON alerts(threat_class)")
        conn.commit()
        conn.close()
        logger.info("AlertEngine DB initialized at %s", self.db_path)

    def start(self):
        logger.info("AlertEngine ready")

    def add_live_handler(self, handler: Callable):
        """Register callback for real-time alert delivery."""
        self._live_handlers.append(handler)

    # ── Main entry point ──────────────────────────────────────────────────────

    def ingest(self, raw: dict):
        """
        Called by any detector module to report a threat.
        Thread-safe.
        """
        try:
            alert = Alert.from_detector_dict(raw)
            alert = self._mapper.enrich(alert)

            self._persist(alert)
            self._push_live(alert)

            with self._lock:
                self.total_alerts += 1

            if self.monitor:
                self.monitor.record_alert()

        except Exception as e:
            logger.error("AlertEngine.ingest error: %s", e, exc_info=True)

    # ── Persistence ───────────────────────────────────────────────────────────

    def _persist(self, alert: Alert):
        import json
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute("""
                INSERT OR REPLACE INTO alerts VALUES
                (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                alert.alert_id, alert.timestamp, alert.timestamp_iso,
                alert.flow_id, alert.src_ip, alert.dst_ip,
                alert.src_port, alert.dst_port, alert.protocol,
                alert.threat_class, alert.threat_subtype,
                alert.severity, alert.confidence,
                json.dumps(alert.evidence),
                alert.mitre_tactic, alert.mitre_technique, alert.mitre_technique_id,
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error("DB persist error: %s", e)

    def _push_live(self, alert: Alert):
        d = alert.to_dict()
        # Push to in-memory queue (non-blocking)
        try:
            self.live_queue.put_nowait(d)
        except queue.Full:
            pass   # drop oldest would be better but simple for now

        # Call registered live handlers
        for h in self._live_handlers:
            try:
                h(d)
            except Exception as e:
                logger.error("Live handler error: %s", e)

    # ── Query API (for dashboard) ─────────────────────────────────────────────

    def query_recent(self, limit: int = 100, threat_class: str = None) -> list:
        """Return most recent alerts from DB."""
        import json
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        where = "WHERE threat_class = ?" if threat_class else ""
        params = (threat_class, limit) if threat_class else (limit,)
        rows = conn.execute(
            f"SELECT * FROM alerts {where} ORDER BY timestamp DESC LIMIT ?", params
        ).fetchall()
        conn.close()
        results = []
        for r in rows:
            d = dict(r)
            d["evidence"] = json.loads(d.pop("evidence_json", "{}"))
            results.append(d)
        return results

    def get_stats(self) -> dict:
        """Return aggregate statistics for the dashboard."""
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute("""
            SELECT threat_class, severity, COUNT(*) as cnt
            FROM alerts
            GROUP BY threat_class, severity
        """).fetchall()
        conn.close()

        by_class = {}
        by_severity = {}
        for threat_class, severity, cnt in rows:
            by_class[threat_class] = by_class.get(threat_class, 0) + cnt
            by_severity[severity]  = by_severity.get(severity, 0) + cnt

        return {
            "total_alerts": self.total_alerts,
            "by_class":     by_class,
            "by_severity":  by_severity,
        }
