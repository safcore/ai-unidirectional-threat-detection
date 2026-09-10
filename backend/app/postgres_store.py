"""
postgres_store.py — PostgreSQL-backed alert storage for NETRION.

Implements the exact same interface as AlertStore (alert_store.py)
for seamless plug-and-play persistence in PostgreSQL.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Optional
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2.pool import ThreadedConnectionPool

logger = logging.getLogger(__name__)


class PostgresAlertStore:
    """Production-grade PostgreSQL alert store with connection pooling and JSONB indexing."""

    def __init__(self, db_url: str, minconn: int = 1, maxconn: int = 10) -> None:
        self._db_url = db_url
        self._pool = ThreadedConnectionPool(minconn, maxconn, dsn=self._db_url)
        self._init_tables()

    def _get_conn(self):
        return self._pool.getconn()

    def _put_conn(self, conn):
        self._pool.putconn(conn)

    def _init_tables(self) -> None:
        """Create alerts table and indexes if they do not exist."""
        ddl = """
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id VARCHAR(64) PRIMARY KEY,
            timestamp TIMESTAMPTZ NOT NULL,
            threat VARCHAR(64) NOT NULL,
            severity VARCHAR(16) NOT NULL,
            confidence REAL NOT NULL,
            source_ip VARCHAR(45) NOT NULL,
            destination_ip VARCHAR(45) NOT NULL,
            source_port INT NOT NULL,
            destination_port INT NOT NULL,
            protocol VARCHAR(16) NOT NULL,
            mitre JSONB NOT NULL DEFAULT '{}'::jsonb,
            evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);
        CREATE INDEX IF NOT EXISTS idx_alerts_threat ON alerts (threat);
        CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts (source_ip);
        CREATE INDEX IF NOT EXISTS idx_alerts_mitre ON alerts USING GIN (mitre);
        """
        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(ddl)
            conn.commit()
            logger.info("PostgreSQL alerts table and indexes verified.")
        finally:
            self._put_conn(conn)

    def _row_to_alert(self, row: dict[str, Any]) -> dict[str, Any]:
        """Normalize database row dictionary to canonical alert format."""
        alert = dict(row)
        # Format timestamp to ISO string if it's a datetime object
        if hasattr(alert.get("timestamp"), "isoformat"):
            alert["timestamp"] = alert["timestamp"].isoformat()
        # Remove DB-specific created_at if present
        alert.pop("created_at", None)
        return alert

    # ── Public API (identical to AlertStore) ───────────────────────────────────

    def get_all(self) -> list[dict[str, Any]]:
        """Return all alerts (newest first)."""
        conn = self._get_conn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 500;")
                rows = cur.fetchall()
                return [self._row_to_alert(r) for r in rows]
        finally:
            self._put_conn(conn)

    def get_by_id(self, alert_id: str) -> Optional[dict[str, Any]]:
        """Return a single alert by ID, or None if not found."""
        conn = self._get_conn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT * FROM alerts WHERE alert_id = %s;", (alert_id,))
                row = cur.fetchone()
                return self._row_to_alert(row) if row else None
        finally:
            self._put_conn(conn)

    def id_exists(self, alert_id: str) -> bool:
        """Return True if an alert with this ID exists."""
        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM alerts WHERE alert_id = %s LIMIT 1;", (alert_id,))
                return cur.fetchone() is not None
        finally:
            self._put_conn(conn)

    def add(self, alert: dict[str, Any]) -> dict[str, Any]:
        """
        Append a new alert and persist to PostgreSQL.
        Raises ValueError on duplicate alert_id.
        """
        alert_id = alert.get("alert_id")
        if not alert_id:
            raise ValueError("Alert missing alert_id")

        if self.id_exists(alert_id):
            raise ValueError(f"Duplicate alert_id: {alert_id}")

        query = """
        INSERT INTO alerts (
            alert_id, timestamp, threat, severity, confidence,
            source_ip, destination_ip, source_port, destination_port,
            protocol, mitre, evidence
        ) VALUES (
            %(alert_id)s, %(timestamp)s, %(threat)s, %(severity)s, %(confidence)s,
            %(source_ip)s, %(destination_ip)s, %(source_port)s, %(destination_port)s,
            %(protocol)s, %(mitre)s, %(evidence)s
        ) RETURNING *;
        """
        params = {
            "alert_id": alert_id,
            "timestamp": alert.get("timestamp"),
            "threat": alert.get("threat", "Unknown"),
            "severity": alert.get("severity", "MEDIUM"),
            "confidence": float(alert.get("confidence", 0.0)),
            "source_ip": alert.get("source_ip", "0.0.0.0"),
            "destination_ip": alert.get("destination_ip", "0.0.0.0"),
            "source_port": int(alert.get("source_port", 0)),
            "destination_port": int(alert.get("destination_port", 0)),
            "protocol": alert.get("protocol", "TCP"),
            "mitre": json.dumps(alert.get("mitre", {})),
            "evidence": json.dumps(alert.get("evidence", {})),
        }

        conn = self._get_conn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(query, params)
                inserted = cur.fetchone()
            conn.commit()
            logger.info("Stored alert %s in PostgreSQL (severity=%s, threat=%s)",
                        alert_id, alert.get("severity"), alert.get("threat"))
            return self._row_to_alert(inserted)
        except Exception as exc:
            conn.rollback()
            logger.error("Failed to insert alert %s into PostgreSQL: %s", alert_id, exc)
            raise
        finally:
            self._put_conn(conn)

    def get_stats(self) -> dict[str, Any]:
        """Compute SOC statistics efficiently via SQL aggregation."""
        query = """
        SELECT
            COUNT(*) AS total_alerts,
            COUNT(*) FILTER (WHERE UPPER(severity) = 'CRITICAL') AS critical,
            COUNT(*) FILTER (WHERE UPPER(severity) = 'HIGH') AS high,
            COUNT(*) FILTER (WHERE UPPER(severity) = 'MEDIUM') AS medium,
            COUNT(*) FILTER (WHERE UPPER(severity) = 'LOW') AS low
        FROM alerts;
        """
        threat_query = "SELECT threat, COUNT(*) as count FROM alerts GROUP BY threat;"

        conn = self._get_conn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(query)
                row = cur.fetchone() or {}
                cur.execute(threat_query)
                threat_rows = cur.fetchall()

            threat_types = {r["threat"]: r["count"] for r in threat_rows}
            return {
                "total_alerts": row.get("total_alerts", 0),
                "critical": row.get("critical", 0),
                "high": row.get("high", 0),
                "medium": row.get("medium", 0),
                "low": row.get("low", 0),
                "threat_types": threat_types,
            }
        finally:
            self._put_conn(conn)

    def reset(self, alerts: list[dict[str, Any]] | None = None) -> None:
        """Clear alerts table and optionally bulk-insert given alerts."""
        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute("TRUNCATE TABLE alerts;")
            conn.commit()
            logger.info("Alerts table truncated in PostgreSQL.")
        finally:
            self._put_conn(conn)

        if alerts:
            for a in alerts:
                try:
                    self.add(a)
                except Exception as exc:
                    logger.warning("Error adding alert during reset: %s", exc)
            logger.info("Reset and loaded %d alerts into PostgreSQL.", len(alerts))
