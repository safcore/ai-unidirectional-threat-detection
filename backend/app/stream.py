"""
stream.py — Server-Sent Events (SSE) stream manager.

Uses a thread-safe queue per connected client.  When a new alert arrives the
Flask route calls broadcast(); every connected EventSource client receives the
event immediately.
"""
from __future__ import annotations

import json
import logging
import queue
import threading
import time
from typing import Any

logger = logging.getLogger(__name__)

_HEARTBEAT_INTERVAL = 15  # seconds between keep-alive comments


class StreamManager:
    """Manages a set of per-client queues for SSE broadcasting."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._clients: list[queue.Queue[str]] = []

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _add_client(self) -> queue.Queue[str]:
        q: queue.Queue[str] = queue.Queue()
        with self._lock:
            self._clients.append(q)
        logger.info("SSE client connected  (total=%d)", len(self._clients))
        return q

    def _remove_client(self, q: queue.Queue[str]) -> None:
        with self._lock:
            try:
                self._clients.remove(q)
            except ValueError:
                pass
        logger.info("SSE client disconnected (total=%d)", len(self._clients))

    # ── Public API ────────────────────────────────────────────────────────────

    def broadcast(self, alert: dict[str, Any]) -> None:
        """Push an alert to every connected SSE client queue."""
        payload = json.dumps(alert, ensure_ascii=False)
        with self._lock:
            clients = list(self._clients)
        for q in clients:
            try:
                q.put_nowait(payload)
            except queue.Full:
                logger.warning("SSE client queue full — dropping event")

    @property
    def client_count(self) -> int:
        with self._lock:
            return len(self._clients)

    def event_stream(self):
        """
        Generator yielded by the /api/stream route.

        Yields SSE-formatted strings.  Blocks between events using a short
        timeout so heartbeats can be sent and client disconnects detected.
        """
        q = self._add_client()

        # Send an initial connection event so the frontend knows it is live
        yield "event: connected\ndata: {\"status\": \"connected\"}\n\n"

        last_heartbeat = time.monotonic()

        try:
            while True:
                # ── Try to get an alert from the queue ──────────────────────
                try:
                    payload = q.get(timeout=1.0)
                    yield f"data: {payload}\n\n"
                    last_heartbeat = time.monotonic()
                except queue.Empty:
                    pass

                # ── Send a heartbeat comment every N seconds ─────────────────
                if time.monotonic() - last_heartbeat >= _HEARTBEAT_INTERVAL:
                    yield ": heartbeat\n\n"
                    last_heartbeat = time.monotonic()

        except GeneratorExit:
            # Client disconnected (Flask detected the broken connection)
            pass
        finally:
            self._remove_client(q)
