"""
M6 — Flask Live Dashboard (Server-Sent Events)
===============================================
Routes:
  GET  /              → Dashboard HTML page
  GET  /api/alerts    → Recent alerts (JSON)
  GET  /api/stats     → Aggregate stats (JSON)
  GET  /api/stream    → Live SSE stream (text/event-stream)
  GET  /api/health    → Health check
"""

import sys
import os
import json
import time
import queue
import threading
import logging

# Add parent to path so we can import other modules
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from flask import Flask, Response, jsonify, render_template, request
from flask_cors import CORS

logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder="templates")
CORS(app)

# ── Shared state (set by run.py before app.run()) ─────────────────────────────
alert_engine = None   # m5_alerts.alert_engine.AlertEngine
stream_monitor = None # m1_ingest.stream_monitor.StreamMonitor

# ── Per-client SSE queues ─────────────────────────────────────────────────────
_sse_clients: list[queue.Queue] = []
_sse_lock = threading.Lock()


def _broadcast_alert(alert_dict: dict):
    """Push a new alert to all connected SSE clients."""
    data = json.dumps(alert_dict, default=str)
    with _sse_lock:
        dead = []
        for q in _sse_clients:
            try:
                q.put_nowait(data)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _sse_clients.remove(q)


def register_with_engine(engine):
    """Called from run.py to wire the alert engine to SSE broadcast."""
    global alert_engine
    alert_engine = engine
    engine.add_live_handler(_broadcast_alert)


def register_monitor(monitor):
    global stream_monitor
    stream_monitor = monitor


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/alerts")
def get_alerts():
    if alert_engine is None:
        return jsonify([])
    limit        = int(request.args.get("limit", 100))
    threat_class = request.args.get("threat_class", None)
    alerts       = alert_engine.query_recent(limit=limit, threat_class=threat_class)
    return jsonify(alerts)


@app.route("/api/stats")
def get_stats():
    stats = {}
    if alert_engine:
        stats.update(alert_engine.get_stats())
    if stream_monitor:
        stats.update(stream_monitor.latest)
        stats["history"] = stream_monitor.get_history()[-30:]  # last 30 seconds
    return jsonify(stats)


@app.route("/api/health")
def health():
    fps = stream_monitor.latest.get("flows_per_sec", 0) if stream_monitor else 0
    return jsonify({
        "status": "ok",
        "flows_per_sec": fps,
        "timestamp": time.time(),
    })


@app.route("/api/stream")
def sse_stream():
    """
    Server-Sent Events endpoint.
    Each connected browser client gets its own queue.
    """
    client_q: queue.Queue = queue.Queue(maxsize=200)
    with _sse_lock:
        _sse_clients.append(client_q)

    def generate():
        try:
            # Send a heartbeat every 15s to keep the connection alive
            last_heartbeat = time.time()
            while True:
                try:
                    data = client_q.get(timeout=1.0)
                    yield f"data: {data}\n\n"
                    last_heartbeat = time.time()
                except queue.Empty:
                    if time.time() - last_heartbeat > 15:
                        yield ": heartbeat\n\n"
                        last_heartbeat = time.time()
        except GeneratorExit:
            pass
        finally:
            with _sse_lock:
                if client_q in _sse_clients:
                    _sse_clients.remove(client_q)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


def run_dashboard(host="0.0.0.0", port=5000, debug=False):
    app.run(host=host, port=port, debug=debug, use_reloader=False, threaded=True)
