"""
routes.py — All Flask API endpoints.

Blueprint: api_bp (prefix /api)
Root route / is also registered here.
"""
from __future__ import annotations

import logging

from flask import Blueprint, Response, jsonify, request, stream_with_context

from . import alert_store, stream_manager
from .models import validate_alert

logger = logging.getLogger(__name__)

api_bp = Blueprint("api", __name__)

# ─────────────────────────────────────────────────────────────────────────────
# Root
# ─────────────────────────────────────────────────────────────────────────────

@api_bp.route("/")
def root():
    return jsonify({
        "service": "PS-145 Threat Detection Backend",
        "version": "1.0.0",
        "endpoints": [
            "GET  /api/health",
            "GET  /api/alerts",
            "GET  /api/alerts/<alert_id>",
            "POST /api/alerts",
            "GET  /api/stats",
            "GET  /api/stream",
            "GET  /api/ai/health",
            "POST /api/ai/analyze/<alert_id>",
            "POST /api/ai/correlate",
        ],
    })


# ─────────────────────────────────────────────────────────────────────────────
# Health
# ─────────────────────────────────────────────────────────────────────────────

@api_bp.route("/api/health")
def health():
    return jsonify({
        "status": "healthy",
        "service": "threat-detection-backend",
        "sse_clients": stream_manager.client_count,
    })


# ─────────────────────────────────────────────────────────────────────────────
# Alerts — GET all
# ─────────────────────────────────────────────────────────────────────────────

@api_bp.route("/api/alerts", methods=["GET"])
def get_alerts():
    severity_filter = request.args.get("severity", "").upper() or None
    alerts = alert_store.get_all()
    if severity_filter:
        alerts = [a for a in alerts if a.get("severity") == severity_filter]
    return jsonify({"alerts": alerts, "count": len(alerts)})


# ─────────────────────────────────────────────────────────────────────────────
# Alerts — GET single
# ─────────────────────────────────────────────────────────────────────────────

@api_bp.route("/api/alerts/<alert_id>", methods=["GET"])
def get_alert(alert_id: str):
    alert = alert_store.get_by_id(alert_id)
    if alert is None:
        return jsonify({"error": "Alert not found"}), 404
    return jsonify(alert)


# ─────────────────────────────────────────────────────────────────────────────
# Alerts — POST (ingest a new alert)
# ─────────────────────────────────────────────────────────────────────────────

@api_bp.route("/api/alerts", methods=["POST"])
def post_alert():
    # 1. Parse JSON body
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"error": "Request body must be valid JSON"}), 400

    logger.info("Incoming alert: %s", data.get("alert_id", "<no id>"))

    # 2. Validate
    errors = validate_alert(data)
    if errors:
        logger.warning("Alert validation failed: %s", errors)
        return jsonify({"error": "Invalid alert", "details": errors}), 422

    # 3. Check for duplicate
    if alert_store.id_exists(data["alert_id"]):
        return jsonify({"error": f"Duplicate alert_id: {data['alert_id']}"}), 409

    # 4. Store
    try:
        stored = alert_store.add(data)
    except OSError as exc:
        logger.error("Storage error: %s", exc)
        return jsonify({"error": "Failed to store alert — storage error"}), 500

    # 5. Broadcast via SSE
    stream_manager.broadcast(stored)

    return jsonify(stored), 201


# ─────────────────────────────────────────────────────────────────────────────
# Stats
# ─────────────────────────────────────────────────────────────────────────────

@api_bp.route("/api/stats", methods=["GET"])
def get_stats():
    return jsonify(alert_store.get_stats())


# ─────────────────────────────────────────────────────────────────────────────
# SSE Stream
# ─────────────────────────────────────────────────────────────────────────────

@api_bp.route("/api/stream", methods=["GET"])
def stream():
    """
    Server-Sent Events endpoint.

    Frontend usage:
        const es = new EventSource("http://localhost:8000/api/stream");
        es.addEventListener("connected", e => console.log("Live!"));
        es.onmessage = e => {
            const alert = JSON.parse(e.data);
            // update dashboard
        };
    """
    return Response(
        stream_with_context(stream_manager.event_stream()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",   # disable Nginx buffering if behind proxy
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# Error handlers
# ─────────────────────────────────────────────────────────────────────────────

@api_bp.app_errorhandler(404)
def not_found(exc: Exception):
    return jsonify({"error": "Not found"}), 404


@api_bp.app_errorhandler(405)
def method_not_allowed(exc: Exception):
    return jsonify({"error": "Method not allowed"}), 405


@api_bp.app_errorhandler(500)
def internal_error(exc: Exception):
    logger.exception("Unhandled server error")
    return jsonify({"error": "Internal server error"}), 500
