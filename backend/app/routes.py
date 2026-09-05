"""
routes.py — All Flask API endpoints.

Blueprint: api_bp (prefix /api)
Root route / is also registered here.
"""
from __future__ import annotations

import logging

from flask import Blueprint, Response, jsonify, request, stream_with_context

from . import alert_store, stream_manager
from .attack_service import attack_service
from .m4_integration import m4_available, process_detection, validate_detection_input
from .m2_adapter import M2AdapterError, normalize_m2_output
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
            "POST /api/detect",
            "POST /api/attack/start",
            "POST /api/attack/stop",
            "GET  /api/attack/status",
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
        "m4": {"available": m4_available()},
    })


@api_bp.route("/api/detect", methods=["POST"])
def detect():
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"error": "Request body must be valid JSON"}), 400
    errors = validate_detection_input(data)
    if errors:
        return jsonify({"error": "Invalid detection request", "details": errors}), 422

    try:
        features, metadata = normalize_m2_output(data)
        event, incident, alert = process_detection(features, metadata)
        if alert_store.id_exists(alert["alert_id"]):
            return jsonify({"error": "Generated duplicate alert_id"}), 500
        stored = alert_store.add(alert)
        stream_manager.broadcast(stored)
        return jsonify({
            "success": True,
            "event": event,
            "incident": incident.to_dict(),
            "alert": stored,
        }), 200
    except (ValueError, M2AdapterError) as exc:
        logger.warning("M4 detection rejected input: %s", exc)
        return jsonify({"error": "M4 detection failed", "details": str(exc)}), 422
    except OSError:
        logger.exception("M4 detection storage failure")
        return jsonify({"error": "Failed to store detection alert"}), 500
    except Exception:
        logger.exception("M4 detection route failure")
        return jsonify({"error": "M4 detection unavailable"}), 503


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
# Attack Traffic Generator Endpoints (M6 Demonstration)
# ─────────────────────────────────────────────────────────────────────────────

@api_bp.route("/api/attack/start", methods=["POST"])
def start_attack():
    """Start an attack traffic generator in simulation or live mode."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400

    attack_type = data.get("attack_type") or data.get("type")
    if not attack_type or not isinstance(attack_type, str):
        return jsonify({"error": "'attack_type' is required (e.g. syn_flood, port_scan, dns_tunnel)"}), 400

    params = data.get("params") or {}
    if not isinstance(params, dict):
        return jsonify({"error": "'params' must be an object"}), 400

    try:
        job = attack_service.start_attack(attack_type, params)
        return jsonify({"status": "started", "attack": job}), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.exception("Failed to start attack")
        return jsonify({"error": str(e)}), 500


@api_bp.route("/api/attack/stop", methods=["POST"])
def stop_attack():
    """Stop a running attack by ID, or stop all attacks if attack_id is omitted."""
    data = request.get_json(silent=True) or {}
    attack_id = data.get("attack_id")

    if attack_id:
        result = attack_service.stop_attack(attack_id)
        if not result:
            return jsonify({"error": f"Attack job '{attack_id}' not found"}), 404
        return jsonify({"status": "stopping", "attack": result}), 200
    else:
        stopped_count = attack_service.stop_all()
        return jsonify({"status": "stopped", "stopped_count": stopped_count}), 200


@api_bp.route("/api/attack/status", methods=["GET"])
def attack_status():
    """Get status of a specific attack or all attack jobs."""
    attack_id = request.args.get("attack_id")
    result = attack_service.get_status(attack_id)
    if attack_id and not result.get("found"):
        return jsonify({"error": f"Attack job '{attack_id}' not found"}), 404
    return jsonify(result), 200


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
