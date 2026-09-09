"""
ai_routes.py — Flask Blueprint for all /api/ai/* endpoints.

Endpoints:
  GET  /api/ai/health
  POST /api/ai/analyze/<alert_id>
  POST /api/ai/correlate

The AI layer is purely additive enrichment.
If AI is unavailable, existing alert/SSE pipeline is unaffected.
"""
from __future__ import annotations

import logging
from typing import Any, cast

from flask import Blueprint, jsonify, request

from . import alert_store, ai_service

logger = logging.getLogger(__name__)

ai_bp = Blueprint("ai", __name__)


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/ai/health
# ─────────────────────────────────────────────────────────────────────────────

@ai_bp.route("/api/ai/health", methods=["GET"])
def ai_health():
    """
    Returns AI configuration status without calling the LLM.

    Example response (key configured):
        {"ai_enabled": true, "provider": "NVIDIA", "model": "...", "status": "available"}

    Example response (no key):
        {"ai_enabled": false, "provider": "NVIDIA", "status": "disabled", "reason": "..."}
    """
    return jsonify(ai_service.health())


# ─────────────────────────────────────────────────────────────────────────────
# POST /api/ai/analyze/<alert_id>
# ─────────────────────────────────────────────────────────────────────────────

@ai_bp.route("/api/ai/analyze/<alert_id>", methods=["POST"])
def ai_analyze(alert_id: str):
    """
    Analyze a stored alert with NVIDIA Nemotron 3.5.

    Query params:
      ?refresh=true  — force new analysis, ignore cache

    Returns enriched AI analysis (or fallback error if AI unavailable).
    HTTP 200 for success or graceful fallback; HTTP 404 if alert not found.

    The existing alert object is NOT modified.
    """
    alert: dict[str, Any] | None = None
    try:
        alert = alert_store.get_by_id(alert_id)
        if alert is None:
            body = request.get_json(silent=True) or {}
            candidate = body.get("alert") if isinstance(body.get("alert"), dict) else body
            if isinstance(candidate, dict) and str(candidate.get("alert_id")) == alert_id:
                alert = candidate
            else:
                return jsonify({"error": f"Alert not found: {alert_id}"}), 404

        refresh = request.args.get("refresh", "").lower() in ("true", "1", "yes")
        logger.info("AI analyze request: alert=%s refresh=%s", alert_id, refresh)

        result = ai_service.analyze_alert(alert, refresh=refresh)

        response: dict[str, Any] = {
            "alert": alert,
            "ai_analysis": result,
        }
        return jsonify(response)
    except Exception as exc:
        logger.error("AI: Route exception in /api/ai/analyze/%s: %s", alert_id, exc)
        current_alert = alert if alert is not None else {"alert_id": alert_id}
        return jsonify({
            "alert": current_alert,
            "ai_analysis": {
                "error": "AI service unavailable",
                "reason": str(exc),
                "fallback": True,
            },
        }), 200


# ─────────────────────────────────────────────────────────────────────────────
# POST /api/ai/correlate
# ─────────────────────────────────────────────────────────────────────────────

@ai_bp.route("/api/ai/correlate", methods=["POST"])
def ai_correlate():
    """
    Check whether a set of alerts may be related (attack chain detection).

    Request body:
      {"alert_ids": ["ALT-001", "ALT-002"]}

    Returns:
      {
        "alert_ids": [...],
        "alerts_analyzed": 2,
        "correlation": {
          "related": true,
          "confidence": 0.88,
          "summary": "...",
          "common_indicators": [...],
          "possible_attack_chain": [...],
          "recommended_actions": [...]
        }
      }

    On AI failure returns a fallback error in the "correlation" field.
    """
    try:
        data: Any = request.get_json(silent=True)
        if not data or "alert_ids" not in data:
            return jsonify({
                "error": "Request body must be JSON with 'alert_ids' list"
            }), 400

        raw_alert_ids = data["alert_ids"]
        if not isinstance(raw_alert_ids, list):
            return jsonify({
                "error": "Provide at least 2 alert IDs in 'alert_ids'"
            }), 400

        alert_ids: list[Any] = cast(list[Any], raw_alert_ids)
        if len(alert_ids) < 2:
            return jsonify({
                "error": "Provide at least 2 alert IDs in 'alert_ids'"
            }), 400

        # Resolve alert IDs to alert objects
        alerts: list[dict[str, Any]] = []
        missing: list[str] = []
        for aid in alert_ids:
            aid_str = str(aid)
            a = alert_store.get_by_id(aid_str)
            if a is None:
                missing.append(aid_str)
            else:
                alerts.append(a)

        if missing:
            return jsonify({
                "error": "Some alert IDs not found",
                "missing": missing,
            }), 404

        logger.info("AI correlate request: %s", alert_ids)
        correlation = ai_service.correlate_alerts(alerts)

        return jsonify({
            "alert_ids": alert_ids,
            "alerts_analyzed": len(alerts),
            "correlation": correlation,
        })
    except Exception as exc:
        logger.error("AI: Route exception in /api/ai/correlate: %s", exc)
        return jsonify({
            "error": "AI correlation failed",
            "correlation": {
                "error": "AI service unavailable",
                "reason": str(exc),
                "fallback": True,
            },
        }), 200
