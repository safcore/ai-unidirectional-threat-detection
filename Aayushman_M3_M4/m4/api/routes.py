"""
Flask REST API Endpoint Blueprint for Phase 3 Detection, Phase 4 Investigation & Nemotron AI Analysis.

Endpoints:
  - POST /api/v1/detect (Preserved Phase 3 Endpoint)
  - POST /api/v1/investigations/events (Phase 4 Ingestion Endpoint)
  - GET  /api/v1/incidents (List Incidents)
  - GET  /api/v1/incidents/<incident_id> (Get Incident Details)
  - GET  /api/v1/incidents/<incident_id>/timeline (Get Timeline)
  - GET  /api/v1/incidents/<incident_id>/attack-chain (Get Attack Chain)
  - GET  /api/v1/incidents/<incident_id>/mitre (Get MITRE Mappings)
  - GET  /api/v1/iocs/<ioc_value> (Query Threat Intel IOC)
  - POST /api/v1/ai/analyze (NVIDIA Nemotron AI Analysis Endpoint)
  - GET  /api/v1/health (Service Health Check)
"""

import logging
from flask import Blueprint, request, jsonify
from ml.detection.detection_engine import get_detection_engine
from ml.investigation.incident_manager import get_incident_manager
from m4_threat_classifier.ai.nemotron_client import get_nemotron_client

logger = logging.getLogger(__name__)

api_bp = Blueprint("m4_api", __name__)


@api_bp.route("/api/v1/health", methods=["GET"])
def health_check():
    """Service Health Check Endpoint."""
    nemotron = get_nemotron_client()
    return jsonify({
        "status": "healthy",
        "service": "M4 Threat Detection & Investigation API",
        "phase3_detection": "active",
        "phase4_investigation": "active",
        "nemotron_ai": "configured" if nemotron.is_configured() else "unconfigured",
    }), 200


@api_bp.route("/api/v1/detect", methods=["POST"])
def detect_threat():
    """
    Phase 3 Real-time Threat Detection API Endpoint (Preserved).
    """
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({
                "status": "error",
                "error_type": "MISSING_JSON_BODY",
                "message": "Request body must contain valid JSON.",
            }), 400

        features = data.get("features", data)
        metadata = data.get("metadata", {})

        engine = get_detection_engine()
        event = engine.process(features, metadata=metadata)

        if event.get("status") == "error":
            return jsonify(event), 400

        return jsonify(event), 200

    except Exception as e:
        logger.exception("Error processing /api/v1/detect request")
        return jsonify({
            "status": "error",
            "error_type": "API_PROCESSING_EXCEPTION",
            "message": str(e),
        }), 500


@api_bp.route("/api/v1/investigations/events", methods=["POST"])
def ingest_investigation_event():
    """
    Phase 4 Pipeline Ingestion Endpoint. Accepts flow features or Phase 3 event dict.
    """
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"status": "error", "message": "Missing JSON body"}), 400

        # Step 1: Run Phase 3 Detection if raw features provided
        if "threat_class" not in data:
            features = data.get("features", data)
            metadata = data.get("metadata", {})
            engine = get_detection_engine()
            event = engine.process(features, metadata=metadata)
            if event.get("status") == "error":
                return jsonify(event), 400
        else:
            event = data

        # Step 2: Run Phase 4 Investigation Pipeline
        mgr = get_incident_manager()
        incident = mgr.process_event(event)

        return jsonify({
            "status": "success",
            "event": event,
            "incident": incident.to_dict(),
        }), 200

    except Exception as e:
        logger.exception("Error processing /api/v1/investigations/events request")
        return jsonify({"status": "error", "message": str(e)}), 500


@api_bp.route("/api/v1/incidents", methods=["GET"])
def list_incidents():
    """List all Phase 4 Incidents."""
    mgr = get_incident_manager()
    incidents = [i.to_dict() for i in mgr.list_incidents()]
    return jsonify({"incidents": incidents, "count": len(incidents)}), 200


@api_bp.route("/api/v1/incidents/<incident_id>", methods=["GET"])
def get_incident_details(incident_id: str):
    """Get details for a specific Incident ID."""
    mgr = get_incident_manager()
    inc = mgr.get_incident(incident_id)
    if not inc:
        return jsonify({"status": "error", "message": f"Incident '{incident_id}' not found"}), 404
    return jsonify(inc.to_dict()), 200


@api_bp.route("/api/v1/incidents/<incident_id>/timeline", methods=["GET"])
def get_incident_timeline(incident_id: str):
    """Get chronological timeline for an Incident ID."""
    mgr = get_incident_manager()
    inc = mgr.get_incident(incident_id)
    if not inc:
        return jsonify({"status": "error", "message": f"Incident '{incident_id}' not found"}), 404
    return jsonify({"incident_id": incident_id, "timeline": inc.timeline}), 200


@api_bp.route("/api/v1/incidents/<incident_id>/attack-chain", methods=["GET"])
def get_incident_attack_chain(incident_id: str):
    """Get attack chain progression for an Incident ID."""
    mgr = get_incident_manager()
    inc = mgr.get_incident(incident_id)
    if not inc:
        return jsonify({"status": "error", "message": f"Incident '{incident_id}' not found"}), 404
    return jsonify({"incident_id": incident_id, "attack_chain": inc.attack_chain}), 200


@api_bp.route("/api/v1/incidents/<incident_id>/mitre", methods=["GET"])
def get_incident_mitre_mappings(incident_id: str):
    """Get MITRE ATT&CK technique mappings for an Incident ID."""
    mgr = get_incident_manager()
    inc = mgr.get_incident(incident_id)
    if not inc:
        return jsonify({"status": "error", "message": f"Incident '{incident_id}' not found"}), 404
    return jsonify({"incident_id": incident_id, "mitre_mappings": inc.mitre_mappings}), 200


@api_bp.route("/api/v1/iocs/<ioc_value>", methods=["GET"])
def query_ioc_intelligence(ioc_value: str):
    """Query Threat Intelligence reputation for an IOC value."""
    mgr = get_incident_manager()
    intel_res = mgr.enrichment_engine.local_provider.lookup_ip(ioc_value)
    if intel_res.get("status") == "not_found":
        intel_res = mgr.enrichment_engine.local_provider.lookup_domain(ioc_value)
    return jsonify(intel_res), 200


@api_bp.route("/api/v1/ai/analyze", methods=["POST"])
def analyze_with_ai():
    """
    NVIDIA Nemotron AI Investigation Analysis Endpoint.
    """
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"status": "error", "message": "Missing JSON body"}), 400

        nemotron = get_nemotron_client()
        result = nemotron.analyze_incident(data)

        return jsonify(result.to_dict()), 200

    except Exception as e:
        logger.exception("Error processing /api/v1/ai/analyze request")
        return jsonify({
            "status": "AI_UNAVAILABLE",
            "analysis": None,
            "reason": f"API request error: {str(e)}",
            "deterministic_detection_available": True,
        }), 500
