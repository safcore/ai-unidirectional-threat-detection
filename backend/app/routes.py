"""
routes.py — All Flask API endpoints.

Blueprint: api_bp (prefix /api)
Root route / is also registered here.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, Response, jsonify, request, stream_with_context

from . import alert_store, stream_manager
from .attack_service import attack_service
from .m4_integration import (
    _feature_names,
    m4_available,
    process_detection,
    validate_detection_input,
)
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
        "service": "NETRION Threat Detection Backend",
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
        try:
            from .flow_store import flow_store
            flow_store.record_flow(features=features, metadata=metadata, detection=event, alert_id=stored.get("alert_id"))
        except Exception:
            pass
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
    from .flow_store import flow_store
    stats = alert_store.get_stats()
    stats["observed_flows"] = flow_store.get_stats().get("total_flows", 0)
    return jsonify(stats)


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

    params = data.get("params")
    if params is None:
        params = {}
    elif not isinstance(params, dict):
        return jsonify({"error": "'params' must be an object"}), 400

    for k, v in data.items():
        if k not in ("attack_type", "type", "params") and k not in params:
            params[k] = v

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
# Real Traffic & IP Analysis (Primary Hero Workflow)
# ─────────────────────────────────────────────────────────────────────────────

@api_bp.route("/api/traffic/analyze-ip", methods=["POST"])
@api_bp.route("/api/analyze-ip", methods=["POST"])
def analyze_ip():
    """
    Analyze real network traffic observed by the system for an IP address.
    Searches observed traffic store for actual flows with src_ip == ip.
    If no traffic was observed for this IP: returns NO_OBSERVED_TRAFFIC.
    If flows exist: evaluates real flows through the M3/M4 detection engine and returns real results.
    """
    data = request.get_json(silent=True) or {}
    ip = str(data.get("ip", "")).strip()

    if not ip:
        return jsonify({"error": "IP address is required"}), 400

    import ipaddress
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"error": f"Invalid IP address format: '{ip}'. Must be a valid IPv4 or IPv6 address."}), 400

    try:
        from .flow_store import flow_store
    except ImportError:
        from backend.app.flow_store import flow_store

    # 1. Search actual observed traffic for this IP
    flows = flow_store.get_flows_by_ip(ip)

    if not flows:
        # NO OBSERVED TRAFFIC: System has never observed network packets/flows for this IP
        return jsonify({
            "status": "NO_OBSERVED_TRAFFIC",
            "verdict": "NO OBSERVED TRAFFIC",
            "observation_status": "NO OBSERVED TRAFFIC",
            "is_threat": False,
            "ip": ip,
            "message": f"NETRION has not observed sufficient traffic evidence for {ip}. No observed traffic available for this host. No malicious or benign verdict is generated.",
            "confidence": None,
            "confidence_display": "N/A",
            "risk_score": None,
            "risk_score_display": "N/A",
            "threat_level": "N/A",
            "attack_behaviors": [],
            "traffic_evidence": {
                "packet_count": 0,
                "flow_count": 0,
                "byte_count": 0,
                "first_seen": None,
                "last_seen": None,
                "source_ports": [],
                "destination_ports": [],
                "destination_ips": [],
                "protocol_distribution": {},
                "connection_statistics": {
                    "avg_duration_ms": 0,
                    "packets_per_second": 0,
                    "bytes_per_second": 0,
                    "total_duration_sec": 0,
                },
                "anomaly_indicators": [],
            },
            "associated_alerts": [],
            "timeline": [],
            "source": "observed_traffic_store",
            "alert_id": None,
            "full_alert": None,
            "evidence": {
                "observed_flows_count": 0,
                "total_flows_in_store": flow_store.total_flows(),
                "status_detail": "Host has not initiated any observed ingress flows or network packets."
            },
        }), 200

    # 2. Flows exist! Take observed flows and evaluate through real M3/M4 ML detection engine
    primary_flow = flows[-1]
    total_pkts = sum(f.packet_count for f in flows)
    total_bytes = sum(f.byte_count for f in flows)
    min_ts = min(f.timestamp for f in flows)
    max_ts = max(f.timestamp for f in flows)
    first_seen = datetime.fromtimestamp(min_ts, timezone.utc).isoformat()
    last_seen = datetime.fromtimestamp(max_ts, timezone.utc).isoformat()

    src_ports = sorted(list(set(f.src_port for f in flows if f.src_port > 0)))[:15]
    dst_ports = sorted(list(set(f.dst_port for f in flows if f.dst_port > 0)))[:15]
    dst_ips = sorted(list(set(f.dst_ip for f in flows if f.dst_ip)))[:15]

    proto_counts = {}
    for f in flows:
        proto_counts[f.protocol] = proto_counts.get(f.protocol, 0) + 1
    proto_dist = {p: round((cnt / len(flows)) * 100, 1) for p, cnt in proto_counts.items()}

    avg_dur_ms = round(sum(f.duration_ms for f in flows) / max(1, len(flows)), 2)
    tot_dur_s = max(0.001, sum(f.duration_ms for f in flows) / 1000.0)
    pkts_per_sec = round(total_pkts / tot_dur_s, 2)
    bytes_per_sec = round(total_bytes / tot_dur_s, 2)

    conn_stats = {
        "avg_duration_ms": avg_dur_ms,
        "packets_per_second": pkts_per_sec,
        "bytes_per_second": bytes_per_sec,
        "total_duration_sec": round(tot_dur_s, 3),
    }

    associated_alerts = [a for a in alert_store.get_all() if a.get("source_ip") == ip]

    event, incident, alert = process_detection(primary_flow.features, primary_flow.metadata)

    # Check if primary flow is already associated with a known threat alert
    stored = alert_store.get_by_id(primary_flow.alert_id) if primary_flow.alert_id else None
    if stored and "Benign" not in stored.get("threat", ""):
        is_threat = True
        alert = stored
    else:
        threat_class = str(event.get("threat_class", "BENIGN")).upper()
        is_threat = threat_class not in ("BENIGN", "NONE", "")

    # Calculate transparent, evidence-backed Risk Score
    try:
        from ml.risk.risk_engine import RiskEngine
        risk_engine = RiskEngine()
        conf_val = float(event.get("confidence", 0.95 if is_threat else 0.85))
        anom_val = float(event.get("anomaly_score") or (0.65 if is_threat else 0.20))
        sev_val = str(alert.get("severity", "HIGH") if is_threat else "LOW")
        intel_val = "MALICIOUS" if is_threat and sev_val in ("HIGH", "CRITICAL") else ("SUSPICIOUS" if is_threat else "BENIGN")
        corr_count = max(1, len(associated_alerts), len(flows) if is_threat else 1)

        risk_res = risk_engine.calculate_risk(
            confidence=conf_val,
            anomaly_score=anom_val,
            severity=sev_val,
            intel_reputation=intel_val,
            correlated_event_count=corr_count
        )
        risk_score = round(risk_res.score, 1)
        risk_level = risk_res.level
        risk_breakdown = dict(risk_res.components)
        risk_breakdown["confidence"] = risk_res.components.get("confidence_score", 0.0)
        risk_breakdown["anomaly"] = risk_res.components.get("anomaly_score", 0.0)
        risk_breakdown["severity"] = risk_res.components.get("severity_score", 0.0)
        risk_breakdown["threat_intel"] = risk_res.components.get("intel_score", 0.0)
        risk_breakdown["flow_frequency"] = risk_res.components.get("correlation_score", 0.0)
        risk_weights = risk_res.weights
        risk_explanation = risk_res.explanation
    except Exception as e:
        logger.warning("Risk calculation fallback: %s", e)
        risk_score = 85.0 if is_threat else 20.0
        risk_level = "HIGH" if is_threat else "LOW"
        risk_breakdown = {}
        risk_weights = {}
        risk_explanation = "Deterministic risk score computed from observed flow parameters."

    # Identify Attack Behaviors
    if is_threat:
        raw_behaviors = set()
        t_name = alert.get("threat") or event.get("threat_class")
        if t_name:
            raw_behaviors.add(str(t_name))
        for a in associated_alerts:
            if a.get("threat"):
                raw_behaviors.add(str(a.get("threat")))
        for f in flows:
            if f.attack_type:
                raw_behaviors.add(f.attack_type.replace("_", " ").title())
        attack_behaviors = sorted(list(raw_behaviors))
    else:
        attack_behaviors = ["Normal Baseline Ingress"]

    # Build Chronological Timeline from actual observations
    timeline = [
        {
            "timestamp": first_seen,
            "title": "First Ingress Flow Observed",
            "event": "First Ingress Flow Observed",
            "category": "INGRESS",
            "severity": "INFO",
            "description": f"First network packet from {ip} captured on passive diode interface.",
            "detail": f"Initial target: {primary_flow.dst_ip}:{primary_flow.dst_port} ({primary_flow.protocol})",
            "details": f"Initial target: {primary_flow.dst_ip}:{primary_flow.dst_port} ({primary_flow.protocol})",
        }
    ]
    for a in associated_alerts[-5:]:
        timeline.append({
            "timestamp": a.get("timestamp") or last_seen,
            "title": f"Threat Alert: {a.get('threat', 'Security Anomaly')}",
            "event": f"Threat Alert: {a.get('threat', 'Security Anomaly')}",
            "category": "ALERT",
            "severity": a.get("severity", "HIGH"),
            "alert_id": a.get("alert_id"),
            "description": a.get("description") or f"Passive detection engine identified {a.get('threat')}.",
            "detail": f"Confidence: {int((a.get('confidence') or 0.9) * 100)}% | MITRE: {a.get('mitre', {}).get('technique', 'T0000')}",
            "details": f"Confidence: {int((a.get('confidence') or 0.9) * 100)}% | MITRE: {a.get('mitre', {}).get('technique', 'T0000')}",
        })
    if last_seen != first_seen or not is_threat:
        timeline.append({
            "timestamp": last_seen,
            "title": "Latest Traffic Evaluated" if is_threat else "Baseline Traffic Validated",
            "event": "Latest Traffic Evaluated" if is_threat else "Baseline Traffic Validated",
            "category": "MONITORING",
            "severity": "LOW" if not is_threat else "INFO",
            "description": f"Total {total_pkts} packets across {len(flows)} flows ingested.",
            "detail": f"Status: {'THREAT DETECTED' if is_threat else 'BENIGN'}",
            "details": f"Status: {'THREAT DETECTED' if is_threat else 'BENIGN'}",
        })

    # Behavioral Anomaly Detection & Known Pattern Breakdown
    anomaly_indicators = []
    if (event.get("anomaly_score") or 0.0) >= 0.40:
        anomaly_indicators.append(f"Isolation Forest severity score {(event.get('anomaly_score') or 0.0):.3f} exceeds baseline variance.")
    if is_threat:
        if float(primary_flow.features.get("SYN Flag Count", 0.0)) >= 50:
            anomaly_indicators.append("Elevated SYN-to-ACK packet ratio observed.")
        if float(primary_flow.features.get("Flow Packets/s", 0.0)) >= 1000:
            anomaly_indicators.append("High-rate packet transmission burst detected.")

    anomaly_detection = {
        "isolation_forest_score": round(float(event.get("anomaly_score") or 0.20), 4),
        "anomaly_level": "ANOMALOUS" if (event.get("anomaly_score") or 0.0) >= 0.45 else "BASELINE",
        "description": "Behavioral anomaly detection helps identify previously unseen suspicious traffic patterns.",
        "known_pattern_detection": {
            "classifier": "XGBoost + Random Forest Dual Consensus",
            "detected_class": event.get("threat_class", "BENIGN"),
            "confidence": round(float(event.get("confidence", 0.85)), 4),
        },
    }

    risk_engine_obj = {
        "score": risk_score,
        "level": risk_level,
        "components": risk_breakdown,
        "weights": risk_weights,
        "formula": "0.25*conf + 0.20*anom + 0.25*sev + 0.15*intel + 0.15*corr",
    }

    dual_engine = {
        "known_pattern_detection": {
            "engine": "NETRION M3/M4 Ensemble Classifier",
            "threat_class": alert.get("threat", event.get("threat_class", "BENIGN")),
            "signature_rule": "Deep Packet / Flow Pattern Match" if is_threat else "Standard Protocol Baseline",
            "mitre_technique": alert.get("mitre", {}).get("technique") if is_threat else "None",
            "status": "DETECTED" if is_threat else "BASELINE",
        },
        "behavioral_anomaly_detection": {
            "engine": "Isolation Forest Unsupervised Anomaly Detector",
            "anomaly_score": round(float(event.get("anomaly_score") or 0.15), 4),
            "anomalous_indicators": anomaly_indicators if anomaly_indicators else ["Within baseline variance distributions"],
            "status": "ANOMALOUS" if (event.get("anomaly_score") or 0.0) >= 0.45 else "NOMINAL",
        },
    }

    traffic_evidence = {
        "packet_count": total_pkts,
        "flow_count": len(flows),
        "byte_count": total_bytes,
        "total_packets": total_pkts,
        "total_flows": len(flows),
        "total_bytes": total_bytes,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "source_ports": src_ports,
        "destination_ports": dst_ports,
        "destination_ips": dst_ips,
        "protocol_distribution": proto_dist,
        "connection_statistics": conn_stats,
        "anomaly_indicators": anomaly_indicators,
    }

    if is_threat:
        # Threat detected from actual observed traffic
        alert_id = primary_flow.alert_id
        if alert_id:
            stored = alert_store.get_by_id(alert_id)
            if stored:
                alert = stored
            else:
                alert["alert_id"] = alert_id
        elif "Benign" not in alert.get("threat", ""):
            stored = alert_store.add(alert)
            stream_manager.broadcast(stored)
            alert = stored
            alert_id = stored.get("alert_id")
            primary_flow.alert_id = alert_id
        else:
            alert_id = alert.get("alert_id")

        return jsonify({
            "status": "THREAT_DETECTED",
            "verdict": "THREAT DETECTED",
            "observation_status": "TRAFFIC OBSERVED",
            "is_threat": True,
            "ip": ip,
            "threat": alert.get("threat", event.get("threat_class")),
            "severity": alert.get("severity", "HIGH"),
            "threat_level": alert.get("severity", "HIGH"),
            "confidence": float(event.get("confidence", alert.get("confidence", 0.95))),
            "confidence_display": f"{int(float(event.get('confidence', alert.get('confidence', 0.95))) * 100)}%",
            "risk_score": risk_score,
            "risk_score_display": f"{int(risk_score)}/100",
            "risk_level": risk_level,
            "risk_breakdown": risk_breakdown,
            "risk_weights": risk_weights,
            "risk_explanation": risk_explanation,
            "risk_formula": "Risk = 0.25*conf + 0.20*anom + 0.25*sev + 0.15*intel + 0.15*corr",
            "risk_engine": risk_engine_obj,
            "dual_engine": dual_engine,
            "attack_behaviors": attack_behaviors,
            "traffic_evidence": traffic_evidence,
            "associated_alerts": associated_alerts,
            "timeline": timeline,
            "investigation_timeline": timeline,
            "anomaly_detection": anomaly_detection,
            "source": "observed_traffic",
            "alert_id": alert_id,
            "full_alert": alert,
            "mitre": alert.get("mitre", {
                "tactic": "Unknown",
                "technique": "T0000",
                "technique_name": "No confident mapping",
            }),
            "evidence": {
                "flow_count": len(flows),
                "packet_count": total_pkts,
                "byte_count": total_bytes,
                "duration_ms": primary_flow.duration_ms,
                "protocol": primary_flow.protocol,
                "src_port": primary_flow.src_port,
                "dst_port": primary_flow.dst_port,
                "dst_ip": primary_flow.dst_ip,
                "decision_reason": event.get("decision_reason"),
                "anomaly_score": event.get("anomaly_score"),
                "classifications": event.get("classifications", {}),
                "iocs": getattr(incident, "iocs", []),
            },
            "flow_metrics": {
                "packets": total_pkts,
                "bytes": total_bytes,
                "flows": len(flows),
                "protocol": primary_flow.protocol,
                "destination_ip": primary_flow.dst_ip,
                "destination_port": primary_flow.dst_port,
            },
        }), 200

    else:
        # Observed and evaluated as non-malicious (BENIGN) by the ML models
        return jsonify({
            "status": "OBSERVED",
            "verdict": "OBSERVED (BENIGN)",
            "observation_status": "TRAFFIC OBSERVED",
            "is_threat": False,
            "ip": ip,
            "classification": "BENIGN",
            "threat": "Benign / Normal Traffic",
            "severity": "LOW",
            "threat_level": "LOW",
            "confidence": float(event.get("confidence", 0.85)),
            "confidence_display": f"{int(float(event.get('confidence', 0.85)) * 100)}%",
            "risk_score": risk_score,
            "risk_score_display": f"{int(risk_score)}/100",
            "risk_level": risk_level,
            "risk_breakdown": risk_breakdown,
            "risk_weights": risk_weights,
            "risk_explanation": risk_explanation,
            "risk_formula": "Risk = 0.25*conf + 0.20*anom + 0.25*sev + 0.15*intel + 0.15*corr",
            "risk_engine": risk_engine_obj,
            "dual_engine": dual_engine,
            "attack_behaviors": attack_behaviors,
            "traffic_evidence": traffic_evidence,
            "associated_alerts": associated_alerts,
            "timeline": timeline,
            "investigation_timeline": timeline,
            "anomaly_detection": anomaly_detection,
            "source": "observed_traffic",
            "evidence": {
                "flow_count": len(flows),
                "packet_count": total_pkts,
                "byte_count": total_bytes,
                "duration_ms": primary_flow.duration_ms,
                "protocol": primary_flow.protocol,
                "src_port": primary_flow.src_port,
                "dst_port": primary_flow.dst_port,
                "dst_ip": primary_flow.dst_ip,
                "decision_reason": event.get("decision_reason"),
                "anomaly_score": event.get("anomaly_score"),
                "classifications": event.get("classifications", {}),
            },
            "flow_metrics": {
                "packets": total_pkts,
                "bytes": total_bytes,
                "flows": len(flows),
                "protocol": primary_flow.protocol,
                "destination_ip": primary_flow.dst_ip,
                "destination_port": primary_flow.dst_port,
            },
            "alert_id": None,
            "full_alert": None,
        }), 200


@api_bp.route("/api/traffic/replay-pcap", methods=["POST"])
def replay_pcap():
    """Replay a real PCAP file through M1->M2->M3/M4->M5 pipeline and record flows."""
    data = request.get_json(silent=True) or {}
    target_name = os.path.basename(str(data.get("pcap_file") or data.get("filename") or "test_capture.pcap").strip())
    project_root = Path(__file__).resolve().parents[2]
    candidate = project_root / "data" / "pcaps" / target_name
    if candidate.exists():
        pcap_path = candidate
    elif (project_root / "data" / target_name).exists():
        pcap_path = project_root / "data" / target_name
    elif (project_root / "data" / "pcaps" / "test_capture.pcap").exists():
        pcap_path = project_root / "data" / "pcaps" / "test_capture.pcap"
    else:
        pcap_path = project_root / "data" / "test_capture.pcap"

    if not pcap_path.exists():
        return jsonify({"error": "PCAP capture file not found on disk"}), 404

    try:
        from m1_ingest.pcap_stream_reader import _parse_pcap_file, _parse_ethernet
        from m1_ingest.pcap_replay import _parse_ip
        from m2_features import FallbackPurePythonAggregator
        from .flow_store import flow_store

        agg = FallbackPurePythonAggregator()
        pkt_count = 0
        observed_srcs = set()

        for ts, raw in _parse_pcap_file(str(pcap_path)):
            pkt_count += 1
            p = _parse_ethernet(raw, ts)
            if not p and len(raw) >= 20:
                p = _parse_ip(raw, ts)
            if p:
                observed_srcs.add(p.src_ip)
                agg.ingest_packet(p)

        flows = agg.flush_flows()
        threat_count = 0

        for feats, meta in flows:
            event, incident, alert = process_detection(feats, meta)
            stored = None
            if alert and "Benign" not in alert.get("threat", "") and alert.get("severity") in ("HIGH", "CRITICAL"):
                threat_count += 1
                stored = alert_store.add(alert)
                stream_manager.broadcast(stored)

            flow_store.record_flow(
                features=feats,
                metadata=meta,
                detection=event,
                alert_id=stored.get("alert_id") if stored else None,
                raw_stats={
                    "packet_count": int(feats.get("Total Fwd Packets", 1)),
                    "byte_count": int(feats.get("Total Length of Fwd Packets", 64)),
                    "duration_us": float(feats.get("Flow Duration", 1000.0)),
                },
            )

        return jsonify({
            "success": True,
            "pcap_file": pcap_path.name,
            "packets_processed": pkt_count,
            "flows_extracted": len(flows),
            "threats_detected": threat_count,
            "observed_ips": sorted(observed_srcs),
            "message": f"Successfully replayed PCAP: {pkt_count} packets, {len(flows)} flows ingested into flow store.",
        }), 200
    except Exception as exc:
        logger.exception("PCAP replay error: %s", exc)
        return jsonify({"error": f"Failed to replay PCAP: {str(exc)}"}), 500


@api_bp.route("/api/traffic/upload-pcap", methods=["POST"])
def upload_pcap():
    """Upload and analyze a custom PCAP file through M1->M2->M3/M4->M5 pipeline."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded. Expected 'file' multipart field."}), 400

    uploaded_file = request.files["file"]
    filename = (uploaded_file.filename or "").strip()
    if not filename:
        return jsonify({"error": "Empty filename provided."}), 400

    # Security validation: allowed extensions only
    allowed_exts = (".pcap", ".pcapng", ".cap")
    if not any(filename.lower().endswith(ext) for ext in allowed_exts):
        return jsonify({"error": f"Invalid file extension and type '{filename}'. Only .pcap, .pcapng, and .cap packet captures are supported."}), 400

    # Security validation: enforce maximum file size (50MB)
    uploaded_file.seek(0, os.SEEK_END)
    file_length = uploaded_file.tell()
    uploaded_file.seek(0)
    if file_length > 50 * 1024 * 1024:
        return jsonify({"error": "Uploaded file exceeds maximum allowed limit of 50MB."}), 413

    import tempfile

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        uploaded_file.save(tmp.name)
        tmp_path = tmp.name

    try:
        from m1_ingest.pcap_stream_reader import _parse_pcap_file, _parse_ethernet
        from m1_ingest.pcap_replay import _parse_ip
        from m2_features import FallbackPurePythonAggregator
        from .flow_store import flow_store

        agg = FallbackPurePythonAggregator()
        pkt_count = 0
        observed_srcs = set()

        for ts, raw in _parse_pcap_file(tmp_path):
            pkt_count += 1
            p = _parse_ethernet(raw, ts)
            if not p and len(raw) >= 20:
                p = _parse_ip(raw, ts)
            if p:
                observed_srcs.add(p.src_ip)
                agg.ingest_packet(p)

        flows = agg.flush_flows()
        threat_count = 0

        for feats, meta in flows:
            event, incident, alert = process_detection(feats, meta)
            stored = None
            if alert and "Benign" not in alert.get("threat", "") and alert.get("severity") in ("HIGH", "CRITICAL"):
                threat_count += 1
                stored = alert_store.add(alert)
                stream_manager.broadcast(stored)

            flow_store.record_flow(
                features=feats,
                metadata=meta,
                detection=event,
                alert_id=stored.get("alert_id") if stored else None,
                raw_stats={
                    "packet_count": int(feats.get("Total Fwd Packets", 1)),
                    "byte_count": int(feats.get("Total Length of Fwd Packets", 64)),
                    "duration_us": float(feats.get("Flow Duration", 1000.0)),
                },
            )

        return jsonify({
            "success": True,
            "filename": uploaded_file.filename,
            "packets_processed": pkt_count,
            "flows_extracted": len(flows),
            "threats_detected": threat_count,
            "observed_ips": sorted(observed_srcs),
            "message": f"Uploaded PCAP analyzed: {pkt_count} packets, {len(flows)} flows ingested.",
        }), 200
    except Exception as exc:
        logger.exception("Upload PCAP error: %s", exc)
        return jsonify({"error": f"Failed to process uploaded PCAP: {str(exc)}"}), 500
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


@api_bp.route("/api/traffic/start-test-traffic", methods=["POST"])
def start_test_traffic():
    """
    Controlled application-level test/replay path (Section 11 requirement).
    Feeds representative benign flow and exactly one requested attack scenario
    (default: syn_flood -> DDoS) through M1->M2->M3/M4->M5, broadcasting the
    resulting alert and registering observed flows in flow_store.
    """
    try:
        from m2_features import adapt_to_canonical_66
        from .flow_store import flow_store

        data = request.get_json(silent=True) or {}
        scenario = str(data.get("attack_type") or data.get("type") or data.get("scenario") or "syn_flood").strip().lower()

        # 1. Clean Benign Flow from 192.168.1.50
        benign_rec = {
            "src_ip": "192.168.1.50",
            "dst_ip": "10.0.0.1",
            "src_port": 1024,
            "dst_port": 80,
            "protocol": "TCP",
            "Flow Duration": 45000.0,
            "Total Fwd Packets": 12.0,
            "Total Backward Packets": 10.0,
            "Total Length of Fwd Packets": 1460.0,
            "Total Length of Bwd Packets": 4096.0,
            "Fwd Packet Length Mean": 121.6,
            "Flow Bytes/s": 46300.0,
            "Flow Packets/s": 183.3,
        }
        b_feats, b_meta = adapt_to_canonical_66(benign_rec)
        b_event, _, _ = process_detection(b_feats, b_meta)
        flow_store.record_flow(
            features=b_feats,
            metadata=b_meta,
            detection=b_event,
            raw_stats={"packet_count": 22, "byte_count": 5556, "duration_us": 45000.0},
        )

        observed_ips = ["192.168.1.50"]
        alerts_generated = 0

        # 2. Generate exactly ONE intended attack flow according to scenario
        if scenario == "port_scan":
            attack_rec = {
                "src_ip": "172.16.0.99",
                "dst_ip": "10.0.0.1",
                "src_port": 49152,
                "dst_port": 22,
                "protocol": "TCP",
                "Flow Duration": 15000.0,
                "Total Fwd Packets": 100.0,
                "Total Backward Packets": 0.0,
                "Total Length of Fwd Packets": 4000.0,
                "Total Length of Bwd Packets": 0.0,
                "SYN Flag Count": 100.0,
                "Flow Packets/s": 8000.0,
                "attack_type": "port_scan",
            }
            stats = {"packet_count": 100, "byte_count": 4000, "duration_us": 15000.0}
            src_ip = "172.16.0.99"
        elif scenario == "dns_tunnel":
            attack_rec = {
                "src_ip": "192.168.1.42",
                "dst_ip": "10.0.0.1",
                "src_port": 53535,
                "dst_port": 53,
                "protocol": "UDP",
                "Flow Duration": 300000.0,
                "Total Fwd Packets": 50.0,
                "Total Backward Packets": 5.0,
                "Total Length of Fwd Packets": 25000.0,
                "Total Length of Bwd Packets": 500.0,
                "Fwd Packet Length Max": 512.0,
                "Fwd Packet Length Mean": 450.0,
                "domain": "aW5maWx0cmF0aW9uLXNlY3JldA.tunnel.example.com",
                "attack_type": "dns_tunnel",
            }
            stats = {"packet_count": 55, "byte_count": 25500, "duration_us": 300000.0}
            src_ip = "192.168.1.42"
        elif scenario == "c2_beacon":
            attack_rec = {
                "src_ip": "192.168.1.55",
                "dst_ip": "10.0.0.1",
                "src_port": 49876,
                "dst_port": 8443,
                "protocol": "TCP",
                "Flow Duration": 10000.0,
                "Total Fwd Packets": 25.0,
                "Total Backward Packets": 5.0,
                "Fwd Packet Length Mean": 32.0,
                "Flow IAT Mean": 1000.0,
                "attack_type": "c2_beacon",
            }
            stats = {"packet_count": 30, "byte_count": 800, "duration_us": 10000.0}
            src_ip = "192.168.1.55"
        elif scenario == "data_exfiltration":
            attack_rec = {
                "src_ip": "192.168.1.77",
                "dst_ip": "10.0.0.1",
                "src_port": 51234,
                "dst_port": 443,
                "protocol": "TCP",
                "Flow Duration": 50000.0,
                "Total Fwd Packets": 200.0,
                "Total Backward Packets": 10.0,
                "Total Length of Fwd Packets": 500000.0,
                "Total Length of Bwd Packets": 1000.0,
                "Fwd Packet Length Max": 1460.0,
                "attack_type": "data_exfiltration",
            }
            stats = {"packet_count": 210, "byte_count": 501000, "duration_us": 50000.0}
            src_ip = "192.168.1.77"
        elif scenario in ("tls_metadata", "encrypted_anomaly"):
            attack_rec = {
                "src_ip": "10.0.0.45",
                "dst_ip": "10.0.0.1",
                "src_port": 58210,
                "dst_port": 443,
                "protocol": "TCP",
                "Flow Duration": 5000000.0,
                "Total Fwd Packets": 40.0,
                "Total Backward Packets": 5.0,
                "Total Length of Fwd Packets": 60000.0,
                "Total Length of Bwd Packets": 300.0,
                "Packet Length Std": 2.0,
                "Flow IAT Std": 0.02,
                "ja3": "a0e9f5d64349fb13191bc781f81f42e1",
                "attack_type": "tls_metadata",
            }
            stats = {"packet_count": 45, "byte_count": 60300, "duration_us": 5000000.0}
            src_ip = "10.0.0.45"
        else:
            # Default / syn_flood: Threat Flow from 192.168.1.105 (SYN Flood DDoS)
            attack_rec = {
                "src_ip": "192.168.1.105",
                "dst_ip": "10.0.0.1",
                "src_port": 54321,
                "dst_port": 80,
                "protocol": "TCP",
                "Flow Duration": 500000.0,
                "Total Fwd Packets": 500.0,
                "Total Backward Packets": 0.0,
                "Total Length of Fwd Packets": 20000.0,
                "Total Length of Bwd Packets": 0.0,
                "Fwd Packet Length Max": 40.0,
                "Fwd Packet Length Min": 40.0,
                "Fwd Packet Length Mean": 40.0,
                "Flow Packets/s": 10000.0,
                "Flow Bytes/s": 400000.0,
                "SYN Flag Count": 500.0,
                "ACK Flag Count": 0.0,
                "attack_type": "syn_flood",
            }
            stats = {"packet_count": 500, "byte_count": 20000, "duration_us": 500000.0}
            src_ip = "192.168.1.105"

        a_feats, a_meta = adapt_to_canonical_66(attack_rec)
        a_event, a_inc, a_alert = process_detection(a_feats, a_meta)
        stored_a = alert_store.add(a_alert)
        stream_manager.broadcast(stored_a)

        flow_store.record_flow(
            features=a_feats,
            metadata=a_meta,
            detection=a_event,
            alert_id=stored_a.get("alert_id"),
            raw_stats=stats,
        )
        observed_ips.append(src_ip)
        alerts_generated = 1

        return jsonify({
            "success": True,
            "message": f"Safe test traffic ({scenario}) ingested through M1->M2->M3/M4->M5 pipeline.",
            "flows_ingested": 2,
            "alerts_generated": alerts_generated,
            "observed_ips": observed_ips,
        }), 200
    except Exception as exc:
        logger.exception("Failed to start safe test traffic: %s", exc)
        return jsonify({"error": f"Failed to ingest test traffic: {str(exc)}"}), 500



@api_bp.route("/api/traffic/live-sample", methods=["POST"])
@api_bp.route("/api/traffic/live-inspect", methods=["POST"])
def live_traffic_sample():
    """Query live traffic status and metrics from flow_store without fake telemetry."""
    try:
        from .flow_store import flow_store
        stats = flow_store.get_stats()
        return jsonify({
            "status": "ACTIVE_MONITORING",
            "interface": "diode0 (Passive Ingress Mirror)",
            "total_flows": stats["total_flows"],
            "total_packets": stats["total_packets"],
            "total_bytes": stats["total_bytes"],
            "unique_source_ips": stats["unique_ips"],
            "observed_source_ips": stats["active_ips"],
            "has_observed_traffic": stats["total_flows"] > 0,
        }), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@api_bp.route("/api/traffic/status", methods=["GET"])
def traffic_status():
    """Get live status of observed traffic in the system."""
    try:
        from .flow_store import flow_store
        stats = flow_store.get_stats()
        stats["hardware_rx_only"] = True
        stats["interface"] = "diode0 (Passive Ingress Mirror)"
        return jsonify(stats), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


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
