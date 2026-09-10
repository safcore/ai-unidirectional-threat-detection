"""
attack_service.py — Thread-safe attack generator service for PS-145 SOC Demonstration.
Manages background attack simulation jobs, tracking, and cancellation.
"""
from __future__ import annotations

import logging
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    from . import alert_store, stream_manager
except ImportError:
    try:
        from app import alert_store, stream_manager
    except ImportError:
        from backend.app import alert_store, stream_manager

VALID_ATTACK_TYPES = {
    "syn_flood",
    "port_scan",
    "dns_tunnel",
    "c2_beacon",
    "data_exfiltration",
    "encrypted_anomaly",
    "tls_metadata",
}


class AttackJob:
    """Represents a single attack generation job."""

    def __init__(
        self,
        job_id: str,
        attack_type: str,
        params: Dict[str, Any],
        stop_event: threading.Event,
    ):
        self.job_id = job_id
        self.attack_type = attack_type
        self.params = params
        self.stop_event = stop_event
        self.status = "running"
        self.started_at = time.time()
        self.ended_at: Optional[float] = None
        self.progress: Dict[str, Any] = {"sent": 0, "open_ports": []}
        self.error: Optional[str] = None
        self.thread: Optional[threading.Thread] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attack_id": self.job_id,
            "attack_type": self.attack_type,
            "status": self.status,
            "params": self.params,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration": (self.ended_at or time.time()) - self.started_at,
            "progress": self.progress,
            "error": self.error,
        }


class AttackService:
    """Thread-safe manager for attack simulation jobs."""

    def __init__(self):
        self._jobs: Dict[str, AttackJob] = {}
        self._lock = threading.Lock()
        self._counter = 0

    def _next_id(self) -> str:
        self._counter += 1
        return f"ATK-{self._counter:03d}"

    def start_attack(self, attack_type: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Start an attack job in a background daemon thread."""
        params = params or {}
        attack_type = attack_type.strip().lower()

        if attack_type not in VALID_ATTACK_TYPES:
            raise ValueError(f"Invalid attack_type '{attack_type}'. Must be one of: {sorted(VALID_ATTACK_TYPES)}")

        # Validate and clamp parameters
        target = str(params.get("target") or "127.0.0.1").strip()
        duration = max(1.0, min(60.0, float(params.get("duration", 2.0))))
        force_simulation = bool(params.get("simulation", True))

        validated_params: Dict[str, Any] = {
            "target": target,
            "duration": duration,
            "simulation": force_simulation,
        }

        if attack_type == "syn_flood":
            port = int(params.get("port", 80))
            rate = max(1, min(1000, int(params.get("rate", 100))))
            validated_params.update({"port": port, "rate": rate})
        elif attack_type == "port_scan":
            start_port = max(1, min(65535, int(params.get("port_start", 1))))
            end_port = max(start_port, min(65535, int(params.get("port_end", min(start_port + 100, 1024)))))
            threads = max(1, min(50, int(params.get("threads", 20))))
            validated_params.update({"port_start": start_port, "port_end": end_port, "threads": threads})
        elif attack_type == "dns_tunnel":
            rate = max(1, min(100, int(params.get("rate", 5))))
            domain = str(params.get("domain", "tunnel.example.com")).strip()
            validated_params.update({"rate": rate, "domain": domain})
        elif attack_type == "c2_beacon":
            port = int(params.get("port", 8443))
            interval = max(0.1, min(10.0, float(params.get("interval", 1.0))))
            validated_params.update({"port": port, "interval": interval})
        elif attack_type == "data_exfiltration":
            port = int(params.get("port", 443))
            rate_kbps = max(10, min(10000, int(params.get("rate_kbps", 500))))
            validated_params.update({"port": port, "rate_kbps": rate_kbps})
        elif attack_type in ("encrypted_anomaly", "tls_metadata"):
            port = int(params.get("port", 443))
            rate = max(1, min(50, int(params.get("rate", 2))))
            ja3 = str(params.get("ja3", "a0e9f5d64349fb13191bc781f81f42e1")).strip()
            validated_params.update({"port": port, "rate": rate, "ja3": ja3})

        with self._lock:
            job_id = self._next_id()
            stop_event = threading.Event()
            job = AttackJob(job_id, attack_type, validated_params, stop_event)
            self._jobs[job_id] = job

        # Spawn background runner
        thread = threading.Thread(
            target=self._run_job,
            args=(job,),
            daemon=True,
            name=f"AttackJob-{job_id}",
        )
        job.thread = thread
        thread.start()

        return job.to_dict()

    def _run_job(self, job: AttackJob) -> None:
        """Worker thread executing the specific attack generator."""
        try:
            # Immediately ingest simulated observable flow into detection pipeline & broadcast via SSE
            self._ingest_attack_detection(job)

            p = job.params
            if job.attack_type == "syn_flood":
                from attack_gen.syn_flood import SynFloodGenerator
                gen = SynFloodGenerator(
                    target_ip=p["target"],
                    target_port=p["port"],
                    rate_pps=p["rate"],
                    duration_sec=p["duration"],
                    force_simulation=p["simulation"],
                    stop_event=job.stop_event,
                )
                sent = gen.run()
                job.progress["sent"] = sent

            elif job.attack_type == "port_scan":
                from attack_gen.port_scan import PortScanGenerator
                gen = PortScanGenerator(
                    target=p["target"],
                    port_start=p["port_start"],
                    port_end=p["port_end"],
                    threads=p["threads"],
                    force_simulation=p["simulation"],
                    stop_event=job.stop_event,
                )
                open_ports = gen.run()
                job.progress["open_ports"] = open_ports
                job.progress["sent"] = gen.scanned

            elif job.attack_type == "dns_tunnel":
                from attack_gen.dns_tunnel import DnsTunnelGenerator
                gen = DnsTunnelGenerator(
                    nameserver=p["target"],
                    base_domain=p["domain"],
                    rate_qps=p["rate"],
                    duration_sec=p["duration"],
                    force_simulation=p["simulation"],
                    stop_event=job.stop_event,
                )
                sent = gen.run()
                job.progress["sent"] = sent

            elif job.attack_type == "c2_beacon":
                from attack_gen.c2_beacon import C2BeaconGenerator
                gen = C2BeaconGenerator(
                    target_ip=p["target"],
                    target_port=p.get("port", 8443),
                    interval_sec=p.get("interval", 1.0),
                    duration_sec=p["duration"],
                    stop_event=job.stop_event,
                )
                sent = gen.run()
                job.progress["sent"] = sent

            elif job.attack_type == "data_exfiltration":
                from attack_gen.data_exfiltration import DataExfiltrationGenerator
                gen = DataExfiltrationGenerator(
                    target_ip=p["target"],
                    target_port=p.get("port", 443),
                    rate_kbps=p.get("rate_kbps", 500),
                    duration_sec=p["duration"],
                    stop_event=job.stop_event,
                )
                bytes_sent = gen.run()
                job.progress["sent"] = bytes_sent
                job.progress["bytes_sent"] = bytes_sent

            elif job.attack_type in ("encrypted_anomaly", "tls_metadata"):
                from attack_gen.tls_metadata import TLSMetadataAnomalyGenerator
                gen = TLSMetadataAnomalyGenerator(
                    target_ip=p["target"],
                    target_port=p.get("port", 443),
                    rate=p.get("rate", 2),
                    duration_sec=p["duration"],
                    ja3_profile=p.get("ja3", "a0e9f5d64349fb13191bc781f81f42e1"),
                    stop_event=job.stop_event,
                )
                sessions = gen.run()
                job.progress["sent"] = sessions
                job.progress["sessions"] = sessions

            with self._lock:
                if job.stop_event.is_set():
                    job.status = "stopped"
                else:
                    job.status = "completed"
                job.ended_at = time.time()

        except Exception as exc:
            logger.exception("Error during attack job %s: %s", job.job_id, exc)
            with self._lock:
                job.status = "error"
                job.error = str(exc)
                job.ended_at = time.time()

    def _ingest_attack_detection(self, job: AttackJob) -> Optional[Dict[str, Any]]:
        """
        Injects the simulated observable attack flow into the canonical M2->M3/M4->M5 pipeline,
        stores the resulting alert in the alert store, and broadcasts it via SSE.
        """
        try:
            from m2_features import adapt_to_canonical_66
            try:
                from app.m4_integration import process_detection
            except ImportError:
                from backend.app.m4_integration import process_detection

            p = job.params
            target_ip = str(p.get("target") or "127.0.0.1").strip()
            target_port = int(p.get("port") or 80)
            duration = float(p.get("duration") or 5.0)
            rate = float(p.get("rate") or 100)

            if job.attack_type == "syn_flood":
                flow_record = {
                    "Destination Port": target_port,
                    "Flow Duration": max(1000.0, duration * 100000.0),
                    "Total Fwd Packets": max(100.0, rate * duration),
                    "Total Backward Packets": 0.0,
                    "Total Length of Fwd Packets": max(4000.0, rate * duration * 40.0),
                    "Total Length of Bwd Packets": 0.0,
                    "Fwd Packet Length Max": 40.0,
                    "Fwd Packet Length Min": 40.0,
                    "Fwd Packet Length Mean": 40.0,
                    "Flow Packets/s": max(5000.0, rate * 100.0),
                    "Flow Bytes/s": max(200000.0, rate * 4000.0),
                    "SYN Flag Count": max(100.0, rate * duration),
                    "ACK Flag Count": 0.0,
                    "FIN Flag Count": 0.0,
                    "src_ip": "192.168.1.105",
                    "dst_ip": target_ip,
                    "src_port": 54321,
                    "dst_port": target_port,
                    "protocol": "TCP",
                }
            elif job.attack_type == "port_scan":
                start_p = int(p.get("port_start") or 1)
                end_p = int(p.get("port_end") or 100)
                flow_record = {
                    "Destination Port": start_p,
                    "Flow Duration": 15000.0,
                    "Total Fwd Packets": float(max(10, end_p - start_p + 1)),
                    "Total Backward Packets": 0.0,
                    "Total Length of Fwd Packets": float(max(10, end_p - start_p + 1) * 40),
                    "Total Length of Bwd Packets": 0.0,
                    "SYN Flag Count": float(max(10, end_p - start_p + 1)),
                    "Flow Packets/s": 8000.0,
                    "src_ip": "172.16.0.99",
                    "dst_ip": target_ip,
                    "src_port": 49152,
                    "dst_port": start_p,
                    "protocol": "TCP",
                }
            elif job.attack_type == "dns_tunnel":
                domain = str(p.get("domain") or "tunnel.example.com").strip()
                flow_record = {
                    "Destination Port": 53,
                    "Flow Duration": 300000.0,
                    "Total Fwd Packets": 50.0,
                    "Total Backward Packets": 5.0,
                    "Total Length of Fwd Packets": 25000.0,
                    "Total Length of Bwd Packets": 500.0,
                    "Fwd Packet Length Max": 512.0,
                    "Fwd Packet Length Mean": 450.0,
                    "src_ip": "192.168.1.42",
                    "dst_ip": target_ip,
                    "src_port": 53535,
                    "dst_port": 53,
                    "protocol": "UDP",
                    "domain": f"aW5maWx0cmF0aW9uLXNlY3JldA.{domain}",
                }
            elif job.attack_type == "c2_beacon":
                flow_record = {
                    "Destination Port": int(p.get("port") or 8443),
                    "Flow Duration": 10000.0,
                    "Total Fwd Packets": 25.0,
                    "Total Backward Packets": 5.0,
                    "Fwd Packet Length Mean": 32.0,
                    "Flow IAT Mean": 1000.0,
                    "src_ip": "192.168.1.55",
                    "dst_ip": target_ip,
                    "src_port": 49876,
                    "dst_port": int(p.get("port") or 8443),
                    "protocol": "TCP",
                }
            elif job.attack_type == "data_exfiltration":
                flow_record = {
                    "Destination Port": int(p.get("port") or 443),
                    "Flow Duration": 50000.0,
                    "Total Fwd Packets": 200.0,
                    "Total Backward Packets": 10.0,
                    "Total Length of Fwd Packets": 500000.0,
                    "Total Length of Bwd Packets": 1000.0,
                    "Fwd Packet Length Max": 1460.0,
                    "src_ip": "192.168.1.77",
                    "dst_ip": target_ip,
                    "src_port": 51234,
                    "dst_port": int(p.get("port") or 443),
                    "protocol": "TCP",
                }
            elif job.attack_type in ("encrypted_anomaly", "tls_metadata"):
                flow_record = {
                    "Destination Port": int(p.get("port") or 443),
                    "Flow Duration": 5000000.0,
                    "Total Fwd Packets": 40.0,
                    "Total Backward Packets": 5.0,
                    "Total Length of Fwd Packets": 60000.0,
                    "Total Length of Bwd Packets": 300.0,
                    "Packet Length Std": 2.0,
                    "Flow IAT Std": 0.02,
                    "src_ip": "10.0.0.45",
                    "dst_ip": target_ip,
                    "src_port": 58210,
                    "dst_port": int(p.get("port") or 443),
                    "protocol": "TCP",
                    "ja3": str(p.get("ja3") or "a0e9f5d64349fb13191bc781f81f42e1"),
                }
            else:
                flow_record = {
                    "Destination Port": target_port,
                    "src_ip": "192.168.1.100",
                    "dst_ip": target_ip,
                    "src_port": 54321,
                    "dst_port": target_port,
                    "protocol": "TCP",
                }

            flow_record["attack_type"] = job.attack_type
            features, metadata = adapt_to_canonical_66(flow_record)
            event, incident, alert = process_detection(features, metadata)

            stored = None
            if alert and "Benign" not in alert.get("threat", ""):
                stored = alert_store.add(alert)
                stream_manager.broadcast(stored)
                logger.info("Attack %s generated alert: %s (%s, severity=%s)",
                            job.job_id, stored.get("alert_id"), stored.get("threat"), stored.get("severity"))

            try:
                from .flow_store import flow_store
                flow_store.record_flow(
                    features=features,
                    metadata=metadata,
                    detection=event,
                    alert_id=stored.get("alert_id") if stored else None,
                    raw_stats={
                        "packet_count": int(flow_record.get("Total Fwd Packets", 100)),
                        "byte_count": int(flow_record.get("Total Length of Fwd Packets", 4000)),
                        "duration_us": float(flow_record.get("Flow Duration", 10000.0)),
                    },
                )
            except Exception as store_err:
                logger.debug("Could not record flow in flow_store: %s", store_err)

            return stored
        except Exception as exc:
            logger.exception("Failed to ingest attack detection alert for %s: %s", job.job_id, exc)
            return None

    def stop_attack(self, attack_id: str) -> Optional[Dict[str, Any]]:
        """Signal an attack job to stop immediately."""
        thread_to_join = None
        with self._lock:
            job = self._jobs.get(attack_id)
            if not job:
                return None
            job.stop_event.set()
            if job.status == "running":
                job.status = "stopping"
            if job.thread and job.thread.is_alive():
                thread_to_join = job.thread
            res = job.to_dict()
        if thread_to_join:
            thread_to_join.join(timeout=0.3)
        return res

    def get_status(self, attack_id: Optional[str] = None) -> Dict[str, Any]:
        """Get status of a specific job or all jobs."""
        with self._lock:
            if attack_id:
                job = self._jobs.get(attack_id)
                if not job:
                    return {"found": False, "attack": None}
                return {"found": True, "attack": job.to_dict()}

            jobs_list = [j.to_dict() for j in self._jobs.values()]
            active_count = sum(1 for j in self._jobs.values() if j.status in ("running", "stopping"))
            return {
                "active_attacks": active_count,
                "total_attacks": len(self._jobs),
                "attacks": jobs_list,
            }

    def stop_all(self) -> int:
        """Stop all running attack jobs."""
        stopped = 0
        threads_to_join = []
        with self._lock:
            for job in self._jobs.values():
                if job.status in ("running", "stopping"):
                    job.stop_event.set()
                    job.status = "stopped"
                    job.ended_at = time.time()
                    stopped += 1
                    if job.thread and job.thread.is_alive():
                        threads_to_join.append(job.thread)
        for t in threads_to_join:
            t.join(timeout=0.3)
        return stopped


# Module-level singleton
attack_service = AttackService()
