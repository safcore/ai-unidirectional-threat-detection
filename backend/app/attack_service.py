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

VALID_ATTACK_TYPES = {"syn_flood", "port_scan", "dns_tunnel"}


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
        duration = max(1.0, min(60.0, float(params.get("duration", 10.0))))
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

    def stop_attack(self, attack_id: str) -> Optional[Dict[str, Any]]:
        """Signal an attack job to stop immediately."""
        with self._lock:
            job = self._jobs.get(attack_id)
            if not job:
                return None
            job.stop_event.set()
            if job.status == "running":
                job.status = "stopping"
            return job.to_dict()

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
        with self._lock:
            for job in self._jobs.values():
                if job.status in ("running", "stopping"):
                    job.stop_event.set()
                    job.status = "stopped"
                    job.ended_at = time.time()
                    stopped += 1
        return stopped


# Module-level singleton
attack_service = AttackService()
