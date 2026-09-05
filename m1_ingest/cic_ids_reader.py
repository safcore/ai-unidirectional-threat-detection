"""
M1 — CIC-IDS 2017 Streaming Reader
=====================================
Reads CIC-IDS 2017 CSV files ROW BY ROW into a threading.Queue.

CRITICAL RULE: This is NOT batch processing.
  - We NEVER load the entire CSV into memory.
  - We NEVER use pandas.read_csv() on the full file.
  - Every row is read, parsed, and put() into the queue individually.
  - The queue is BOUNDED — if the consumer is slow, the producer
    sleeps rather than accumulating all rows in RAM.

Modes:
  1. TIMESTAMP mode (default):
     Replays rows at their original timing (scaled by speed factor).
     Produces realistic traffic bursts matching the dataset.

  2. RATE mode:
     Replays at a fixed flows/sec regardless of timestamps.
     Good for load testing / benchmarking.

  3. DEMO mode (no CSV file):
     Generates synthetic CIC-IDS-format rows covering all attack types.
     Use this to verify M1 works before the dataset is downloaded.

Usage:
    reader = CICIDSReader(
        csv_paths=["data/cic-ids-2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"],
        flow_queue=my_queue,
        mode="rate",
        target_fps=1000,
    )
    reader.start()
"""

import csv
import os
import queue
import random
import threading
import time
import logging
from pathlib import Path
from typing import List, Optional

from .flow_record import (
    CICFlowRecord, COLUMN_MAP, LABEL_TO_THREAT,
    _safe_float, _safe_int
)

logger = logging.getLogger(__name__)

# ── Normalise a raw CSV header → COLUMN_MAP keys → attribute names ────────────

def _normalise_header(raw_headers: List[str]) -> dict:
    """
    Build a mapping: csv_col_index → normalised_attr_name.
    Strips leading/trailing spaces and handles encoding variants.
    """
    mapping = {}
    for idx, col in enumerate(raw_headers):
        col_clean = col.strip()
        if col_clean in COLUMN_MAP:
            mapping[idx] = COLUMN_MAP[col_clean]
        else:
            # Fuzzy match (handles encoding differences like \x96 vs –)
            for canonical, attr in COLUMN_MAP.items():
                if col_clean.lower() == canonical.lower():
                    mapping[idx] = attr
                    break
    return mapping


def _row_to_normalised_dict(row: List[str], col_map: dict) -> dict:
    """Convert a raw CSV row (list of strings) to a normalised attr dict."""
    d = {}
    for idx, attr in col_map.items():
        if idx < len(row):
            d[attr] = row[idx]
    return d


# ── Main Reader ───────────────────────────────────────────────────────────────

class CICIDSReader:
    """
    Streams CIC-IDS 2017 CSV rows into a threading.Queue one row at a time.

    Parameters
    ----------
    csv_paths : list of str
        Paths to CIC-IDS 2017 CSV files. Multiple files are played
        sequentially. Pass an empty list to use DEMO mode.
    flow_queue : queue.Queue
        The shared M1 threading.Queue.
    mode : str
        'timestamp' — replay at original timing (scaled by speed)
        'rate'      — replay at fixed target_fps flows/sec
        'demo'      — generate synthetic CIC-IDS-format rows
    target_fps : int
        Target flows/sec for 'rate' mode (default 1000).
    speed : float
        Speed multiplier for 'timestamp' mode. 1.0 = real time, 10.0 = 10x.
    loop : bool
        Whether to loop the CSV files when exhausted.
    stop_event : threading.Event
        Set to stop the reader cleanly.
    monitor : StreamMonitor
        Optional — for recording flow counts.
    """

    def __init__(
        self,
        csv_paths: List[str],
        flow_queue: queue.Queue,
        mode: str = "rate",
        target_fps: int = 1000,
        speed: float = 1.0,
        loop: bool = True,
        stop_event: Optional[threading.Event] = None,
        monitor=None,
    ):
        self.csv_paths  = [str(p) for p in csv_paths]
        self.q          = flow_queue
        self.mode       = mode if csv_paths else "demo"
        self.target_fps = target_fps
        self.speed      = speed
        self.loop       = loop
        self.stop_event = stop_event or threading.Event()
        self.monitor    = monitor

        # Stats
        self.rows_read    = 0
        self.rows_dropped = 0
        self.rows_attack  = 0
        self.rows_benign  = 0

        self._thread = threading.Thread(
            target=self._run, name="CICIDSReader", daemon=True
        )

    def start(self):
        self._thread.start()
        logger.info(
            "CICIDSReader started | mode=%s | files=%d | fps=%d",
            self.mode, len(self.csv_paths), self.target_fps,
        )

    def stop(self):
        self.stop_event.set()
        self._thread.join(timeout=5)

    # ── Internal run loop ─────────────────────────────────────────────────────

    def _run(self):
        if self.mode == "demo":
            self._run_demo()
            return

        while not self.stop_event.is_set():
            any_file_ok = False
            for csv_path in self.csv_paths:
                if self.stop_event.is_set():
                    break
                if not os.path.exists(csv_path):
                    logger.warning("CSV not found: %s — skipping", csv_path)
                    continue
                any_file_ok = True
                self._stream_file(csv_path)

            if not any_file_ok:
                logger.warning("No valid CSV files found — switching to DEMO mode")
                self._run_demo()
                return

            if not self.loop:
                break

        logger.info(
            "CICIDSReader done | rows=%d (attack=%d benign=%d drops=%d)",
            self.rows_read, self.rows_attack, self.rows_benign, self.rows_dropped,
        )

    def _stream_file(self, csv_path: str):
        """Stream a single CSV file row by row."""
        logger.info("Streaming: %s", os.path.basename(csv_path))
        interval = 1.0 / self.target_fps if self.mode == "rate" else 0.0

        replay_wall_start = time.time()
        first_ts: Optional[float] = None

        try:
            with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.reader(f)

                # ── Parse header ───────────────────────────────────────────
                try:
                    raw_headers = next(reader)
                except StopIteration:
                    logger.warning("Empty file: %s", csv_path)
                    return

                col_map = _normalise_header(raw_headers)
                if not col_map:
                    logger.error("Could not map any columns in %s", csv_path)
                    return

                logger.info("  Columns mapped: %d / %d", len(col_map), len(raw_headers))

                # ── Stream rows ────────────────────────────────────────────
                for raw_row in reader:
                    if self.stop_event.is_set():
                        return

                    norm = _row_to_normalised_dict(raw_row, col_map)
                    try:
                        flow = CICFlowRecord.from_row(norm)
                    except Exception as e:
                        logger.debug("Row parse error: %s", e)
                        continue

                    # ── Timing ─────────────────────────────────────────────
                    if self.mode == "timestamp":
                        # Use dataset timestamps for realistic replay
                        row_ts = self._parse_timestamp(flow.timestamp_str)
                        if row_ts and first_ts is None:
                            first_ts = row_ts
                        if row_ts and first_ts:
                            relative = (row_ts - first_ts) / self.speed
                            target_wall = replay_wall_start + relative
                            sleep_for = target_wall - time.time()
                            if sleep_for > 0:
                                time.sleep(min(sleep_for, 0.05))
                    elif self.mode == "rate":
                        if interval > 0:
                            time.sleep(interval)

                    # ── Enqueue ────────────────────────────────────────────
                    try:
                        self.q.put_nowait(flow)
                        self.rows_read += 1
                        if flow.is_attack:
                            self.rows_attack += 1
                        else:
                            self.rows_benign += 1
                    except queue.Full:
                        self.rows_dropped += 1

                    if self.monitor:
                        self.monitor.record_flow()

        except Exception as e:
            logger.error("Error streaming %s: %s", csv_path, e, exc_info=True)

    @staticmethod
    def _parse_timestamp(ts_str: str) -> Optional[float]:
        """
        Parse CIC-IDS 2017 timestamp string to epoch float.
        Format: '5/7/2017 9:04'  or  '07/05/2017 09:04:00'
        """
        if not ts_str:
            return None
        from datetime import datetime
        formats = [
            "%m/%d/%Y %H:%M",
            "%m/%d/%Y %H:%M:%S",
            "%d/%m/%Y %H:%M",
            "%d/%m/%Y %H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(ts_str.strip(), fmt)
                return dt.timestamp()
            except ValueError:
                continue
        return None

    # ── Demo mode: synthetic CIC-IDS-format rows ─────────────────────────────

    def _run_demo(self):
        """
        Generate synthetic CIC-IDS-format flow records covering all attack types.
        Used when no real CSV files are available.
        """
        logger.info("DEMO mode: generating synthetic CIC-IDS 2017-format flows")
        interval = 1.0 / self.target_fps if self.target_fps > 0 else 0.0

        attack_labels = list(LABEL_TO_THREAT.keys())

        while not self.stop_event.is_set():
            roll  = random.random()
            label = "BENIGN" if roll < 0.65 else random.choice(attack_labels[1:])
            flow  = self._make_demo_flow(label)

            try:
                self.q.put_nowait(flow)
                self.rows_read += 1
                if flow.is_attack:
                    self.rows_attack += 1
                else:
                    self.rows_benign += 1
            except queue.Full:
                self.rows_dropped += 1

            if self.monitor:
                self.monitor.record_flow()

            if interval > 0:
                time.sleep(interval)

    @staticmethod
    def _make_demo_flow(label: str) -> CICFlowRecord:
        """Generate one synthetic CIC-IDS-format flow for the given label."""
        r = random.random

        def rip():
            return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        def rport(lo=1024, hi=65535):
            return random.randint(lo, hi)

        # Base values (benign-ish)
        base = dict(
            src_ip         = rip(),
            dst_ip         = rip(),
            src_port       = rport(),
            dst_port       = random.choice([80, 443, 22, 8080, 53]),
            protocol       = random.choice(["TCP", "UDP"]),
            timestamp_str  = "",
            flow_duration  = random.uniform(1e4, 1e7),
            total_fwd_pkts = random.randint(3, 200),
            total_bwd_pkts = random.randint(2, 180),
            fwd_bytes      = random.uniform(200, 50000),
            bwd_bytes      = random.uniform(200, 50000),
            pkt_len_mean   = random.uniform(200, 1000),
            pkt_len_std    = random.uniform(20, 200),
            flow_iat_mean  = random.uniform(1e4, 1e6),
            flow_iat_std   = random.uniform(1e3, 5e5),
            fin_flag_count = random.randint(0, 2),
            syn_flag_count = random.randint(0, 2),
            ack_flag_count = random.randint(1, 50),
            rst_flag_count = 0,
            psh_flag_count = random.randint(0, 10),
            urg_flag_count = 0,
            down_up_ratio  = random.uniform(0.5, 2.0),
            avg_pkt_size   = random.uniform(200, 1000),
            init_win_fwd   = random.choice([65535, 8192, 1024, 512]),
            init_win_bwd   = random.choice([65535, 8192, 1024, 512]),
            active_mean    = random.uniform(1e5, 1e7),
            idle_mean      = random.uniform(1e6, 1e8),
            flow_bytes_s   = random.uniform(100, 5000),
            flow_pkts_s    = random.uniform(1, 100),
        )

        # Override with attack-specific characteristics
        if label in ("DDoS", "DoS Hulk", "DoS GoldenEye",
                     "DoS slowloris", "DoS Slowhttptest"):
            base.update(
                total_fwd_pkts = random.randint(1000, 50000),
                syn_flag_count = random.randint(500, 5000),
                ack_flag_count = 0,
                flow_pkts_s    = random.uniform(1000, 10000),
                flow_bytes_s   = random.uniform(50000, 500000),
                pkt_len_mean   = random.uniform(0, 60),
                flow_iat_mean  = random.uniform(10, 1000),
            )
        elif label == "PortScan":
            base.update(
                dst_port       = random.randint(1, 65535),
                syn_flag_count = 1,
                ack_flag_count = 0,
                total_fwd_pkts = 1,
                total_bwd_pkts = 0,
                fwd_bytes      = 0,
                bwd_bytes      = 0,
                flow_duration  = random.uniform(1, 1000),
            )
        elif label in ("FTP-Patator", "SSH-Patator"):
            base.update(
                dst_port       = 21 if "FTP" in label else 22,
                total_fwd_pkts = random.randint(5, 20),
                flow_duration  = random.uniform(1e5, 5e6),
            )
        elif label == "Bot":
            base.update(
                flow_iat_mean  = random.uniform(2.5e7, 3.5e7),  # ~30s beacon
                flow_iat_std   = random.uniform(1e5, 5e5),       # very regular
                total_fwd_pkts = random.randint(2, 8),
                fwd_bytes      = random.uniform(64, 256),
            )
        elif label == "Infiltration":
            base.update(
                fwd_bytes      = random.uniform(500000, 5000000),  # big upload
                bwd_bytes      = random.uniform(100, 500),
                down_up_ratio  = random.uniform(0.0, 0.01),
            )

        # Build the record — pull all values from base, add identity + labels
        import hashlib
        five = f"{base['src_ip']}|{base['dst_ip']}|{base['src_port']}|{base['dst_port']}|{base['protocol']}"
        fid = hashlib.sha256(five.encode()).hexdigest()[:16]

        rec = CICFlowRecord(
            flow_id        = fid,
            label          = label,
            threat_class   = LABEL_TO_THREAT.get(label, "") or "",
            src_ip         = base["src_ip"],
            dst_ip         = base["dst_ip"],
            src_port       = base["src_port"],
            dst_port       = base["dst_port"],
            protocol       = base["protocol"],
            flow_duration  = base["flow_duration"],
            total_fwd_pkts = base["total_fwd_pkts"],
            total_bwd_pkts = base["total_bwd_pkts"],
            fwd_bytes      = base["fwd_bytes"],
            bwd_bytes      = base["bwd_bytes"],
            pkt_len_mean   = base["pkt_len_mean"],
            pkt_len_std    = base["pkt_len_std"],
            flow_iat_mean  = base["flow_iat_mean"],
            flow_iat_std   = base["flow_iat_std"],
            fin_flag_count = base["fin_flag_count"],
            syn_flag_count = base["syn_flag_count"],
            ack_flag_count = base["ack_flag_count"],
            rst_flag_count = base["rst_flag_count"],
            psh_flag_count = base["psh_flag_count"],
            urg_flag_count = base["urg_flag_count"],
            down_up_ratio  = base["down_up_ratio"],
            avg_pkt_size   = base["avg_pkt_size"],
            init_win_fwd   = base["init_win_fwd"],
            init_win_bwd   = base["init_win_bwd"],
            active_mean    = base["active_mean"],
            idle_mean      = base["idle_mean"],
            flow_bytes_s   = base["flow_bytes_s"],
            flow_pkts_s    = base["flow_pkts_s"],
        )
        return rec
