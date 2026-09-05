"""
Module 2 (M2) — M2 Pipeline Coordinator & Production Interface
==============================================================
Implements the M2 production contract defined in the Team Leader Master Guide:
    flow_window → NFStream → feature extraction → FeatureAdapter → pandas DataFrame

Includes:
1. M2Pipeline: The primary production feature extractor for completed FlowWindows.
2. M1WindowBridge: Compatibility bridge aggregating M1's RawPacket stream into
   30-second windows when M1 has not yet implemented native window emission.
3. batch_extract_pcap: Offline / test evaluation helper for full PCAP benchmarking.
"""

import queue
import threading
import logging
import time
from typing import Callable, Optional, Tuple, Generator, List, Any
import pandas as pd

from .config import M2Config
from .flow_types import FlowWindow, WindowMetadata
from .engine import NFStreamEngine
from .window_aggregator import StreamWindowAggregator

logger = logging.getLogger("m2.pipeline")


class M2Pipeline:
    """
    Production M2 Feature Extractor.
    Consumes 30-second FlowWindows, runs NFStream C-dissection and packet analysis,
    and produces strictly-typed, deterministically-ordered pandas DataFrames for M3/M4.

    Production Contract (as defined by Team Leader Master Guide):
        meta, df = pipeline.process_flow_window(flow_window)
    """

    def __init__(self, config: Optional[M2Config] = None):
        self.config = config or M2Config()
        self.config.validate()

        self.engine = NFStreamEngine(config=self.config)

        # Output dispatching
        self.output_queue: queue.Queue[Tuple[WindowMetadata, pd.DataFrame]] = queue.Queue(maxsize=1000)
        self._subscribers: List[Callable[[pd.DataFrame, WindowMetadata], None]] = []

        # Internal compatibility bridge for raw packet streams (used when M1 emits RawPackets)
        self._bridge: Optional["M1WindowBridge"] = None
        self.aggregator = StreamWindowAggregator(
            config=self.config,
            on_window_ready=self.process_flow_window,
        )

        self._queue_worker_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._is_running = False
        self._input_queue: Optional[queue.Queue] = None
        self._latest_result: Optional[Tuple[WindowMetadata, pd.DataFrame]] = None

        # Metrics
        self.windows_processed = 0
        self.flows_extracted = 0

    # ── PRODUCTION API (Team Leader Master Guide) ─────────────────────────────

    def process_flow_window(self, window: FlowWindow) -> Tuple[WindowMetadata, pd.DataFrame]:
        """
        PRODUCTION CONTRACT:
        flow_window → NFStream → feature extraction → FeatureAdapter → pandas DataFrame.

        Accepts a 30-second FlowWindow (from M1 or bridge), executes C-speed flow
        dissection via NFStream, extracts deep packet statistics (TTL, TCP window,
        retransmissions, port patterns), and delivers the DataFrame to M3/M4.
        """
        df = self.engine.extract_from_window(window)
        meta = window.get_metadata(flow_count=len(df))
        self._latest_result = (meta, df)

        self.windows_processed += 1
        self.flows_extracted += len(df)

        # Optional CSV persistence for evaluation / backward compatibility
        if self.config.output_csv_path:
            try:
                df.to_csv(self.config.output_csv_path, index=False)
            except Exception as e:
                logger.error("Could not write CSV to %s: %s", self.config.output_csv_path, e)

        # Enqueue for pull consumers (M3/M4)
        try:
            self.output_queue.put_nowait((meta, df))
        except queue.Full:
            logger.warning("M2 output queue full, dropping oldest window DataFrame")
            try:
                _ = self.output_queue.get_nowait()
                self.output_queue.put_nowait((meta, df))
            except Exception:
                pass

        # Push to registered subscriber callbacks (M3/M4)
        for subscriber in self._subscribers:
            try:
                subscriber(df, meta)
            except Exception as e:
                logger.error("Error in M2 subscriber: %s", e, exc_info=True)

        return meta, df

    def ingest_window(self, window: FlowWindow) -> Tuple[WindowMetadata, pd.DataFrame]:
        """Alias for process_flow_window conforming to streaming ingest naming."""
        return self.process_flow_window(window)

    def subscribe(self, callback: Callable[[pd.DataFrame, WindowMetadata], None]) -> None:
        """Register a downstream callback (e.g. Aayushman's M3 AI model) to receive DataFrames."""
        self._subscribers.append(callback)

    def get_next_window(self, timeout: float = 1.0) -> Tuple[Optional[WindowMetadata], Optional[pd.DataFrame]]:
        """
        Pull-based API for downstream consumers (e.g. M3/M4 threat detector).
        Blocks until the next 30-second window DataFrame is available, or timeout expires.
        """
        try:
            return self.output_queue.get(timeout=timeout)
        except queue.Empty:
            return None, None

    # ── M1 COMPATIBILITY BRIDGE (For RawPacket Streams) ───────────────────────

    def ingest(self, pkt: Any) -> None:
        """
        Compatibility handler when M1 delivers raw packets instead of FlowWindows.
        Buffers packets in StreamWindowAggregator; completed windows automatically
        invoke process_flow_window().
        """
        self.aggregator.ingest(pkt)

    def attach_to_m1(self, m1_pipeline: Any) -> None:
        """Compatibility attachment to Meet's M1 IngestPipeline via add_consumer."""
        if hasattr(m1_pipeline, "add_consumer"):
            m1_pipeline.add_consumer(self.ingest)
            logger.info("M2 attached to M1 IngestPipeline via add_consumer")
        else:
            raise AttributeError("M1 pipeline does not expose 'add_consumer' method")

    def attach_to_queue(self, pkt_queue: queue.Queue) -> None:
        """Compatibility attachment directly to an M1 threading.Queue of RawPacket objects."""
        self._input_queue = pkt_queue
        if self._is_running and (self._queue_worker_thread is None or not self._queue_worker_thread.is_alive()):
            self._queue_worker_thread = threading.Thread(
                target=self._run_queue_worker,
                name="M2-QueueWorker",
                daemon=True,
            )
            self._queue_worker_thread.start()
            logger.info("M2-QueueWorker thread started on attach")

    def start(self) -> None:
        """Start M2 background worker thread (if reading from raw packet queue)."""
        if self._is_running:
            return

        self._stop_event.clear()
        self._is_running = True

        if self._input_queue is not None and (self._queue_worker_thread is None or not self._queue_worker_thread.is_alive()):
            self._queue_worker_thread = threading.Thread(
                target=self._run_queue_worker,
                name="M2-QueueWorker",
                daemon=True,
            )
            self._queue_worker_thread.start()
            logger.info("M2-QueueWorker thread started")

        logger.info("M2Pipeline started (window_duration=%ss)", self.config.window_duration_sec)

    def stop(self, flush: bool = True) -> None:
        """
        Stop M2 pipeline gracefully.
        Flushes the final partial window if flush=True.
        """
        if not self._is_running:
            return

        logger.info("Stopping M2Pipeline...")
        self._stop_event.set()

        if self._queue_worker_thread and self._queue_worker_thread.is_alive():
            self._queue_worker_thread.join(timeout=3.0)

        if flush:
            self.flush()

        self._is_running = False
        logger.info("M2Pipeline stopped. Windows: %d, Flows: %d", self.windows_processed, self.flows_extracted)

    def flush(self) -> Optional[Tuple[WindowMetadata, pd.DataFrame]]:
        """Flush the aggregator's current buffer and extract features immediately."""
        self._latest_result = None
        final_window = self.aggregator.flush()
        if final_window:
            return self._latest_result
        return None

    # ── OFFLINE / TEST UTILITIES (Clearly Separated from Production) ──────────

    def batch_extract_pcap(self, pcap_path: str, window_id: str = "w_eval") -> pd.DataFrame:
        """
        [OFFLINE / EVALUATION UTILITY ONLY]
        Extracts features from an entire PCAP file directly without windowing.
        Used strictly for offline model training, dataset conversion, and benchmarking.
        NOT used in the real-time production streaming path.
        """
        df = self.engine.extract_from_pcap(pcap_path, window_id=window_id)
        if self.config.output_csv_path:
            df.to_csv(self.config.output_csv_path, index=False)
        return df

    # Alias for backward compatibility with existing test runners
    process_pcap = batch_extract_pcap

    def _run_queue_worker(self) -> None:
        """Worker loop pulling packets from attached M1 queue."""
        assert self._input_queue is not None
        while not self._stop_event.is_set():
            try:
                pkt = self._input_queue.get(timeout=0.1)
                self.ingest(pkt)
                self._input_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error("Error in M2 queue worker: %s", e)


class M1WindowBridge:
    """
    Explicit Compatibility Bridge for M1 -> M2 integration.
    Slices raw packets from M1 into 30-second FlowWindows and feeds them to M2.
    """

    def __init__(self, m2_pipeline: M2Pipeline):
        self.m2 = m2_pipeline
        self.aggregator = StreamWindowAggregator(
            config=m2_pipeline.config,
            on_window_ready=self.m2.process_flow_window,
        )

    def ingest(self, pkt: Any) -> Optional[FlowWindow]:
        return self.aggregator.ingest(pkt)

    def flush(self) -> Optional[FlowWindow]:
        return self.aggregator.flush()
