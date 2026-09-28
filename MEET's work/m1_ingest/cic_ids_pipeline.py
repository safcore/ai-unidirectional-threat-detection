"""
M1 — CIC-IDS 2017 Ingest Pipeline
=====================================
The M1 pipeline wired specifically for CIC-IDS 2017 dataset flows.

Data flow:
  CICIDSReader (producer thread)
       │  put(CICFlowRecord)
       ▼
  threading.Queue  [bounded, 50 000 rows]
       │  get(CICFlowRecord)
       ▼
  FlowWorker (1+ consumer threads)
       │  call handler(CICFlowRecord)
       ▼
  Registered downstream handlers (feature extractor, classifiers)

The queue is the ONLY path — zero return-path traffic,
zero handshakes, zero probes.
"""

import queue
import threading
import time
import logging
from typing import Callable, List, Optional

from m1_ingest.cic_ids_reader import CICIDSReader
from m1_ingest.flow_record import CICFlowRecord

logger = logging.getLogger(__name__)


# ── Factory ───────────────────────────────────────────────────────────────────

def make_flow_queue(maxsize: int = 50_000) -> queue.Queue:
    """
    Create the bounded shared flow queue.
    50 000-row capacity: at 1000 fps that's ~50 seconds of buffer.
    """
    return queue.Queue(maxsize=maxsize)


# ── Consumer worker ───────────────────────────────────────────────────────────

class FlowWorker:
    """
    Pulls CICFlowRecord objects from the queue and calls handler(flow).
    Multiple FlowWorkers can share the same queue for parallelism.
    """

    def __init__(
        self,
        flow_queue: queue.Queue,
        handler: Callable[[CICFlowRecord], None],
        name: str = "FlowWorker",
        stop_event: Optional[threading.Event] = None,
    ):
        self.q          = flow_queue
        self.handler    = handler
        self.stop_event = stop_event or threading.Event()
        self._thread    = threading.Thread(target=self._run, name=name, daemon=True)
        self.flows_processed = 0
        self.errors          = 0

    def start(self):
        self._thread.start()

    def stop(self):
        self.stop_event.set()
        self._thread.join(timeout=5)

    def _run(self):
        while not self.stop_event.is_set():
            try:
                flow: CICFlowRecord = self.q.get(timeout=0.1)
                self.handler(flow)
                self.flows_processed += 1
                self.q.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                self.errors += 1
                logger.error("[%s] handler error: %s", self._thread.name, e)


# ── Pipeline ──────────────────────────────────────────────────────────────────

class CICIDSPipeline:
    """
    Top-level M1 pipeline for CIC-IDS 2017.

    Usage:
        pipeline = CICIDSPipeline(
            csv_paths=["data/cic-ids-2017/Friday-Afternoon-DDos.csv"],
            target_fps=1000,
        )
        pipeline.add_handler(my_feature_extractor)
        pipeline.start()
        ...
        pipeline.stop()
    """

    def __init__(
        self,
        csv_paths: List[str] = None,
        target_fps: int       = 1000,
        mode: str             = "rate",
        speed: float          = 1.0,
        loop: bool            = True,
        queue_size: int       = 50_000,
        num_workers: int      = 2,
        monitor=None,
    ):
        self.csv_paths   = csv_paths or []
        self.target_fps  = target_fps
        self.mode        = mode if self.csv_paths else "demo"
        self.speed       = speed
        self.loop        = loop
        self.queue_size  = queue_size
        self.num_workers = num_workers
        self.monitor     = monitor

        self._stop_event  = threading.Event()
        self.flow_queue   = make_flow_queue(queue_size)
        self._handlers: List[Callable] = []
        self._workers: List[FlowWorker] = []
        self._reader: Optional[CICIDSReader] = None

    def add_handler(self, handler: Callable[[CICFlowRecord], None]):
        """Register a consumer callback (called in worker thread)."""
        self._handlers.append(handler)

    def start(self):
        # ── Producer ─────────────────────────────────────────────────────────
        self._reader = CICIDSReader(
            csv_paths   = self.csv_paths,
            flow_queue  = self.flow_queue,
            mode        = self.mode,
            target_fps  = self.target_fps,
            speed       = self.speed,
            loop        = self.loop,
            stop_event  = self._stop_event,
            monitor     = self.monitor,
        )
        self._reader.start()

        # ── Consumers ────────────────────────────────────────────────────────
        def _dispatch(flow: CICFlowRecord):
            for h in self._handlers:
                h(flow)

        for i in range(self.num_workers):
            w = FlowWorker(
                self.flow_queue, _dispatch,
                name       = f"FlowWorker-{i}",
                stop_event = self._stop_event,
            )
            w.start()
            self._workers.append(w)

        logger.info(
            "CICIDSPipeline started | mode=%s | workers=%d | queue=%d",
            self.mode, len(self._workers), self.queue_size,
        )

    def stop(self):
        self._stop_event.set()
        logger.info(
            "CICIDSPipeline stopped | total_flows=%d",
            self.total_processed,
        )

    @property
    def total_processed(self) -> int:
        return sum(w.flows_processed for w in self._workers)

    @property
    def queue_depth(self) -> int:
        return self.flow_queue.qsize()

    @property
    def reader_stats(self) -> dict:
        if not self._reader:
            return {}
        return {
            "rows_read":    self._reader.rows_read,
            "rows_attack":  self._reader.rows_attack,
            "rows_benign":  self._reader.rows_benign,
            "rows_dropped": self._reader.rows_dropped,
        }
