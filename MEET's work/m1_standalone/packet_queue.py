"""
M1 — Packet Queue (threading.Queue Streaming Core)
===================================================
The heart of the ingest layer.

Architecture:
  Producer threads (PcapReplayer / SyntheticTrafficGenerator)
      │
      ▼  put()
  [threading.Queue]  ← BOUNDED — drops if full to avoid OOM
      │
      ▼  get()
  Consumer threads (FlowAggregator in M2, plus StreamMonitor)

The queue is the ONLY path through which data flows.
No packet is ever re-transmitted, no probe is sent.
"""

import threading
import queue
import time
import logging
from typing import Callable, Optional
from pcap_replay import RawPacket

logger = logging.getLogger(__name__)


# ── Shared queue factory ─────────────────────────────────────────────────────

def make_packet_queue(maxsize: int = 100_000) -> queue.Queue:
    """
    Create the bounded shared packet queue.
    maxsize prevents runaway memory growth if consumers fall behind.
    """
    return queue.Queue(maxsize=maxsize)


# ── Consumer worker ──────────────────────────────────────────────────────────

class PacketWorker:
    """
    Pulls packets from the shared queue and calls `handler(packet)`.
    Runs in its own daemon thread.  Multiple workers can share the same queue
    for parallel processing (each packet is consumed exactly once).
    """

    def __init__(
        self,
        pkt_queue: queue.Queue,
        handler: Callable[[RawPacket], None],
        name: str = "PacketWorker",
        stop_event: Optional[threading.Event] = None,
    ):
        self.q = pkt_queue
        self.handler = handler
        self.stop_event = stop_event or threading.Event()
        self._thread = threading.Thread(target=self._run, name=name, daemon=True)
        self.packets_processed = 0
        self.errors = 0

    def start(self):
        self._thread.start()
        logger.info("[%s] started", self._thread.name)

    def stop(self):
        self.stop_event.set()
        self._thread.join(timeout=5)

    def _run(self):
        while not self.stop_event.is_set():
            try:
                pkt: RawPacket = self.q.get(timeout=0.1)
                self.handler(pkt)
                self.packets_processed += 1
                self.q.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                self.errors += 1
                logger.error("[%s] handler error: %s", self._thread.name, e)


# ── Pipeline manager ─────────────────────────────────────────────────────────

class IngestPipeline:
    """
    Wires producers + consumers together around the shared queue.
    Usage:

        pipeline = IngestPipeline(pps=10_000)
        pipeline.add_consumer(flow_aggregator.ingest)
        pipeline.start()
        ...
        pipeline.stop()
    """

    def __init__(
        self,
        pcap_path: Optional[str] = None,
        pps: int = 5_000,
        queue_size: int = 100_000,
        num_workers: int = 2,
        attack_mix: float = 0.30,
    ):
        self.pkt_queue = make_packet_queue(queue_size)
        self._producers = []
        self._workers: list[PacketWorker] = []
        self._consumer_handlers: list[Callable] = []
        self._stop_event = threading.Event()
        self.num_workers = num_workers
        self.pps = pps
        self.pcap_path = pcap_path
        self.attack_mix = attack_mix

    def add_consumer(self, handler: Callable[[RawPacket], None]):
        """Register a packet handler.  Called in worker thread(s)."""
        self._consumer_handlers.append(handler)

    def start(self):
        from pcap_replay import SyntheticTrafficGenerator, PcapReplayer

        # ── Producers ────────────────────────────────────────────────────────
        if self.pcap_path:
            prod = PcapReplayer(
                self.pcap_path, self.pkt_queue,
                loop=True, stop_event=self._stop_event
            )
        else:
            prod = SyntheticTrafficGenerator(
                self.pkt_queue,
                packets_per_sec=self.pps,
                attack_mix=self.attack_mix,
                stop_event=self._stop_event,
            )
        prod.start()
        self._producers.append(prod)

        # ── Consumers ────────────────────────────────────────────────────────
        def dispatch(pkt: RawPacket):
            for h in self._consumer_handlers:
                h(pkt)

        for i in range(self.num_workers):
            w = PacketWorker(
                self.pkt_queue, dispatch,
                name=f"PacketWorker-{i}",
                stop_event=self._stop_event,
            )
            w.start()
            self._workers.append(w)

        logger.info(
            "IngestPipeline started: %d producers, %d workers, queue_size=%d",
            len(self._producers), len(self._workers), self.pkt_queue.maxsize
        )

    def stop(self):
        self._stop_event.set()
        logger.info("IngestPipeline stopping...")

    @property
    def total_processed(self) -> int:
        return sum(w.packets_processed for w in self._workers)

    @property
    def queue_depth(self) -> int:
        return self.pkt_queue.qsize()
