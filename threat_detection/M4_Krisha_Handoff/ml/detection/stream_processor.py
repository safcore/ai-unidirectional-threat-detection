"""
Queue-Based Non-Blocking Stream Processor Module.

Enables continuous real-time feature processing via thread-safe queues:
  Upstream Producer -> Feature Queue -> Worker Threads -> Detection Engine -> Event Queue -> Downstream Consumer
"""

import queue
import time
import logging
import threading
from typing import Dict, Any, Optional, List
from ml.detection.detection_engine import get_detection_engine

logger = logging.getLogger(__name__)


class StreamProcessor:
    """
    Multi-threaded queue worker manager for real-time threat detection.
    """

    def __init__(self, max_queue_size: int = 10000, worker_count: int = 2):
        self.input_queue = queue.Queue(maxsize=max_queue_size)
        self.output_queue = queue.Queue(maxsize=max_queue_size)
        self.worker_count = worker_count
        self.workers: List[threading.Thread] = []
        self.is_running = False
        self.processed_count = 0
        self.failed_count = 0
        self.engine = None

    def start(self):
        """Start worker threads."""
        if self.is_running:
            return
        self.engine = get_detection_engine()
        self.is_running = True

        for i in range(self.worker_count):
            t = threading.Thread(target=self._worker_loop, name=f"DetectionWorker-{i+1}", daemon=True)
            t.start()
            self.workers.append(t)
        logger.info(f"Started StreamProcessor with {self.worker_count} worker threads.")

    def stop(self):
        """Stop worker threads."""
        self.is_running = False
        for _ in range(self.worker_count):
            self.input_queue.put(None)  # Poison pill
        for t in self.workers:
            t.join(timeout=2.0)
        self.workers.clear()
        logger.info("Stopped StreamProcessor workers.")

    def submit_flow(self, features: Dict[str, Any], metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Submit a flow feature vector to input queue (non-blocking)."""
        if not self.is_running:
            self.start()
        try:
            self.input_queue.put_nowait({"features": features, "metadata": metadata})
            return True
        except queue.Full:
            logger.warning("StreamProcessor input queue is FULL. Dropping flow vector!")
            self.failed_count += 1
            return False

    def get_event(self, block: bool = True, timeout: Optional[float] = 1.0) -> Optional[Dict[str, Any]]:
        """Fetch next processed Threat Event from output queue."""
        try:
            return self.output_queue.get(block=block, timeout=timeout)
        except queue.Empty:
            return None

    def _worker_loop(self):
        """Worker thread loop consuming flows from input queue."""
        while self.is_running:
            try:
                item = self.input_queue.get(timeout=0.5)
                if item is None:  # Poison pill signal
                    break

                features = item.get("features", {})
                metadata = item.get("metadata")

                # Run Detection Engine (Exception safe)
                event = self.engine.process(features, metadata=metadata)
                
                try:
                    self.output_queue.put_nowait(event)
                    self.processed_count += 1
                except queue.Full:
                    logger.warning("StreamProcessor output queue is FULL. Dropping event!")
                    self.failed_count += 1

                self.input_queue.task_done()

            except queue.Empty:
                continue
            except Exception as e:
                logger.exception("Error in StreamProcessor worker loop.")
                self.failed_count += 1
