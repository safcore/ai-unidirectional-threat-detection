"""
Module 2 (M2) — Streaming Window Aggregator
============================================
Consumes individual RawPackets streamed from M1, slices them into deterministic
30-second sliding/tumbling temporal windows, and emits completed FlowWindows.
Zero cross-window state leakage. Thread-safe for multi-worker M1 ingest pipelines.
"""

import time
import threading
import logging
from typing import Callable, List, Optional, Any

from .config import M2Config
from .flow_types import FlowWindow

logger = logging.getLogger("m2.window_aggregator")


class StreamWindowAggregator:
    """
    Streaming 30-second window aggregator.
    Exposes an `.ingest(pkt)` callback compatible with M1 IngestPipeline.add_consumer.
    """

    def __init__(
        self,
        config: Optional[M2Config] = None,
        on_window_ready: Optional[Callable[[FlowWindow], None]] = None,
    ):
        self.config = config or M2Config()
        self.config.validate()
        self.on_window_ready = on_window_ready

        self._lock = threading.Lock()
        self._window_counter = 0
        self._window_start: Optional[float] = None
        self._window_end: Optional[float] = None
        self._current_packets: List[Any] = []
        self._last_packet_time: float = 0.0

        # Metrics
        self.total_packets_received = 0
        self.total_windows_emitted = 0

    def ingest(self, pkt: Any) -> Optional[FlowWindow]:
        """
        Ingest one packet from M1. Thread-safe.
        Called by M1 PacketWorker or pipeline consumers.
        If adding this packet completes a 30-second window, the completed window
        is emitted to `on_window_ready` and returned.
        """
        with self._lock:
            self.total_packets_received += 1
            now = time.time()

            # Determine timestamp
            if self.config.time_source == "packet":
                pkt_ts = getattr(pkt, "timestamp", None)
                if pkt_ts is not None:
                    try:
                        ts = float(pkt_ts)
                    except (ValueError, TypeError):
                        ts = now
                else:
                    ts = now
            else:
                ts = now

            self._last_packet_time = ts

            # Initialize first window
            if self._window_start is None:
                self._window_start = ts
                self._window_end = self._window_start + self.config.window_duration_sec
                self._current_packets = [pkt]
                return None

            # Check if packet belongs to current window
            if ts < self._window_end:
                self._current_packets.append(pkt)
                return None

            # Boundary crossed: Emit current window
            completed_window = self._finalize_current_window(is_final=False)

            # Advance window state
            slide = self.config.slide_interval_sec
            duration = self.config.window_duration_sec

            if slide >= duration:
                # Tumbling / disjoint window: clean state separation
                if ts >= self._window_end + duration:
                    # Large gap in traffic: realign to current packet
                    self._window_start = ts
                else:
                    self._window_start = self._window_end
                self._window_end = self._window_start + duration
                self._current_packets = [pkt]
            else:
                # Overlapping sliding window
                if ts >= self._window_end + duration:
                    # Large gap in traffic: previous buffer is completely outside the new window
                    self._window_start = ts
                    self._window_end = self._window_start + duration
                    self._current_packets = [pkt]
                else:
                    self._window_start += slide
                    self._window_end = self._window_start + duration
                    # Retain only packets that fall inside the new shifted window
                    self._current_packets = [
                        p for p in self._current_packets
                        if float(getattr(p, "timestamp", 0.0) or now) >= self._window_start
                    ]
                    self._current_packets.append(pkt)

            # Deliver completed window
            if completed_window and self.on_window_ready:
                try:
                    self.on_window_ready(completed_window)
                except Exception as e:
                    logger.error("Error in on_window_ready callback: %s", e, exc_info=True)

            return completed_window

    def flush(self) -> Optional[FlowWindow]:
        """
        Closes and emits the current partially filled window (e.g. at end of stream/shutdown).
        Thread-safe.
        """
        with self._lock:
            if not self._current_packets:
                return None

            completed_window = self._finalize_current_window(is_final=True)
            self._current_packets = []
            self._window_start = None
            self._window_end = None

            if completed_window and self.on_window_ready:
                try:
                    self.on_window_ready(completed_window)
                except Exception as e:
                    logger.error("Error in on_window_ready during flush: %s", e, exc_info=True)

            return completed_window

    def _finalize_current_window(self, is_final: bool) -> FlowWindow:
        """Internal helper to construct a FlowWindow from current buffer."""
        self._window_counter += 1
        window_id = f"w_{self._window_counter:04d}"

        start_time = self._window_start if self._window_start is not None else 0.0
        end_time = self._window_end if self._window_end is not None else start_time + self.config.window_duration_sec

        window = FlowWindow(
            window_id=window_id,
            start_time=start_time,
            end_time=end_time,
            packets=list(self._current_packets),
            is_final=is_final,
        )

        self.total_windows_emitted += 1
        logger.debug("Emitted window %s (%d packets)", window.window_id, window.packet_count)
        return window

    def reset(self) -> None:
        """Reset aggregator state completely."""
        with self._lock:
            self._window_counter = 0
            self._window_start = None
            self._window_end = None
            self._current_packets = []
            self._last_packet_time = 0.0
            self.total_packets_received = 0
            self.total_windows_emitted = 0
