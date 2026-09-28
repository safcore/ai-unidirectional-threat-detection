"""
Module 2 (M2) — Flow Types & Data Containers
=============================================
Defines containers for sliding flow windows, window metadata, and packet collections.
"""

from dataclasses import dataclass, field
from typing import List, Any, Optional
import time


@dataclass
class WindowMetadata:
    """Metadata describing a completed flow window."""
    window_id: str
    start_time: float
    end_time: float
    duration_sec: float
    packet_count: int
    flow_count: int = 0
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "window_id": self.window_id,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_sec": self.duration_sec,
            "packet_count": self.packet_count,
            "flow_count": self.flow_count,
            "created_at": self.created_at,
        }


@dataclass
class FlowWindow:
    """
    A discrete temporal slice of network traffic captured from M1.
    Represents a 30-second (or configured duration) batch of RawPackets.
    """
    window_id: str
    start_time: float
    end_time: float
    packets: List[Any] = field(default_factory=list)
    is_final: bool = False

    @property
    def packet_count(self) -> int:
        return len(self.packets)

    @property
    def duration(self) -> float:
        return max(self.end_time - self.start_time, 0.0)

    @property
    def is_empty(self) -> bool:
        return len(self.packets) == 0

    def get_metadata(self, flow_count: int = 0) -> WindowMetadata:
        return WindowMetadata(
            window_id=self.window_id,
            start_time=self.start_time,
            end_time=self.end_time,
            duration_sec=self.duration,
            packet_count=self.packet_count,
            flow_count=flow_count,
        )
