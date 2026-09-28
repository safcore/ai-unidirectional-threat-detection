"""
Module 2 (M2) — Configuration
==============================
Central configuration for M2 Feature Extraction pipeline, window parameters,
NFStream C-engine options, and schema mappings.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class M2Config:
    """
    Configuration options for M2 Feature Extraction.
    """
    # ── Sliding Window Parameters ─────────────────────────────────────────────
    # Team Guide specifies a 30-second window
    window_duration_sec: float = 30.0
    slide_interval_sec: float = 30.0     # 30.0 = tumbling (disjoint); < 30.0 = overlapping
    idle_timeout_sec: float = 5.0        # Flush window if traffic goes silent for this duration
    time_source: str = "packet"          # "packet" (uses packet header timestamps) or "wall_clock"
    max_queue_size: int = 100_000        # Max queue capacity for incoming packets

    # ── NFStream Engine Settings ──────────────────────────────────────────────
    statistical_analysis: bool = True    # Compute bidirectional statistics (IAT, sizes, flags)
    splt_analysis: int = 0               # Sequence Packet Length / Time (0 = disabled)
    n_dissections: int = 20              # Max packets inspected per flow for nDPI dissection
    active_timeout: int = 1800           # Seconds before an active flow expires
    idle_timeout: int = 120              # Seconds of inactivity before an idle flow expires
    accounting_mode: int = 0             # 0 = standard packet + byte counters

    # ── Feature & Schema Settings ─────────────────────────────────────────────
    include_meta_columns: bool = True    # window_id, src_ip, dst_ip, ports, protocol
    include_dpi_features: bool = True    # application_name, application_category_name
    output_csv_path: Optional[str] = None # If set, also writes each DataFrame to CSV
    replace_inf_nan: bool = True         # Automatically replace NaN / Inf with 0.0

    def validate(self) -> None:
        """Validate configuration sanity."""
        if self.window_duration_sec <= 0:
            raise ValueError(f"window_duration_sec must be positive, got {self.window_duration_sec}")
        if self.slide_interval_sec <= 0:
            raise ValueError(f"slide_interval_sec must be positive, got {self.slide_interval_sec}")
        if self.slide_interval_sec > self.window_duration_sec:
            raise ValueError(
                f"slide_interval_sec ({self.slide_interval_sec}) cannot exceed "
                f"window_duration_sec ({self.window_duration_sec})"
            )
        if self.time_source not in ("packet", "wall_clock"):
            raise ValueError(f"Invalid time_source: {self.time_source}. Choose 'packet' or 'wall_clock'.")
