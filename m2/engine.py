"""
Module 2 (M2) — NFStream Feature Extraction Engine
===================================================
Wraps NFStream C-dissection and flow aggregation engine. Executes flow statistical
analysis in pure RAM with micro-PCAP bridges, strictly offline and data-diode compliant.
"""

import os
import logging
import pandas as pd
from typing import Optional, List

from .bootstrap import ensure_nfstream_ready
from .config import M2Config
from .flow_types import FlowWindow
from .packet_adapter import packets_to_temp_pcap
from .adapter import FeatureAdapter
from .packet_analyzer import WindowPacketAnalyzer

logger = logging.getLogger("m2.engine")


class NFStreamEngine:
    """
    Feature extraction engine powered by NFStream.
    Handles PCAP and FlowWindow inputs, executes C-engine statistical dissection,
    and returns standardized, typed pandas DataFrames via FeatureAdapter.
    """

    def __init__(self, config: Optional[M2Config] = None):
        self.config = config or M2Config()
        self.config.validate()
        self._nfstream = ensure_nfstream_ready()
        self.adapter = FeatureAdapter(replace_inf_nan=self.config.replace_inf_nan)

    def extract_from_window(self, window: FlowWindow) -> pd.DataFrame:
        """
        Extract flow features from a 30-second FlowWindow.
        Serializes packets to a transient micro-PCAP, processes through NFStream,
        and returns the mapped, typed pandas DataFrame.
        """
        if window is None or window.is_empty:
            logger.debug("Window %s is empty, returning empty DataFrame", getattr(window, "window_id", "w_empty"))
            return self.adapter.create_empty_dataframe(window_id=getattr(window, "window_id", "w_empty"))

        temp_pcap = None
        try:
            temp_pcap = packets_to_temp_pcap(window.packets, prefix=f"m2_w_{window.window_id}_")
            logger.debug(
                "Extracting features from window %s (%d packets) via %s",
                window.window_id,
                window.packet_count,
                temp_pcap,
            )
            # Run packet-level deep inspection for TTL, TCP window, retransmissions, port patterns
            flow_metrics, host_patterns = WindowPacketAnalyzer.analyze_window_packets(window.packets)
            raw_df = self._run_nfstreamer(temp_pcap)
            adapted_df = self.adapter.adapt(
                raw_df,
                window_id=window.window_id,
                flow_metrics=flow_metrics,
                host_patterns=host_patterns,
            )
            logger.info(
                "Window %s extracted: %d flows from %d packets",
                window.window_id,
                len(adapted_df),
                window.packet_count,
            )
            return adapted_df
        except Exception as e:
            logger.error("Error extracting features from window %s: %s", window.window_id, e, exc_info=True)
            return self.adapter.create_empty_dataframe(window_id=window.window_id)
        finally:
            if temp_pcap and os.path.exists(temp_pcap):
                try:
                    os.remove(temp_pcap)
                except OSError as e:
                    logger.warning("Could not delete temporary pcap %s: %s", temp_pcap, e)

    def extract_from_packets(self, packets: List[object], window_id: str = "w_batch") -> pd.DataFrame:
        """Convenience method to extract features from a raw list of packets."""
        start_ts = getattr(packets[0], "timestamp", 0.0) if packets else 0.0
        end_ts = getattr(packets[-1], "timestamp", 0.0) if packets else 0.0
        window = FlowWindow(window_id=window_id, start_time=start_ts, end_time=end_ts, packets=packets)
        return self.extract_from_window(window)

    def extract_from_pcap(self, pcap_path: str, window_id: str = "w_pcap") -> pd.DataFrame:
        """
        Extract flow features directly from a PCAP / PCAPNG file.
        """
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        logger.debug("Running NFStream on PCAP: %s", pcap_path)
        raw_df = self._run_nfstreamer(pcap_path)
        adapted_df = self.adapter.adapt(raw_df, window_id=window_id)
        logger.info("PCAP %s extracted: %d flows", pcap_path, len(adapted_df))
        return adapted_df

    def _run_nfstreamer(self, source: str) -> pd.DataFrame:
        """Internal runner for nfstream.NFStreamer."""
        streamer = self._nfstream.NFStreamer(
            source=source,
            statistical_analysis=self.config.statistical_analysis,
            splt_analysis=self.config.splt_analysis,
            n_dissections=self.config.n_dissections,
            active_timeout=self.config.active_timeout,
            idle_timeout=self.config.idle_timeout,
            accounting_mode=self.config.accounting_mode,
        )
        return streamer.to_pandas()
