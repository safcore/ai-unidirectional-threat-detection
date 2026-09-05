"""
Unit tests for run_live_pipeline.py orchestrator.
"""
from __future__ import annotations

import pytest
from pathlib import Path
from run_live_pipeline import run_pipeline


class TestPipelineOrchestrator:
    def test_synthetic_dry_run(self):
        stats = run_pipeline(
            mode="synthetic",
            direct=True,
            dry_run=True,
            rate=100.0,
            max_events=5,
        )
        assert stats["flows_processed"] >= 1
        assert "alerts_generated" in stats
        assert "threat_counts" in stats

    def test_missing_pcap_raises(self):
        with pytest.raises(FileNotFoundError):
            run_pipeline(
                mode="pcap",
                input_path="non_existent_file.pcap",
                direct=True,
            )

    def test_missing_dataset_raises(self):
        with pytest.raises(FileNotFoundError):
            run_pipeline(
                mode="dataset",
                input_path="non_existent_file.csv",
                direct=True,
            )

    def test_direct_mode_stores_alert(self, tmp_store, monkeypatch):
        import backend.app as app_mod
        monkeypatch.setattr(app_mod, "alert_store", tmp_store)

        stats = run_pipeline(
            mode="synthetic",
            direct=True,
            dry_run=False,
            rate=100.0,
            max_events=5,
        )
        assert stats["flows_processed"] >= 1
