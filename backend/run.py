"""
backend/run.py — Standard production entry point for the NETRION Flask backend.

Run with:
    python run.py
or:
    python -m app.main
"""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

# Ensure backend directory and project root are in sys.path
_backend_dir = Path(__file__).resolve().parent
_project_root = _backend_dir.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))
if str(_backend_dir) not in sys.path:
    sys.path.insert(0, str(_backend_dir))

from app.env_loader import load_env
_env_path = load_env()

from app.main import app, _load_mock_data, ai_service

logger = logging.getLogger("netrion.backend")

if __name__ == "__main__":
    _load_mock_data()

    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_PORT", "5000"))

    logger.info("=" * 60)
    logger.info("  NETRION Threat Detection & Investigation Backend")
    logger.info("  Listening on http://%s:%d", host, port)
    logger.info("  Health:    http://%s:%d/api/health", host, port)
    logger.info("  Alerts:    http://%s:%d/api/alerts", host, port)
    logger.info("  Stream:    http://%s:%d/api/stream", host, port)
    logger.info("  AI Health: http://%s:%d/api/ai/health", host, port)
    ai_status = ai_service.health()
    has_key = bool(os.environ.get("NVIDIA_API_KEY", "").strip())
    logger.info("  AI Key:    %s", "DETECTED (configured)" if has_key else "NOT SET")
    logger.info("  AI Status: %s (model=%s)", ai_status["status"], ai_status["model"])
    logger.info("=" * 60)

    app.run(host=host, port=port, threaded=True, debug=False)
