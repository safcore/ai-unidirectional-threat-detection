"""
PS-145 Threat Detection Backend
Flask application factory.
"""
from __future__ import annotations

from typing import Any

import os
import sys

# Ensure backend directory and project root are in sys.path
_current_dir = os.path.dirname(os.path.abspath(__file__))
_backend_dir = os.path.dirname(_current_dir)
_project_root = os.path.dirname(_backend_dir)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

# ── 1. Load .env BEFORE any singletons or routes are instantiated ─────────────
from .env_loader import load_env
_loaded_env = load_env()

from flask import Flask
from flask_cors import CORS

from .alert_store import AlertStore
from .stream import StreamManager
from .ai_service import AIService

# Initialize storage layer (PostgreSQL if DATABASE_URL is set, else local JSON)
db_url = os.environ.get("DATABASE_URL", "").strip()
if db_url and db_url.startswith("postgres"):
    try:
        from .postgres_store import PostgresAlertStore
        alert_store = PostgresAlertStore(db_url)
        import logging
        logging.getLogger(__name__).info("Connected to PostgreSQL alert store: %s", db_url.split("@")[-1])
    except Exception as exc:
        import logging
        logging.getLogger(__name__).warning("Failed to connect to PostgreSQL (%s), falling back to local JSON store.", exc)
        alert_store = AlertStore()
else:
    alert_store = AlertStore()

stream_manager = StreamManager()
ai_service = AIService()


def create_app(config: dict[str, Any] | None = None) -> Flask:
    """Application factory."""
    app = Flask(__name__)

    # ── CORS ──────────────────────────────────────────────────────────────────
    # Allow the Vite/React dev server on localhost:5173
    CORS(
        app,
        resources={r"/api/*": {"origins": [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
        ]}},
        supports_credentials=False,
    )

    # ── Config overrides (for tests) ──────────────────────────────────────────
    if config is not None:
        app.config.from_mapping(config)

    # ── Register blueprints ───────────────────────────────────────────────────
    from .routes import api_bp
    from .ai_routes import ai_bp
    app.register_blueprint(api_bp)
    app.register_blueprint(ai_bp)

    return app
