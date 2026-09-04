"""
PS-145 Threat Detection Backend
Flask application factory.
"""
from __future__ import annotations

from typing import Any

# ── 1. Load .env BEFORE any singletons or routes are instantiated ─────────────
from .env_loader import load_env
_loaded_env = load_env()

from flask import Flask
from flask_cors import CORS

from .alert_store import AlertStore
from .stream import StreamManager
from .ai_service import AIService

# Module-level singletons — shared across routes
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
