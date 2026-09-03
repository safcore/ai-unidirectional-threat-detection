"""
env_loader.py — Robust environment variable loader for PS-145.
Determines absolute path to backend/.env regardless of current working directory.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

_loaded_path: str | None = None
_load_attempted = False


def load_env(force: bool = False) -> str | None:
    """
    Find and load .env file into os.environ.
    Tries multiple candidate paths anchored to the codebase location.
    Uses override=True to ensure file values take precedence over empty session variables.
    Returns the resolved path of the loaded .env file, or None if not found.
    """
    global _loaded_path, _load_attempted
    if _load_attempted and not force:
        return _loaded_path

    _load_attempted = True
    try:
        from dotenv import load_dotenv
    except ImportError:
        logger.warning("python-dotenv is not installed; relying on existing environment variables.")
        return None

    app_dir = Path(__file__).resolve().parent       # .../backend/app
    backend_dir = app_dir.parent                   # .../backend
    root_dir = backend_dir.parent                  # .../ps145

    candidates = [
        backend_dir / ".env",
        root_dir / "backend" / ".env",
        root_dir / ".env",
        Path.cwd() / "backend" / ".env",
        Path.cwd() / ".env",
    ]

    for candidate in candidates:
        if candidate.is_file():
            load_dotenv(dotenv_path=candidate, override=True)
            _loaded_path = str(candidate)
            logger.info("Loaded environment from %s", candidate)
            return _loaded_path

    logger.warning("No .env file found in expected locations: %s", [str(c) for c in candidates])
    return None
