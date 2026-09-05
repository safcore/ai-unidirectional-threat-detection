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


def _harmonize_env() -> None:
    """
    Bidirectionally bridge NVIDIA environment variables between Anika's backend
    and Aayushman's M4 client without exposing secrets.
    """
    pairs = [
        ("NVIDIA_API_KEY", "NVIDIA_NIM_API_KEY"),
        ("NVIDIA_MODEL", "NVIDIA_NIM_MODEL"),
        ("NVIDIA_BASE_URL", "NVIDIA_NIM_BASE_URL"),
        ("AI_TIMEOUT_SECS", "NVIDIA_NIM_TIMEOUT"),
    ]
    for k1, k2 in pairs:
        v1 = os.environ.get(k1)
        v2 = os.environ.get(k2)
        if v1 and not v2:
            os.environ[k2] = v1
        elif v2 and not v1:
            os.environ[k1] = v2


def load_env(force: bool = False) -> str | None:
    """
    Find and load .env file into os.environ.
    Tries multiple candidate paths anchored to the codebase location.
    Uses override=True to ensure file values take precedence over empty session variables.
    Returns the resolved path of the loaded .env file, or None if not found.
    """
    global _loaded_path, _load_attempted
    if _load_attempted and not force:
        _harmonize_env()
        return _loaded_path

    _load_attempted = True
    try:
        from dotenv import load_dotenv
    except ImportError:
        logger.warning("python-dotenv is not installed; relying on existing environment variables.")
        _harmonize_env()
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
            _harmonize_env()
            logger.info("Loaded environment from %s", candidate)
            return _loaded_path

    _harmonize_env()
    logger.warning("No .env file found in expected locations: %s", [str(c) for c in candidates])
    return None

