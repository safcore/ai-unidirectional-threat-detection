"""
config_loader.py
=================

Tiny wrapper around loading config/thresholds.yaml so no module hard-codes
magic numbers (PROMPT section 27). Cached so we don't re-read the file on
every single flow in a streaming loop.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Any, Dict

import yaml

DEFAULT_CONFIG_PATH = os.path.join(
    os.path.dirname(__file__), "config", "thresholds.yaml"
)


@lru_cache(maxsize=8)
def load_config(path: str = DEFAULT_CONFIG_PATH) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    if not isinstance(config, dict):
        raise ValueError(f"Config at {path} did not parse to a dict")
    return config


def clear_config_cache() -> None:
    """Useful in tests when a test swaps in a custom config file."""
    load_config.cache_clear()
