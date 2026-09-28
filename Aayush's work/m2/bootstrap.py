"""
Module 2 (M2) — NFStream Bootstrap & DLL Initialization
======================================================
Ensures Windows C-extension DLLs (especially wpcap.dll from Npcap) are discoverable
by Python 3.8+ before NFStream's native C-engine (_lib_engine.pyd) is imported.
"""

import os
import sys
import platform
import logging

logger = logging.getLogger("m2.bootstrap")

# Known Npcap / WinPcap installation directories on Windows
NPCAP_CANDIDATE_PATHS = [
    r"C:\Windows\System32\Npcap",
    r"C:\Program Files\Npcap",
    r"C:\Program Files (x86)\Npcap",
]

_BOOTSTRAPPED = False


def bootstrap_environment() -> bool:
    """
    Initialize DLL directories on Windows so NFStream can load wpcap.dll.
    Returns True if bootstrap succeeded or is not needed (non-Windows).
    """
    global _BOOTSTRAPPED
    if _BOOTSTRAPPED:
        return True

    if "windows" in platform.system().lower():
        for path in NPCAP_CANDIDATE_PATHS:
            if os.path.isdir(path):
                try:
                    os.add_dll_directory(path)
                    logger.debug("Added DLL directory: %s", path)
                except Exception as e:
                    logger.warning("Failed to add DLL directory %s: %s", path, e)

        # Also ensure PATH contains Npcap if legacy loaders are invoked
        current_path = os.environ.get("PATH", "")
        for path in NPCAP_CANDIDATE_PATHS:
            if os.path.isdir(path) and path not in current_path:
                os.environ["PATH"] = path + os.pathsep + os.environ["PATH"]

    _BOOTSTRAPPED = True
    return True


def ensure_nfstream_ready():
    """
    Validates that NFStream can be imported and that its native C-engine is functional.
    Raises RuntimeError with clear troubleshooting instructions if it fails.
    """
    bootstrap_environment()
    try:
        import nfstream
        # Test minimal streamer instantiation attribute access
        _ = nfstream.NFStreamer
        return nfstream
    except ImportError as e:
        error_msg = (
            f"Failed to initialize NFStream native engine: {e}\n"
            "Troubleshooting for Windows:\n"
            "1. Verify that Npcap is installed (https://npcap.com/#download).\n"
            "   Ensure 'Install Npcap in WinPcap API-compatible Mode' was checked.\n"
            "2. Verify wpcap.dll exists at C:\\Windows\\System32\\Npcap\\wpcap.dll.\n"
            "3. Ensure sitecustomize.py is placed in Python site-packages calling os.add_dll_directory."
        )
        logger.error(error_msg)
        raise RuntimeError(error_msg) from e


# Automatically bootstrap when this module is loaded
bootstrap_environment()
