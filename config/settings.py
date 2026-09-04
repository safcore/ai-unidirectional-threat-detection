"""
Central configuration settings for M4 Advanced Threat Classifier B.
"""

import os
from pathlib import Path
from typing import List, Dict, Any

# Root base directory
BASE_DIR = Path(__file__).resolve().parent.parent

class Settings:
    """Project-wide configuration parameters."""

    # Paths
    DATA_DIR = BASE_DIR / "data"
    RAW_DATA_DIR = DATA_DIR / "raw"
    PROCESSED_DATA_DIR = DATA_DIR / "processed"
    FEATURE_DATA_DIR = DATA_DIR / "features"
    MODELS_DIR = BASE_DIR / "models"

    # Supported threat categories
    CLASSES: List[str] = ["BENIGN", "DGA", "C2", "DATA_EXFILTRATION"]

    # Feature Engineering Configs
    NGRAM_RANGE: List[int] = [2, 3, 4]
    
    # Model Hyperparameters Defaults
    RANDOM_STATE: int = 42
    TEST_SIZE: float = 0.2
    VALIDATION_SIZE: float = 0.1

    # Nemotron Reasoning Configs
    NEMOTRON_MODEL_NAME: str = "nvidia/nemotron-3-ultra-550b-a55b"
    NEMOTRON_API_KEY: str = os.getenv("NEMOTRON_API_KEY", "")
    NEMOTRON_API_URL: str = os.getenv("NEMOTRON_API_URL", "https://api.nvidia.com/v1/nemotron")

    # API Configs
    API_HOST: str = os.getenv("API_HOST", "0.0.0.0")
    API_PORT: int = int(os.getenv("API_PORT", "5000"))

    @classmethod
    def ensure_directories(cls) -> None:
        """Ensure all required directories exist."""
        for path in [
            cls.RAW_DATA_DIR / "dga",
            cls.RAW_DATA_DIR / "c2",
            cls.RAW_DATA_DIR / "exfiltration",
            cls.PROCESSED_DATA_DIR,
            cls.FEATURE_DATA_DIR,
            cls.MODELS_DIR,
        ]:
            path.mkdir(parents=True, exist_ok=True)
