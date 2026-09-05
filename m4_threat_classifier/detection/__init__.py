"""
M4 Advanced Detection Package (DGA, C2, and Data Exfiltration Detectors).
"""

from .dga_detector import DGADetector, DGAResult
from .c2_detector import C2Detector, C2Result
from .exfiltration_detector import ExfiltrationDetector, ExfiltrationResult

__all__ = [
    "DGADetector",
    "DGAResult",
    "C2Detector",
    "C2Result",
    "ExfiltrationDetector",
    "ExfiltrationResult",
]
