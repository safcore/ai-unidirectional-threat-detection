"""
attack_gen — Synthetic Attack Traffic Generators for PS-145 SOC Demonstration.
Provides SYN Flood, Port Scan, and DNS Tunnel generators with cancellation support
and safe simulation fallback on Windows / unprivileged environments.
"""

from .syn_flood import SynFloodGenerator
from .port_scan import PortScanGenerator
from .dns_tunnel import DnsTunnelGenerator
from .c2_beacon import C2BeaconGenerator
from .data_exfiltration import DataExfiltrationGenerator
from .tls_metadata import TLSMetadataAnomalyGenerator

__all__ = [
    "SynFloodGenerator",
    "PortScanGenerator",
    "DnsTunnelGenerator",
    "C2BeaconGenerator",
    "DataExfiltrationGenerator",
    "TLSMetadataAnomalyGenerator",
]
