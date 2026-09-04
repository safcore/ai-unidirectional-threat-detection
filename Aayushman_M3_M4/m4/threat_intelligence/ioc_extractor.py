"""
IOC Extraction Engine Module.

Extracts and normalizes observable security indicators (IPv4, IPv6, Domain, URL, Port, Protocol, Hash)
from normalized Phase 3 threat events.
"""

import re
import ipaddress
import logging
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class IOC:
    """Structured Indicator of Compromise (IOC) object."""
    ioc_type: str        # IPv4 / IPv6 / Domain / URL / Port / Protocol / Hash
    value: str           # Normalized string value
    first_seen: str
    last_seen: str
    source_event_id: str
    confidence: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def is_valid_ipv4(ip_str: str) -> bool:
    """Validate IPv4 address format."""
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except ValueError:
        return False


def is_valid_ipv6(ip_str: str) -> bool:
    """Validate IPv6 address format."""
    try:
        ipaddress.IPv6Address(ip_str)
        return True
    except ValueError:
        return False


def extract_iocs(event: Dict[str, Any]) -> List[IOC]:
    """
    Extract and normalize observable security indicators from a Phase 3 threat event dictionary.
    """
    iocs: List[IOC] = []
    seen_values: Set[str] = set()

    event_id = event.get("event_id", "unknown-event")
    timestamp = event.get("timestamp", "")
    confidence = float(event.get("confidence", 1.0))

    source_info = event.get("source", {})
    dest_info = event.get("destination", {})

    # Extract IPs
    src_ip = source_info.get("src_ip")
    if src_ip and str(src_ip).strip():
        ip_val = str(src_ip).strip()
        if is_valid_ipv4(ip_val) and ip_val not in seen_values:
            iocs.append(IOC("IPv4", ip_val, timestamp, timestamp, event_id, confidence))
            seen_values.add(ip_val)
        elif is_valid_ipv6(ip_val) and ip_val not in seen_values:
            iocs.append(IOC("IPv6", ip_val, timestamp, timestamp, event_id, confidence))
            seen_values.add(ip_val)

    dst_ip = dest_info.get("dst_ip")
    if dst_ip and str(dst_ip).strip():
        ip_val = str(dst_ip).strip()
        if is_valid_ipv4(ip_val) and ip_val not in seen_values:
            iocs.append(IOC("IPv4", ip_val, timestamp, timestamp, event_id, confidence))
            seen_values.add(ip_val)
        elif is_valid_ipv6(ip_val) and ip_val not in seen_values:
            iocs.append(IOC("IPv6", ip_val, timestamp, timestamp, event_id, confidence))
            seen_values.add(ip_val)

    # Extract Ports
    dst_port = dest_info.get("dst_port")
    if dst_port is not None and str(dst_port).isdigit():
        port_val = f"Port:{dst_port}"
        if port_val not in seen_values:
            iocs.append(IOC("Port", str(dst_port), timestamp, timestamp, event_id, confidence))
            seen_values.add(port_val)

    # Extract Domain if passed in payload
    domain_val = event.get("domain") or source_info.get("domain") or dest_info.get("domain")
    if domain_val and str(domain_val).strip():
        norm_domain = str(domain_val).strip().lower()
        if norm_domain not in seen_values:
            iocs.append(IOC("Domain", norm_domain, timestamp, timestamp, event_id, confidence))
            seen_values.add(norm_domain)

    # Extract Hash if passed in payload
    hash_val = event.get("hash") or event.get("file_hash")
    if hash_val and str(hash_val).strip():
        norm_hash = str(hash_val).strip().lower()
        if norm_hash not in seen_values:
            iocs.append(IOC("Hash", norm_hash, timestamp, timestamp, event_id, confidence))
            seen_values.add(norm_hash)

    return iocs
