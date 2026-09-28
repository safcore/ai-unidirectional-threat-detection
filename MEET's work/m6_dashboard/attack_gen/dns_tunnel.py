"""
M6 — DNS Tunnel Traffic Generator
===================================
Simulates dnscat2/iodine-style DNS tunneling by sending DNS queries
with long, high-entropy subdomain labels to a specified nameserver.

Uses stdlib socket (UDP) — no raw sockets needed.
"""

import socket
import struct
import random
import time
import logging
import argparse

logger = logging.getLogger(__name__)


def _encode_dns_name(domain: str) -> bytes:
    """Encode a domain name in DNS wire format."""
    result = b""
    for label in domain.split("."):
        result += bytes([len(label)]) + label.encode()
    return result + b"\x00"


def _build_dns_query(domain: str, qtype: int = 1) -> bytes:
    """Build a DNS query packet."""
    txid    = random.randint(0, 65535)
    flags   = 0x0100   # standard query, recursion desired
    qdcount = 1
    header  = struct.pack("!HHHHHH", txid, flags, qdcount, 0, 0, 0)
    qname   = _encode_dns_name(domain)
    qclass  = 1        # IN
    question = qname + struct.pack("!HH", qtype, qclass)
    return header + question


def _make_dga_label(length: int = 40) -> str:
    """Generate a random high-entropy DNS label (mimics dnscat2 encoding)."""
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choices(chars, k=length))


class DnsTunnelGenerator:
    """
    Sends DNS queries with long, high-entropy subdomain labels.
    Simulates DNS tunnel traffic for detection testing.
    """

    def __init__(
        self,
        nameserver: str = "8.8.8.8",
        base_domain: str = "tunnel.example.com",
        rate_qps: int = 5,         # queries per second
        duration_sec: float = 30.0,
        label_len: int = 50,       # long labels = exfiltration payload
        qtype: int = 16,           # TXT record (common for tunneling)
    ):
        self.ns       = nameserver
        self.domain   = base_domain
        self.rate     = rate_qps
        self.duration = duration_sec
        self.label_len = label_len
        self.qtype    = qtype
        self._sent    = 0

    def run(self):
        interval = 1.0 / self.rate if self.rate > 0 else 0.0
        end_time = time.time() + self.duration
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.5)

        logger.info(
            "DNS Tunnel: sending %d qps to %s (base=%s, label_len=%d)",
            self.rate, self.ns, self.domain, self.label_len
        )

        while time.time() < end_time:
            label  = _make_dga_label(self.label_len)
            fqdn   = f"{label}.{self.domain}"
            pkt    = _build_dns_query(fqdn, qtype=self.qtype)

            try:
                sock.sendto(pkt, (self.ns, 53))
                self._sent += 1
                logger.debug("DNS query: %s", fqdn)
            except OSError as e:
                logger.debug("DNS send error: %s", e)

            if interval > 0:
                time.sleep(interval)

        sock.close()
        logger.info("DNS Tunnel complete: %d queries sent", self._sent)
        return self._sent


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description="DNS Tunnel Generator (demo)")
    parser.add_argument("--ns",       default="8.8.8.8")
    parser.add_argument("--domain",   default="tunnel.example.com")
    parser.add_argument("--rate",     type=int,   default=5)
    parser.add_argument("--duration", type=float, default=10.0)
    parser.add_argument("--label-len",type=int,   default=50)
    args = parser.parse_args()
    gen = DnsTunnelGenerator(args.ns, args.domain, args.rate, args.duration, args.label_len)
    gen.run()
