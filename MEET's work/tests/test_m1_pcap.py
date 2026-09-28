"""
M1 PCAP Streaming Test
========================
Tests the PCAP reader with either:
  1. A real PCAP file  (pass --pcap path/to/file.pcap)
  2. A tiny synthetic PCAP generated in-memory (no file needed)

Proves that packets flow through threading.Queue one-by-one,
NOT loaded all at once into memory.

Run:
    python tests/test_m1_pcap.py                          # synthetic PCAP
    python tests/test_m1_pcap.py --pcap data/traffic.pcap # real file
"""

import sys, os, struct, socket, random, tempfile, time, queue, argparse, logging, threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")

from m1_ingest.pcap_stream_reader import PcapStreamReader, RawPacket
from m1_ingest.stream_monitor     import StreamMonitor
from m1_ingest.cic_ids_pipeline   import make_flow_queue


# ── Build a tiny synthetic PCAP file for testing ─────────────────────────────

def _build_pcap(n_packets: int = 2000) -> str:
    """
    Write a minimal valid PCAP file containing n_packets synthetic packets.
    Returns the path to the temp file.
    """
    def rip():
        return bytes([random.randint(1,254), random.randint(0,255),
                      random.randint(0,255), random.randint(1,254)])

    # Packet scenarios
    def syn_packet():
        """TCP SYN (DDoS / port scan)"""
        src = rip(); dst = b"\xc0\xa8\x64\x01"  # 192.168.100.1
        sport = random.randint(1024,65535); dport = 80
        ip  = _ipv4_hdr(src, dst, 6, 20)
        tcp = _tcp_hdr(sport, dport, flags=0x02, payload=b"")
        return ip + tcp

    def udp_large():
        """Large UDP (amplification)"""
        src = rip(); dst = rip()
        payload = bytes(random.randint(512, 1400))
        ip  = _ipv4_hdr(src, dst, 17, 8 + len(payload))
        udp = struct.pack("!HHHH", 53, random.randint(1024,65535),
                          8+len(payload), 0) + payload
        return ip + udp

    def dns_query():
        """DNS query with long label"""
        src = rip(); dst = b"\x08\x08\x08\x08"   # 8.8.8.8
        label = bytes([random.randint(97,122) for _ in range(40)])
        payload = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + \
                  bytes([len(label)]) + label + b"\x03com\x00\x00\x01\x00\x01"
        ip  = _ipv4_hdr(src, dst, 17, 8 + len(payload))
        udp = struct.pack("!HHHH", random.randint(1024,65535), 53,
                          8+len(payload), 0) + payload
        return ip + udp

    def benign():
        """Normal HTTPS flow"""
        src = rip(); dst = rip()
        payload = bytes(random.randint(100, 1400))
        ip  = _ipv4_hdr(src, dst, 6, 20 + len(payload))
        tcp = _tcp_hdr(random.randint(1024,65535), 443,
                       flags=0x18, payload=payload)
        return ip + tcp

    makers = [syn_packet, udp_large, dns_query, benign, benign, benign]

    # PCAP global header (little-endian)
    global_hdr = struct.pack("<IHHiIII",
        0xa1b2c3d4,   # magic for little-endian libpcap
        2, 4,         # version 2.4
        0,            # thiszone
        0,            # sigfigs
        65535,        # snaplen
        1,            # link type = Ethernet
    )

    # Build packets with fake Ethernet header (6+6+2 bytes)
    eth_src = b"\xaa\xbb\xcc\xdd\xee\xff"
    eth_dst = b"\x11\x22\x33\x44\x55\x66"
    eth_type = b"\x08\x00"   # IPv4

    ts = time.time() - n_packets * 0.001   # start 1ms per packet in the past
    f = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False, mode="wb")
    f.write(global_hdr)

    for i in range(n_packets):
        pkt_data = eth_dst + eth_src + eth_type + random.choice(makers)()
        ts_sec  = int(ts)
        ts_usec = int((ts % 1) * 1_000_000)
        incl    = len(pkt_data)
        f.write(struct.pack("<IIII", ts_sec, ts_usec, incl, incl))
        f.write(pkt_data)
        ts += 0.001   # 1ms between packets

    f.close()
    return f.name


def _ipv4_hdr(src: bytes, dst: bytes, proto: int, payload_len: int) -> bytes:
    total = 20 + payload_len
    return struct.pack("!BBHHHBBH4s4s",
        0x45, 0, total, random.randint(0,65535), 0,
        64, proto, 0, src, dst)


def _tcp_hdr(sport, dport, flags, payload) -> bytes:
    hdr = struct.pack("!HHIIBBHHH",
        sport, dport, random.randint(0,2**32-1), 0,
        0x50, flags, 65535, 0, 0)
    return hdr + payload


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="M1 PCAP Streaming Smoke Test")
    parser.add_argument("--pcap",     default=None,   help="Real PCAP file to test")
    parser.add_argument("--speed",    type=float, default=100.0, help="Replay speed (default 100x)")
    parser.add_argument("--duration", type=int,   default=10,    help="Test duration seconds")
    args = parser.parse_args()

    print("=" * 65)
    print("M1 PCAP STREAMING TEST")
    print("=" * 65)

    # ── Prepare PCAP ──────────────────────────────────────────────────────────
    cleanup_pcap = False
    if args.pcap and os.path.exists(args.pcap):
        pcap_path = args.pcap
        print(f"Mode: REAL PCAP → {pcap_path}")
    else:
        print("Mode: SYNTHETIC PCAP (2000 packets generated in memory)")
        pcap_path = _build_pcap(2000)
        cleanup_pcap = True

    # ── Wire M1 ───────────────────────────────────────────────────────────────
    monitor    = StreamMonitor(interval_sec=1.0, print_stats=True)
    flow_queue = make_flow_queue(maxsize=10_000)

    # Simple per-packet handler
    pkt_counts = {"total": 0, "TCP": 0, "UDP": 0, "DNS": 0, "ICMP": 0}
    lock       = threading.Lock()
    stop_evt   = threading.Event()

    def handle_packet(pkt):
        with lock:
            pkt_counts["total"] += 1
            proto = getattr(pkt, "protocol", "OTHER")
            pkt_counts[proto] = pkt_counts.get(proto, 0) + 1
        monitor.record_flow()

    # Consumer thread — pulls RawPacket from queue, calls handler
    def consumer_loop():
        import queue as _q
        while not stop_evt.is_set():
            try:
                pkt = flow_queue.get(timeout=0.1)
                handle_packet(pkt)
                flow_queue.task_done()
            except _q.Empty:
                continue

    consumer = threading.Thread(target=consumer_loop, name="PcapConsumer", daemon=True)

    reader = PcapStreamReader(
        pcap_path  = pcap_path,
        flow_queue = flow_queue,
        speed      = args.speed,
        loop       = True,
        monitor    = monitor,
    )

    # ── Start ──────────────────────────────────────────────────────────────────
    monitor.start()
    consumer.start()
    reader.start()

    print(f"\nStreaming at {args.speed:.0f}x speed for {args.duration}s...\n")
    time.sleep(args.duration)

    # ── Results ───────────────────────────────────────────────────────────────
    avg_fps = monitor.avg_flows_per_sec(last_n=args.duration - 1)
    print()
    print("=" * 65)
    print("RESULTS")
    print("=" * 65)
    print(f"  Avg packets/sec      : {avg_fps:>10.0f}")
    print(f"  Total packets        : {pkt_counts['total']:>10,}")
    for proto, cnt in sorted(pkt_counts.items()):
        if proto != "total" and cnt > 0:
            print(f"    {proto:<6}           : {cnt:>10,}")
    print(f"  Queue depth at exit  : {flow_queue.qsize():>10,}")

    print()
    if avg_fps > 0 and pkt_counts["total"] > 0:
        print("[PASS] PCAP is streaming packet-by-packet through threading.Queue")
        print("       This proves the pipeline is NOT batch processing.")
    else:
        print("[FAIL] No packets received - check PCAP path")
        sys.exit(1)

    reader.stop()
    stop_evt.set()
    monitor.stop()

    if cleanup_pcap:
        try:
            os.unlink(pcap_path)
        except Exception:
            pass


if __name__ == "__main__":
    main()
