"""
Module 2 (M2) — Window Packet Analyzer
=======================================
Performs deep packet-level inspection on packets in a FlowWindow to extract
features not directly available from NFStream's default flow records:
- TTL and TTL variance
- Cumulative TCP flag bitmask
- TCP advertised window size (init, mean, max)
- IP fragment flags (DF count, MF count)
- TCP retransmission count
- Sequential vs random port-access pattern (port scan heuristics)
"""

import struct
import numpy as np
from collections import defaultdict
from typing import List, Dict, Tuple, Any, Optional
import logging

logger = logging.getLogger("m2.packet_analyzer")


def _extract_ip_tcp_details(pkt: Any) -> Dict[str, Any]:
    """
    Extracts raw protocol header details (TTL, TCP window size, sequence number, IP flags)
    from pkt.raw_frame / pkt.raw, falling back to dataclass attributes.
    """
    raw = getattr(pkt, "raw_frame", None) or getattr(pkt, "raw", None) or b""

    ttl = int(getattr(pkt, "ttl", 64) or 64)
    tcp_win = 0
    seq_num = 0
    ip_df = 0
    ip_mf = 0
    frag_offset = 0
    flags = int(getattr(pkt, "flags", 0) or 0)
    payload_len = int(getattr(pkt, "payload_len", 0) or 0)

    # Offset to IPv4 header
    ip_offset = None
    if len(raw) >= 14 and raw[12:14] == b"\x08\x00":
        ip_offset = 14
    elif len(raw) >= 20 and (raw[0] >> 4) == 4:
        ip_offset = 0

    if ip_offset is not None and len(raw) >= ip_offset + 20:
        try:
            # Parse IPv4 header
            # byte 6-7: flags + fragment offset
            flags_frag = struct.unpack_from("!H", raw, ip_offset + 6)[0]
            ip_df = 1 if (flags_frag & 0x4000) else 0
            ip_mf = 1 if (flags_frag & 0x2000) else 0
            frag_offset = flags_frag & 0x1FFF

            # byte 8: TTL
            parsed_ttl = raw[ip_offset + 8]
            if parsed_ttl > 0:
                ttl = parsed_ttl

            ip_proto = raw[ip_offset + 9]
            ihl = (raw[ip_offset] & 0x0F) * 4
            l4_offset = ip_offset + ihl

            # If TCP (protocol 6)
            if ip_proto == 6 and len(raw) >= l4_offset + 20:
                seq_num = struct.unpack_from("!I", raw, l4_offset + 4)[0]
                flags = raw[l4_offset + 13]
                tcp_win = struct.unpack_from("!H", raw, l4_offset + 14)[0]
                tcp_hdr_len = ((raw[l4_offset + 12] >> 4) & 0x0F) * 4
                actual_payload = len(raw) - (l4_offset + tcp_hdr_len)
                if actual_payload >= 0:
                    payload_len = actual_payload
        except Exception:
            pass

    return {
        "ttl": ttl,
        "tcp_win": tcp_win,
        "seq_num": seq_num,
        "ip_df": ip_df,
        "ip_mf": ip_mf,
        "frag_offset": frag_offset,
        "flags": flags,
        "payload_len": payload_len,
    }


class WindowPacketAnalyzer:
    """
    Analyzes all packets in a FlowWindow to produce flow-level metrics and
    host-level port access patterns.
    """

    @classmethod
    def analyze_window_packets(cls, packets: List[Any]) -> Tuple[Dict[Tuple, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
        """
        Processes packets in the window.
        Returns:
            flow_metrics: Dict mapping (src_ip, dst_ip, src_port, dst_port, proto_num) -> metrics dict
            host_patterns: Dict mapping src_ip -> {port_sequentiality_score, port_access_type}
        """
        if not packets:
            return {}, {}

        # 1. Group packets by bidirectional flow key
        flow_packets = defaultdict(list)
        # 2. Track destination ports per source IP in arrival order
        src_port_history = defaultdict(list)

        proto_map = {"TCP": 6, "UDP": 17, "ICMP": 1, "DNS": 17}

        for pkt in packets:
            src_ip = getattr(pkt, "src_ip", "0.0.0.0")
            dst_ip = getattr(pkt, "dst_ip", "0.0.0.0")
            sport = int(getattr(pkt, "src_port", 0) or 0)
            dport = int(getattr(pkt, "dst_port", 0) or 0)
            raw_proto = getattr(pkt, "protocol", "TCP")
            proto = raw_proto if isinstance(raw_proto, int) else proto_map.get(str(raw_proto).upper(), 6)

            details = _extract_ip_tcp_details(pkt)
            details["ts"] = float(getattr(pkt, "timestamp", 0.0) or 0.0)
            details["src_ip"] = src_ip
            details["dst_ip"] = dst_ip
            details["sport"] = sport
            details["dport"] = dport
            details["proto"] = proto

            # Forward key
            key_fwd = (src_ip, dst_ip, sport, dport, proto)
            flow_packets[key_fwd].append(details)

            # Bidirectional key
            bidi_key = (
                tuple(sorted([src_ip, dst_ip])),
                min(sport, dport),
                max(sport, dport),
                proto,
            )
            flow_packets[bidi_key].append(details)

            # Track destination ports accessed by src_ip
            src_port_history[src_ip].append(dport)

        # ── 3. Compute Host Port Access Patterns ──────────────────────────────
        host_patterns = {}
        for src_ip, dports in src_port_history.items():
            unique_ports = []
            for p in dports:
                if not unique_ports or unique_ports[-1] != p:
                    unique_ports.append(p)

            if len(unique_ports) <= 2:
                score = 0.0
                p_type = "SINGLE"
            else:
                diffs = [abs(unique_ports[i + 1] - unique_ports[i]) for i in range(len(unique_ports) - 1)]
                seq_steps = sum(1 for d in diffs if d == 1)
                score = float(seq_steps) / float(len(diffs)) if diffs else 0.0

                if score >= 0.5:
                    p_type = "SEQUENTIAL"
                else:
                    p_type = "RANDOM"

            host_patterns[src_ip] = {
                "port_sequentiality_score": round(score, 4),
                "port_access_type": p_type,
            }

        # ── 4. Compute Per-Flow Metrics ────────────────────────────────────────
        flow_metrics = {}
        for key, p_list in flow_packets.items():
            ttls = [p["ttl"] for p in p_list]
            ttl_mean = float(np.mean(ttls)) if ttls else 64.0
            ttl_std = float(np.std(ttls)) if len(ttls) > 1 else 0.0
            ttl_var = float(ttl_std ** 2)
            ttl_min = float(np.min(ttls)) if ttls else 64.0
            ttl_max = float(np.max(ttls)) if ttls else 64.0

            # TCP flag bitmask (bitwise OR across all packets in the flow)
            flag_bitmask = 0
            for p in p_list:
                flag_bitmask |= int(p["flags"])

            # TCP Window Size
            win_sizes = [p["tcp_win"] for p in p_list if p["tcp_win"] > 0]
            win_init = float(win_sizes[0]) if win_sizes else 0.0
            win_mean = float(np.mean(win_sizes)) if win_sizes else 0.0
            win_max = float(np.max(win_sizes)) if win_sizes else 0.0

            # IP Fragment Flags
            df_count = sum(p["ip_df"] for p in p_list)
            mf_count = sum(p["ip_mf"] for p in p_list)

            # TCP Retransmission detection
            # Duplicate (seq_num, payload_len) in the same direction with payload > 0 or SYN
            seen_seqs = set()
            retransmissions = 0
            for p in p_list:
                if p["proto"] == 6 and (p["payload_len"] > 0 or (p["flags"] & 0x02)):
                    dir_key = (p["src_ip"], p["seq_num"], p["payload_len"])
                    if dir_key in seen_seqs:
                        retransmissions += 1
                    else:
                        seen_seqs.add(dir_key)

            flow_metrics[key] = {
                "ttl_mean": ttl_mean,
                "ttl_std": ttl_std,
                "ttl_var": ttl_var,
                "ttl_min": ttl_min,
                "ttl_max": ttl_max,
                "tcp_flag_bitmask": int(flag_bitmask),
                "tcp_win_init": win_init,
                "tcp_win_mean": win_mean,
                "tcp_win_max": win_max,
                "ip_df_count": int(df_count),
                "ip_mf_count": int(mf_count),
                "retransmission_count": int(retransmissions),
            }

        return flow_metrics, host_patterns
