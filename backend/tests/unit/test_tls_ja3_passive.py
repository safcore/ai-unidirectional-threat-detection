"""
test_tls_passive_extraction.py
==============================
Validates:
1. Genuinely passive raw ClientHello parsing (without decryption).
2. Standard JA3 MD5 computation with GREASE filtering.
3. Standard JA4 observable client fingerprint calculation.
4. Handling incomplete/corrupt payloads gracefully (returns None without fabricating hashes).
"""
from __future__ import annotations

import pytest
from ml.detection.tls_metadata_detector import (
    parse_tls_client_hello,
    TLSMetadataDetector,
    GREASE_VALUES,
)


def _build_client_hello(ciphers_list, exts_list=None, sni_name=None, is_tls13=False):
    client_ver = bytes([0x03, 0x03])
    random_bytes = bytes(32)
    sess_id = bytes([0x00])

    ciphers_bytes = bytearray()
    for c in ciphers_list:
        ciphers_bytes.extend([(c >> 8) & 0xFF, c & 0xFF])
    ciphers_field = bytes([(len(ciphers_bytes) >> 8) & 0xFF, len(ciphers_bytes) & 0xFF]) + bytes(ciphers_bytes)

    comp_field = bytes([0x01, 0x00])

    ext_payload = bytearray()
    if sni_name:
        sni_enc = sni_name.encode("utf-8")
        # RFC 6066:
        # server_name_list_length (2 bytes)
        # name_type (1 byte, 0x00 = host_name)
        # name_length (2 bytes)
        # host_name (N bytes)
        inner = bytes([0x00]) + bytes([(len(sni_enc) >> 8) & 0xFF, len(sni_enc) & 0xFF]) + sni_enc
        sni_data = bytes([(len(inner) >> 8) & 0xFF, len(inner) & 0xFF]) + inner
        ext_payload.extend([0x00, 0x00])
        ext_payload.extend([(len(sni_data) >> 8) & 0xFF, len(sni_data) & 0xFF])
        ext_payload.extend(sni_data)

    if is_tls13:
        sv_data = bytes([0x02, 0x03, 0x04])
        ext_payload.extend([0x00, 0x2B])
        ext_payload.extend([(len(sv_data) >> 8) & 0xFF, len(sv_data) & 0xFF])
        ext_payload.extend(sv_data)

    if exts_list:
        for ext_id in exts_list:
            ext_payload.extend([(ext_id >> 8) & 0xFF, ext_id & 0xFF])
            ext_payload.extend([0x00, 0x00])

    exts_field = bytes([(len(ext_payload) >> 8) & 0xFF, len(ext_payload) & 0xFF]) + bytes(ext_payload)

    body = client_ver + random_bytes + sess_id + ciphers_field + comp_field + exts_field
    hs_msg = bytes([0x01, 0x00, (len(body) >> 8) & 0xFF, len(body) & 0xFF]) + body
    rec = bytes([0x16, 0x03, 0x01, (len(hs_msg) >> 8) & 0xFF, len(hs_msg) & 0xFF]) + hs_msg
    return rec


def test_tls_passive_parsing_and_fingerprinting():
    ciphers = [0x0A0A, 0xC02F, 0xC030, 0x009E]
    exts = [0x000A, 0x000B, 0x1A1A]
    pkt = _build_client_hello(ciphers_list=ciphers, exts_list=exts, sni_name="malicious-beacon.corp", is_tls13=True)

    parsed = parse_tls_client_hello(pkt)
    assert parsed is not None
    assert parsed["sni"] == "malicious-beacon.corp"
    assert parsed["has_tls13"] is True
    for c in parsed["ciphers"]:
        assert c not in GREASE_VALUES
    for e in parsed["extensions"]:
        assert e not in GREASE_VALUES

    ja3_str, ja3_hash = TLSMetadataDetector.compute_ja3_fingerprint(
        ssl_version=parsed["version"],
        ciphers=parsed["ciphers"],
        extensions=parsed["extensions"],
        curves=parsed["curves"],
        point_formats=parsed["point_formats"],
    )
    assert ja3_hash is not None
    assert len(ja3_hash) == 32

    ja4 = TLSMetadataDetector.compute_ja4_fingerprint(
        protocol="TCP",
        tls_version=parsed["version"],
        has_sni=True,
        ciphers=parsed["ciphers"],
        extensions=parsed["extensions"],
        has_tls13=parsed["has_tls13"],
    )
    assert ja4.startswith("t13d")
    assert len(ja4.split("_")) == 3


def test_corrupt_payload_returns_none_without_synthetics():
    garbage = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08" * 5
    assert parse_tls_client_hello(garbage) is None
    assert parse_tls_client_hello(b"") is None
