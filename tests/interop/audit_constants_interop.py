#!/usr/bin/env python3
"""Audit: compare Python RNS constants against Rust rete constants.

This test imports the Python RNS library and extracts every class-level constant
from the key modules, then compares against the expected Rust values. Any mismatch
is reported as a test failure.

Usage:
  cd tests/interop
  uv run python audit_constants_interop.py
"""

import sys
import json
import os


def main():
    passed = 0
    failed = 0
    warnings = 0
    results = []

    def check(area, name, python_val, rust_val, *, note=""):
        nonlocal passed, failed, warnings
        if python_val == rust_val:
            results.append(("PASS", area, name, python_val, rust_val, note))
            passed += 1
        elif note.startswith("INTENTIONAL"):
            results.append(("WARN", area, name, python_val, rust_val, note))
            warnings += 1
        else:
            results.append(("FAIL", area, name, python_val, rust_val, note))
            failed += 1

    try:
        import RNS
    except ImportError:
        print("ERROR: RNS not installed. Run: pip install rns", file=sys.stderr)
        sys.exit(1)

    # -----------------------------------------------------------------------
    # Reticulum system constants
    # -----------------------------------------------------------------------
    check("Reticulum", "MTU", RNS.Reticulum.MTU, 500)
    check("Reticulum", "TRUNCATED_HASHLENGTH", RNS.Reticulum.TRUNCATED_HASHLENGTH, 128)
    check("Reticulum", "HEADER_MINSIZE", RNS.Reticulum.HEADER_MINSIZE, 19)
    check("Reticulum", "HEADER_MAXSIZE", RNS.Reticulum.HEADER_MAXSIZE, 35)
    check("Reticulum", "IFAC_MIN_SIZE", RNS.Reticulum.IFAC_MIN_SIZE, 1)
    check("Reticulum", "MDU", RNS.Reticulum.MDU, 464)
    check("Reticulum", "DEFAULT_PER_HOP_TIMEOUT", RNS.Reticulum.DEFAULT_PER_HOP_TIMEOUT, 6)
    check("Reticulum", "ANNOUNCE_CAP", RNS.Reticulum.ANNOUNCE_CAP, 2)

    # -----------------------------------------------------------------------
    # Packet constants
    # -----------------------------------------------------------------------
    check("Packet", "HEADER_1", RNS.Packet.HEADER_1, 0x00)
    check("Packet", "HEADER_2", RNS.Packet.HEADER_2, 0x01)
    check("Packet", "DATA", RNS.Packet.DATA, 0x00)
    check("Packet", "ANNOUNCE", RNS.Packet.ANNOUNCE, 0x01)
    check("Packet", "LINKREQUEST", RNS.Packet.LINKREQUEST, 0x02)
    check("Packet", "PROOF", RNS.Packet.PROOF, 0x03)

    # Context bytes
    check("Packet", "NONE", RNS.Packet.NONE, 0x00)
    check("Packet", "RESOURCE", RNS.Packet.RESOURCE, 0x01)
    check("Packet", "RESOURCE_ADV", RNS.Packet.RESOURCE_ADV, 0x02)
    check("Packet", "RESOURCE_REQ", RNS.Packet.RESOURCE_REQ, 0x03)
    check("Packet", "RESOURCE_HMU", RNS.Packet.RESOURCE_HMU, 0x04)
    check("Packet", "RESOURCE_PRF", RNS.Packet.RESOURCE_PRF, 0x05)
    check("Packet", "RESOURCE_ICL", RNS.Packet.RESOURCE_ICL, 0x06)
    check("Packet", "RESOURCE_RCL", RNS.Packet.RESOURCE_RCL, 0x07)
    check("Packet", "CACHE_REQUEST", RNS.Packet.CACHE_REQUEST, 0x08)
    check("Packet", "REQUEST", RNS.Packet.REQUEST, 0x09)
    check("Packet", "RESPONSE", RNS.Packet.RESPONSE, 0x0A)
    check("Packet", "PATH_RESPONSE", RNS.Packet.PATH_RESPONSE, 0x0B)
    check("Packet", "COMMAND", RNS.Packet.COMMAND, 0x0C)
    check("Packet", "COMMAND_STATUS", RNS.Packet.COMMAND_STATUS, 0x0D)
    check("Packet", "CHANNEL", RNS.Packet.CHANNEL, 0x0E)
    check("Packet", "KEEPALIVE", RNS.Packet.KEEPALIVE, 0xFA)
    check("Packet", "LINKIDENTIFY", RNS.Packet.LINKIDENTIFY, 0xFB)
    check("Packet", "LINKCLOSE", RNS.Packet.LINKCLOSE, 0xFC)
    check("Packet", "LINKPROOF", RNS.Packet.LINKPROOF, 0xFD)
    check("Packet", "LRRTT", RNS.Packet.LRRTT, 0xFE)
    check("Packet", "LRPROOF", RNS.Packet.LRPROOF, 0xFF)

    # MDU
    check("Packet", "PLAIN_MDU", RNS.Packet.PLAIN_MDU, 464)
    check("Packet", "ENCRYPTED_MDU", RNS.Packet.ENCRYPTED_MDU, 383)

    # -----------------------------------------------------------------------
    # Identity constants
    # -----------------------------------------------------------------------
    check("Identity", "KEYSIZE", RNS.Identity.KEYSIZE, 512,
          note="bits; Rust uses 64 bytes")
    check("Identity", "HASHLENGTH", RNS.Identity.HASHLENGTH, 256,
          note="bits; Rust uses 32 bytes")
    check("Identity", "SIGLENGTH", RNS.Identity.SIGLENGTH, 512,
          note="bits; Rust uses 64 bytes")
    check("Identity", "NAME_HASH_LENGTH", RNS.Identity.NAME_HASH_LENGTH, 80,
          note="bits; Rust uses 10 bytes")
    check("Identity", "TRUNCATED_HASHLENGTH", RNS.Identity.TRUNCATED_HASHLENGTH, 128,
          note="bits; Rust uses 16 bytes")

    # Token overhead
    from RNS.Cryptography import Token as CryptoToken
    check("Identity", "TOKEN_OVERHEAD", CryptoToken.TOKEN_OVERHEAD, 48)

    # HKDF key lengths
    check("Identity", "DERIVED_KEY_LENGTH", RNS.Identity.DERIVED_KEY_LENGTH, 64)

    # -----------------------------------------------------------------------
    # Transport constants
    # -----------------------------------------------------------------------
    check("Transport", "PATHFINDER_M", RNS.Transport.PATHFINDER_M, 128)
    check("Transport", "PATHFINDER_R", RNS.Transport.PATHFINDER_R, 1)
    check("Transport", "PATHFINDER_G", RNS.Transport.PATHFINDER_G, 5)
    check("Transport", "PATHFINDER_RW", RNS.Transport.PATHFINDER_RW, 0.5)
    check("Transport", "PATHFINDER_E", RNS.Transport.PATHFINDER_E, 604800)
    check("Transport", "LOCAL_REBROADCASTS_MAX", RNS.Transport.LOCAL_REBROADCASTS_MAX, 2)
    check("Transport", "PATH_REQUEST_TIMEOUT", RNS.Transport.PATH_REQUEST_TIMEOUT, 15)
    check("Transport", "PATH_REQUEST_GRACE", RNS.Transport.PATH_REQUEST_GRACE, 0.4,
          note="INTENTIONAL: Rust uses 1s (integer seconds)")
    check("Transport", "PATH_REQUEST_MI", RNS.Transport.PATH_REQUEST_MI, 20)
    check("Transport", "REVERSE_TIMEOUT", RNS.Transport.REVERSE_TIMEOUT, 480)
    check("Transport", "DESTINATION_TIMEOUT", RNS.Transport.DESTINATION_TIMEOUT, 604800)
    check("Transport", "MAX_RECEIPTS", RNS.Transport.MAX_RECEIPTS, 1024)

    # -----------------------------------------------------------------------
    # Link constants
    # -----------------------------------------------------------------------
    check("Link", "KEEPALIVE", RNS.Link.KEEPALIVE, 360)
    check("Link", "STALE_FACTOR", RNS.Link.STALE_FACTOR, 2)
    check("Link", "STALE_TIME", RNS.Link.STALE_TIME, 720)
    check("Link", "KEEPALIVE_MAX", RNS.Link.KEEPALIVE_MAX, 360)
    check("Link", "KEEPALIVE_MIN", RNS.Link.KEEPALIVE_MIN, 5)
    check("Link", "KEEPALIVE_MAX_RTT", RNS.Link.KEEPALIVE_MAX_RTT, 1.75)
    check("Link", "STALE_GRACE", RNS.Link.STALE_GRACE, 5)
    check("Link", "TRAFFIC_TIMEOUT_MIN_MS", RNS.Link.TRAFFIC_TIMEOUT_MIN_MS, 5)
    check("Link", "TRAFFIC_TIMEOUT_FACTOR", RNS.Link.TRAFFIC_TIMEOUT_FACTOR, 6)
    check("Link", "KEEPALIVE_TIMEOUT_FACTOR", RNS.Link.KEEPALIVE_TIMEOUT_FACTOR, 4)
    check("Link", "ESTABLISHMENT_TIMEOUT_PER_HOP", RNS.Link.ESTABLISHMENT_TIMEOUT_PER_HOP, 6)
    check("Link", "LINK_MTU_SIZE", RNS.Link.LINK_MTU_SIZE, 3)

    # Link MDU: floor((MTU - IFAC_MIN_SIZE - HEADER_MINSIZE - TOKEN_OVERHEAD) / 16) * 16 - 1
    py_link_mdu = RNS.Link.MDU
    check("Link", "MDU", py_link_mdu, 431)

    # Encryption modes
    check("Link", "MODE_AES256_CBC", RNS.Link.MODE_AES256_CBC, 0x01)

    # -----------------------------------------------------------------------
    # Channel constants
    # -----------------------------------------------------------------------
    check("Channel", "WINDOW", RNS.Channel.Channel.WINDOW, 2)
    check("Channel", "WINDOW_MIN", RNS.Channel.Channel.WINDOW_MIN, 2)
    check("Channel", "WINDOW_MIN_LIMIT_SLOW", RNS.Channel.Channel.WINDOW_MIN_LIMIT_SLOW, 2)
    check("Channel", "WINDOW_MIN_LIMIT_MEDIUM", RNS.Channel.Channel.WINDOW_MIN_LIMIT_MEDIUM, 5)
    check("Channel", "WINDOW_MIN_LIMIT_FAST", RNS.Channel.Channel.WINDOW_MIN_LIMIT_FAST, 16)
    check("Channel", "WINDOW_MAX_SLOW", RNS.Channel.Channel.WINDOW_MAX_SLOW, 5)
    check("Channel", "WINDOW_MAX_MEDIUM", RNS.Channel.Channel.WINDOW_MAX_MEDIUM, 12)
    check("Channel", "WINDOW_MAX_FAST", RNS.Channel.Channel.WINDOW_MAX_FAST, 48)
    check("Channel", "WINDOW_MAX", RNS.Channel.Channel.WINDOW_MAX, 48)
    check("Channel", "FAST_RATE_THRESHOLD", RNS.Channel.Channel.FAST_RATE_THRESHOLD, 10)
    check("Channel", "RTT_FAST", RNS.Channel.Channel.RTT_FAST, 0.18)
    check("Channel", "RTT_MEDIUM", RNS.Channel.Channel.RTT_MEDIUM, 0.75)
    check("Channel", "RTT_SLOW", RNS.Channel.Channel.RTT_SLOW, 1.45)
    check("Channel", "WINDOW_FLEXIBILITY", RNS.Channel.Channel.WINDOW_FLEXIBILITY, 4)
    check("Channel", "SEQ_MAX", RNS.Channel.Channel.SEQ_MAX, 0xFFFF)
    check("Channel", "SEQ_MODULUS", RNS.Channel.Channel.SEQ_MODULUS, 0x10000)

    # -----------------------------------------------------------------------
    # Resource constants
    # -----------------------------------------------------------------------
    check("Resource", "WINDOW", RNS.Resource.WINDOW, 4)
    check("Resource", "WINDOW_MIN", RNS.Resource.WINDOW_MIN, 2)
    check("Resource", "WINDOW_MAX_SLOW", RNS.Resource.WINDOW_MAX_SLOW, 10)
    check("Resource", "WINDOW_MAX_FAST", RNS.Resource.WINDOW_MAX_FAST, 75)
    check("Resource", "WINDOW_MAX_VERY_SLOW", RNS.Resource.WINDOW_MAX_VERY_SLOW, 4)
    check("Resource", "WINDOW_FLEXIBILITY", RNS.Resource.WINDOW_FLEXIBILITY, 4)
    check("Resource", "FAST_RATE_THRESHOLD", RNS.Resource.FAST_RATE_THRESHOLD, 4)
    check("Resource", "VERY_SLOW_RATE_THRESHOLD", RNS.Resource.VERY_SLOW_RATE_THRESHOLD, 2)
    check("Resource", "RATE_FAST", RNS.Resource.RATE_FAST, 6250)
    check("Resource", "RATE_VERY_SLOW", RNS.Resource.RATE_VERY_SLOW, 250)
    check("Resource", "MAPHASH_LEN", RNS.Resource.MAPHASH_LEN, 4)
    check("Resource", "SDU", RNS.Resource.SDU, 464)
    check("Resource", "RANDOM_HASH_SIZE", RNS.Resource.RANDOM_HASH_SIZE, 4)
    check("Resource", "MAX_EFFICIENT_SIZE", RNS.Resource.MAX_EFFICIENT_SIZE, 1048575)
    check("Resource", "PART_TIMEOUT_FACTOR", RNS.Resource.PART_TIMEOUT_FACTOR, 4)
    check("Resource", "PART_TIMEOUT_FACTOR_AFTER_RTT", RNS.Resource.PART_TIMEOUT_FACTOR_AFTER_RTT, 2)
    check("Resource", "PROOF_TIMEOUT_FACTOR", RNS.Resource.PROOF_TIMEOUT_FACTOR, 3)
    check("Resource", "MAX_RETRIES", RNS.Resource.MAX_RETRIES, 16)
    check("Resource", "MAX_ADV_RETRIES", RNS.Resource.MAX_ADV_RETRIES, 4)

    # -----------------------------------------------------------------------
    # Destination constants
    # -----------------------------------------------------------------------
    check("Destination", "SINGLE", RNS.Destination.SINGLE, 0x00)
    check("Destination", "GROUP", RNS.Destination.GROUP, 0x01)
    check("Destination", "PLAIN", RNS.Destination.PLAIN, 0x02)
    check("Destination", "LINK", RNS.Destination.LINK, 0x03)
    check("Destination", "PROVE_NONE", RNS.Destination.PROVE_NONE, 0x21)
    check("Destination", "PROVE_APP", RNS.Destination.PROVE_APP, 0x22)
    check("Destination", "PROVE_ALL", RNS.Destination.PROVE_ALL, 0x23)
    check("Destination", "ALLOW_NONE", RNS.Destination.ALLOW_NONE, 0x00)
    check("Destination", "ALLOW_ALL", RNS.Destination.ALLOW_ALL, 0x01)
    check("Destination", "ALLOW_LIST", RNS.Destination.ALLOW_LIST, 0x02)
    check("Destination", "IN", RNS.Destination.IN, 0x11)
    check("Destination", "OUT", RNS.Destination.OUT, 0x12)

    # -----------------------------------------------------------------------
    # Computed values (cross-check against generated vectors)
    # -----------------------------------------------------------------------
    import math
    from RNS.Cryptography import Token as CryptoToken2

    # Verify computed_vectors.json exists and matches Python
    vectors_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "computed_vectors.json")
    if os.path.exists(vectors_path):
        with open(vectors_path) as f:
            vectors = json.load(f)

        # MTU vectors
        for v in vectors.get("mtu_vectors", []):
            mtu = v["mtu"]
            expected_mdu = math.floor(
                (mtu - RNS.Reticulum.IFAC_MIN_SIZE - RNS.Reticulum.HEADER_MINSIZE - CryptoToken2.TOKEN_OVERHEAD) / 16
            ) * 16 - 1
            check("Computed", f"link_mdu(MTU={mtu})", expected_mdu, v["link_mdu"])

            expected_sdu = mtu - RNS.Reticulum.HEADER_MAXSIZE - RNS.Reticulum.IFAC_MIN_SIZE
            check("Computed", f"resource_sdu(MTU={mtu})", expected_sdu, v["resource_sdu"])

            expected_hml = math.floor((expected_mdu - 134) / 4)
            check("Computed", f"hashmap_max_len(MTU={mtu})", expected_hml, v["hashmap_max_len"])

        # RTT vectors
        for v in vectors.get("rtt_vectors", []):
            rtt = v["rtt"]
            expected_ka = max(
                RNS.Link.KEEPALIVE_MIN,
                min(RNS.Link.KEEPALIVE_MAX, rtt * (RNS.Link.KEEPALIVE_MAX / RNS.Link.KEEPALIVE_MAX_RTT)),
            )
            check("Computed", f"keepalive(RTT={rtt})", expected_ka, v["keepalive_interval_s"])
    else:
        print("  NOTE: computed_vectors.json not found, skipping computed value checks")

    # -----------------------------------------------------------------------
    # Report
    # -----------------------------------------------------------------------
    print()
    print("=" * 70)
    print("  Python RNS Constants Audit")
    print("-" * 70)

    for status, area, name, py_val, rust_val, note in results:
        if status == "FAIL":
            note_str = f"  ({note})" if note else ""
            print(f"  FAIL  {area}.{name}: Python={py_val} Rust={rust_val}{note_str}")
        elif status == "WARN":
            note_str = f"  ({note})" if note else ""
            print(f"  WARN  {area}.{name}: Python={py_val} Rust={rust_val}{note_str}")

    print("-" * 70)
    total = passed + failed + warnings
    print(f"  Results: {passed}/{total} passed, {failed}/{total} failed, {warnings} intentional deviations")
    if failed == 0:
        print("  ALL CONSTANTS MATCH")
    else:
        print("  MISMATCHES FOUND")
    print("=" * 70)

    sys.exit(1 if failed > 0 else 0)


if __name__ == "__main__":
    main()
