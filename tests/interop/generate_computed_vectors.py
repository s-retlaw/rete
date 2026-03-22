#!/usr/bin/env python3
"""Generate computed test vectors from Python RNS internals.

Extracts derived values (Link MDU, channel windows, keepalive timing, etc.)
across a configuration matrix of MTU and RTT values. Writes the results to
computed_vectors.json for validation by Rust unit tests.

Usage:
  cd tests/interop
  uv run python generate_computed_vectors.py
  uv run python generate_computed_vectors.py --out /tmp/computed_vectors.json
"""

import argparse
import json
import math
import os
import sys
from datetime import datetime, timezone


def main():
    parser = argparse.ArgumentParser(
        description="Generate computed test vectors from Python RNS internals"
    )
    parser.add_argument(
        "--out",
        default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "computed_vectors.json"),
        help="Output path (default: computed_vectors.json in same directory)",
    )
    args = parser.parse_args()

    # -----------------------------------------------------------------------
    # Import Python RNS
    # -----------------------------------------------------------------------
    try:
        import RNS
        from RNS.Cryptography import Token
    except ImportError:
        print("ERROR: RNS not installed. Run: pip install rns", file=sys.stderr)
        sys.exit(1)

    rns_version = RNS.__version__ if hasattr(RNS, "__version__") else "unknown"

    # -----------------------------------------------------------------------
    # Configuration matrix
    # -----------------------------------------------------------------------
    MTUS = [500, 1000, 2000, 4096, 8192]
    RTTS = [0.01, 0.05, 0.18, 0.5, 0.75, 1.0, 1.5, 2.0]
    HOPS = [1, 2, 3, 5, 8, 10]

    # -----------------------------------------------------------------------
    # Extract constants from Python RNS classes
    # -----------------------------------------------------------------------
    ifac_min_size = RNS.Reticulum.IFAC_MIN_SIZE
    header_minsize = RNS.Reticulum.HEADER_MINSIZE
    header_maxsize = RNS.Reticulum.HEADER_MAXSIZE
    token_overhead = Token.TOKEN_OVERHEAD

    # Link timing constants
    keepalive_min = RNS.Link.KEEPALIVE_MIN
    keepalive_max = RNS.Link.KEEPALIVE_MAX
    keepalive_max_rtt = RNS.Link.KEEPALIVE_MAX_RTT
    stale_factor = RNS.Link.STALE_FACTOR
    stale_grace = RNS.Link.STALE_GRACE
    traffic_timeout_min_ms = RNS.Link.TRAFFIC_TIMEOUT_MIN_MS
    traffic_timeout_factor = RNS.Link.TRAFFIC_TIMEOUT_FACTOR
    establishment_timeout_per_hop = RNS.Link.ESTABLISHMENT_TIMEOUT_PER_HOP

    # Channel window constants
    ch = RNS.Channel.Channel
    rtt_fast = ch.RTT_FAST
    rtt_medium = ch.RTT_MEDIUM
    rtt_slow = ch.RTT_SLOW
    window_min_limit_fast = ch.WINDOW_MIN_LIMIT_FAST
    window_min_limit_medium = ch.WINDOW_MIN_LIMIT_MEDIUM
    window_min_limit_slow = ch.WINDOW_MIN_LIMIT_SLOW
    window_max_fast = ch.WINDOW_MAX_FAST
    window_max_medium = ch.WINDOW_MAX_MEDIUM
    window_max_slow = ch.WINDOW_MAX_SLOW
    channel_initial_window = ch.WINDOW

    # Resource constants
    maphash_len = RNS.Resource.MAPHASH_LEN

    # ADV_OVERHEAD: try to extract from RNS.Resource, fall back to computing
    # from known fixed fields if the attribute doesn't exist.
    # The advertisement overhead is:
    #   hash(32) + random_hash(4) + flags(1) + segments(2) + segment_index(2) +
    #   comp_indicator(1) + total_size(8) + total_hash(64) + name_len(2) +
    #   nonce(16) + token(2) = 134
    try:
        adv_overhead = RNS.Resource.ADV_OVERHEAD
    except AttributeError:
        adv_overhead = 134

    # -----------------------------------------------------------------------
    # MTU vectors
    # -----------------------------------------------------------------------
    mtu_vectors = []
    for mtu in MTUS:
        # Link MDU: floor((mtu - IFAC_MIN_SIZE - HEADER_MINSIZE - TOKEN_OVERHEAD) / 16) * 16 - 1
        link_mdu = math.floor(
            (mtu - ifac_min_size - header_minsize - token_overhead) / 16
        ) * 16 - 1

        # Resource SDU: mtu - HEADER_MAXSIZE - IFAC_MIN_SIZE
        resource_sdu = mtu - header_maxsize - ifac_min_size

        # Hashmap max len: floor((link_mdu - ADV_OVERHEAD) / MAPHASH_LEN)
        hashmap_max_len = math.floor((link_mdu - adv_overhead) / maphash_len)

        mtu_vectors.append({
            "mtu": mtu,
            "link_mdu": link_mdu,
            "resource_sdu": resource_sdu,
            "hashmap_max_len": hashmap_max_len,
        })

    # -----------------------------------------------------------------------
    # RTT vectors
    # -----------------------------------------------------------------------
    rtt_vectors = []
    for rtt in RTTS:
        # Keepalive interval: max(KEEPALIVE_MIN, min(KEEPALIVE_MAX, rtt * (KEEPALIVE_MAX / KEEPALIVE_MAX_RTT)))
        keepalive_interval = max(
            keepalive_min,
            min(keepalive_max, rtt * (keepalive_max / keepalive_max_rtt)),
        )

        # Stale time: keepalive * STALE_FACTOR + STALE_GRACE
        stale_time = keepalive_interval * stale_factor + stale_grace

        # Traffic timeout: max(TRAFFIC_TIMEOUT_MIN_MS, rtt * 1000 * TRAFFIC_TIMEOUT_FACTOR)
        traffic_timeout = max(
            traffic_timeout_min_ms, rtt * 1000 * traffic_timeout_factor
        )

        rtt_vectors.append({
            "rtt": rtt,
            "keepalive_interval_s": keepalive_interval,
            "stale_time_s": stale_time,
            "traffic_timeout_ms": traffic_timeout,
        })

    # -----------------------------------------------------------------------
    # Channel vectors (RTT-based window selection)
    # -----------------------------------------------------------------------
    channel_vectors = []
    for rtt in RTTS:
        if rtt < rtt_fast:
            window_min = window_min_limit_fast
            window_max = window_max_fast
        elif rtt < rtt_medium:
            window_min = window_min_limit_medium
            window_max = window_max_medium
        elif rtt < rtt_slow:
            window_min = window_min_limit_slow
            window_max = window_max_slow
        else:
            window_min = window_min_limit_slow
            window_max = window_max_slow

        channel_vectors.append({
            "rtt": rtt,
            "window_min": window_min,
            "window_max": window_max,
            "initial_window": channel_initial_window,
        })

    # -----------------------------------------------------------------------
    # Hop vectors (establishment timeout)
    # -----------------------------------------------------------------------
    hop_vectors = []
    for hops in HOPS:
        establishment_timeout = hops * establishment_timeout_per_hop
        hop_vectors.append({
            "hops": hops,
            "establishment_timeout_s": establishment_timeout,
        })

    # -----------------------------------------------------------------------
    # Build output
    # -----------------------------------------------------------------------
    output = {
        "_generator": "generate_computed_vectors.py",
        "_rns_version": rns_version,
        "_generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "_description": (
            "Computed test vectors derived from Python RNS internals across a "
            "configuration matrix of MTU and RTT values. Used to validate Rust "
            "computed constants match the Python reference."
        ),
        "_constants_used": {
            "IFAC_MIN_SIZE": ifac_min_size,
            "HEADER_MINSIZE": header_minsize,
            "HEADER_MAXSIZE": header_maxsize,
            "TOKEN_OVERHEAD": token_overhead,
            "KEEPALIVE_MIN": keepalive_min,
            "KEEPALIVE_MAX": keepalive_max,
            "KEEPALIVE_MAX_RTT": keepalive_max_rtt,
            "STALE_FACTOR": stale_factor,
            "STALE_GRACE": stale_grace,
            "TRAFFIC_TIMEOUT_MIN_MS": traffic_timeout_min_ms,
            "TRAFFIC_TIMEOUT_FACTOR": traffic_timeout_factor,
            "ESTABLISHMENT_TIMEOUT_PER_HOP": establishment_timeout_per_hop,
            "ADV_OVERHEAD": adv_overhead,
            "MAPHASH_LEN": maphash_len,
            "RTT_FAST": rtt_fast,
            "RTT_MEDIUM": rtt_medium,
            "RTT_SLOW": rtt_slow,
            "WINDOW_MIN_LIMIT_FAST": window_min_limit_fast,
            "WINDOW_MIN_LIMIT_MEDIUM": window_min_limit_medium,
            "WINDOW_MIN_LIMIT_SLOW": window_min_limit_slow,
            "WINDOW_MAX_FAST": window_max_fast,
            "WINDOW_MAX_MEDIUM": window_max_medium,
            "WINDOW_MAX_SLOW": window_max_slow,
            "CHANNEL_INITIAL_WINDOW": channel_initial_window,
        },
        "mtu_vectors": mtu_vectors,
        "rtt_vectors": rtt_vectors,
        "channel_vectors": channel_vectors,
        "hop_vectors": hop_vectors,
    }

    with open(args.out, "w") as f:
        json.dump(output, f, indent=2)
        f.write("\n")

    print(f"Wrote {len(mtu_vectors)} MTU vectors, "
          f"{len(rtt_vectors)} RTT vectors, "
          f"{len(channel_vectors)} channel vectors, "
          f"{len(hop_vectors)} hop vectors")
    print(f"Output: {args.out}")


if __name__ == "__main__":
    main()
