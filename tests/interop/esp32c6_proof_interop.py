#!/usr/bin/env python3
"""ESP32-C6 proof interop test — Topology A (rete-linux <-> ESP32 over serial).

Tests proof of delivery:
1. rete-linux sends encrypted DATA to ESP32 (using --peer-seed for pre-registered identity)
2. ESP32 (with ProveAll strategy) generates and sends back a proof
3. Verify PROOF_RECEIVED in rete-linux stdout
4. Verify echoed DATA received
"""

import sys
import time

from interop_helpers import InteropTest


def main():
    with InteropTest("esp32c6-proof", default_port=0, default_timeout=30.0) as t:
        # Start rete-linux connected to ESP32 over serial
        # --peer-seed pre-registers ESP32's identity so we can send DATA immediately
        # --auto-reply-ping sends a ping DATA packet on startup
        rust_lines = t.start_rust_serial(
            seed="esp32c6-proof-test-42",
            extra_args=["--peer-seed", "rete-esp32c6-test", "--auto-reply-ping"],
        )

        # Wait for DATA_SENT (rete-linux sends ping immediately via pre-registered peer)
        t._log("waiting for data send...")
        data_sent = t.wait_for_line(rust_lines, "DATA_SENT", timeout=15)
        t.check(data_sent is not None, "DATA was sent to ESP32",
                detail=f"got: {data_sent}")

        if data_sent is None:
            t.dump_output("Rust stdout", rust_lines)
            return

        # Wait for proof (ESP32 has ProveAll strategy)
        t._log("waiting for proof...")
        proof = t.wait_for_line(rust_lines, "PROOF_RECEIVED", timeout=15)
        t.check(proof is not None, "Received proof from ESP32")

        # Wait for echo (ESP32 echoes data back)
        time.sleep(2.0)
        got_echo = t.has_line(rust_lines, "DATA:", contains="echo:ping:")
        t.check(got_echo, "Received echoed data from ESP32")

        # Dump output
        t.dump_output("Rust stdout", rust_lines)


if __name__ == "__main__":
    main()
