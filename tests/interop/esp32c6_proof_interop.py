#!/usr/bin/env python3
"""ESP32-C6 proof interop test — Topology A (rete-linux <-> ESP32 over serial).

Tests proof of delivery:
1. rete-linux receives ESP32 announce, sends auto-reply ping
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
        # --auto-reply-ping sends a ping DATA packet when it receives an announce
        rust_lines = t.start_rust_serial(
            extra_args=["--auto-reply-ping"],
        )

        # Wait for ESP32 announce (rete-linux discovers ESP32, then auto-sends ping)
        t._log("waiting for ESP32 announce...")
        esp32_dest = t.discover_esp32_dest(rust_lines, timeout=15)
        t.check(esp32_dest is not None, "ESP32 announce received")

        if esp32_dest is None:
            t.dump_output("Rust stdout", rust_lines)
            return

        # Wait for proof (ESP32 has ProveAll strategy, sends proof after receiving DATA)
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
