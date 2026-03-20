#!/usr/bin/env python3
"""ESP32-C6 request/response interop test — Topology A (rete-linux <-> ESP32 over serial).

Tests request/response over a link:
1. Establish link to ESP32
2. Send request via stdin command
3. ESP32 firmware responds with "esp32-response:<path_hash>"
4. Verify RESPONSE_RECEIVED on rete-linux stdout
5. Close link to free ESP32 slot
"""

import sys
import time

from interop_helpers import ESP32C6_DEST, InteropTest


def main():
    with InteropTest("esp32c6-request", default_port=0, default_timeout=30.0) as t:
        # Start rete-linux connected to ESP32 over serial
        rust_lines = t.start_rust_serial(
            seed="esp32c6-request-test-42",
            extra_args=["--peer-seed", "rete-esp32c6-test"],
        )

        # Wait for startup
        time.sleep(2.0)

        # Establish link
        link_id, ok = t.establish_esp32_link(rust_lines, ESP32C6_DEST)
        t.check(ok, "Link established")
        if not ok:
            t.dump_output("Rust stdout", rust_lines)
            return

        # Send a request
        t._log("sending request...")
        t.send_rust(f"request {link_id} /test hello-request")

        # Wait for RESPONSE_RECEIVED
        resp_line = t.wait_for_line(rust_lines, "RESPONSE_RECEIVED", timeout=10)
        t.check(resp_line is not None, "Received response from ESP32")

        # Close the link to free ESP32 slot
        t.close_esp32_link(link_id)

        # Dump output
        t.dump_output("Rust stdout", rust_lines)


if __name__ == "__main__":
    main()
