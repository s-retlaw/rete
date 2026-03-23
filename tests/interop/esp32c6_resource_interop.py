#!/usr/bin/env python3
"""ESP32-C6 resource interop test — Topology A (rete-linux <-> ESP32 over serial).

Tests small resource transfer to ESP32:
1. Establish link
2. Send a small resource (<500 bytes, single segment, no compression)
3. Verify RESOURCE_COMPLETE on rete-linux stdout (ESP32 received it)
"""

import sys
import time

from interop_helpers import InteropTest


def main():
    with InteropTest("esp32c6-resource", default_port=0, default_timeout=60.0) as t:
        # Start rete-linux connected to ESP32 over serial
        rust_lines = t.start_rust_serial()

        # Discover ESP32 destination hash from its announce
        esp32_dest = t.discover_esp32_dest(rust_lines, timeout=15)
        if esp32_dest is None:
            t.check(False, "Discover ESP32 destination hash")
            t.dump_output("Rust stdout", rust_lines)
            return

        # Establish link
        link_id, ok = t.establish_esp32_link(rust_lines, esp32_dest)
        t.check(ok, "Link established")
        if not ok:
            t.dump_output("Rust stdout", rust_lines)
            return

        # Send a small resource
        t._log("sending resource...")
        test_payload = "Hello from rete-linux resource transfer!"
        t.send_rust(f"resource {link_id} {test_payload}")

        # Poll for RESOURCE_COMPLETE instead of fixed sleep.
        # Serial latency (115200 baud + HDLC) needs time for proof roundtrip.
        complete_line = t.wait_for_line(rust_lines, "RESOURCE_COMPLETE", timeout=45)

        # At minimum, verify the link is still alive (no crash on resource)
        link_closed = t.has_line(rust_lines, "LINK_CLOSED")
        t.check(not link_closed, "Link stayed open after resource transfer")

        # Send a channel message to verify link is still functional
        t.send_rust(f"channel {link_id} 0001 post-resource-check")
        time.sleep(3.0)
        got_echo = t.has_line(rust_lines, "CHANNEL_MSG", contains="echo:post-resource-check")
        t.check(got_echo, "Link functional after resource transfer (channel echo works)")

        # Check for RESOURCE_COMPLETE on sender side (ESP32 sent proof back)
        t.check(complete_line is not None, "Resource transfer completed (sender received proof)")

        # Close the link to free ESP32 slot
        t.close_esp32_link(link_id, rust_lines=rust_lines)

        # Dump output (including stderr for resource debugging)
        rust_stderr = t.collect_rust_stderr(last_chars=4000)
        t.dump_output("Rust stdout", rust_lines)
        t.dump_output("Rust stderr", rust_stderr.strip().split("\n"))


if __name__ == "__main__":
    main()
