#!/usr/bin/env python3
"""ESP32-C6 resource interop test — Topology A (rete-linux <-> ESP32 over serial).

Tests small resource transfer to ESP32:
1. Establish link (using known dest hash via --peer-seed)
2. Send a small resource (<500 bytes, single segment, no compression)
3. Verify RESOURCE_COMPLETE on rete-linux stdout (ESP32 received it)
"""

import sys
import time

from interop_helpers import ESP32C6_DEST, InteropTest


def main():
    with InteropTest("esp32c6-resource", default_port=0, default_timeout=30.0) as t:
        # Start rete-linux connected to ESP32 over serial
        rust_lines = t.start_rust_serial(
            seed="esp32c6-resource-test-42",
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

        # Send a small resource
        t._log("sending resource...")
        test_payload = "Hello from rete-linux resource transfer!"
        t.send_rust(f"resource {link_id} {test_payload}")

        # Wait for resource completion event on the receiver (ESP32) side
        # rete-linux as sender sees the resource was initiated
        # The receiver (ESP32) will log RESOURCE_COMPLETE but we can't see that
        # Instead, check if rete-linux shows resource-related output
        time.sleep(5.0)

        # At minimum, verify the link is still alive (no crash on resource)
        link_closed = t.has_line(rust_lines, "LINK_CLOSED")
        t.check(not link_closed, "Link stayed open after resource transfer")

        # Send a channel message to verify link is still functional
        t.send_rust(f"channel {link_id} 0001 post-resource-check")
        time.sleep(3.0)
        got_echo = t.has_line(rust_lines, "CHANNEL_MSG", contains="echo:post-resource-check")
        t.check(got_echo, "Link functional after resource transfer (channel echo works)")

        # Check for RESOURCE_COMPLETE on sender side (ESP32 sent proof back)
        got_complete = t.has_line(rust_lines, "RESOURCE_COMPLETE")
        t.check(got_complete, "Resource transfer completed (sender received proof)")

        # Close the link to free ESP32 slot
        t.close_esp32_link(link_id)

        # Dump output
        t.dump_output("Rust stdout", rust_lines)


if __name__ == "__main__":
    main()
