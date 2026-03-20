#!/usr/bin/env python3
"""ESP32-C6 link teardown interop test — Topology A (rete-linux <-> ESP32 over serial).

Tests that LINKCLOSE frees ESP32 link slots:
1. Establish link, verify LINK_ESTABLISHED
2. Send close command, verify LINK_CLOSED
3. Establish a NEW link (proves slot was freed)
4. Send channel message on new link, verify echo
5. Close second link
"""

import sys
import time

from interop_helpers import ESP32C6_DEST, InteropTest


def main():
    with InteropTest("esp32c6-teardown", default_port=0, default_timeout=30.0) as t:
        # Start rete-linux connected to ESP32 over serial
        rust_lines = t.start_rust_serial(
            seed="esp32c6-teardown-test-42",
            extra_args=["--peer-seed", "rete-esp32c6-test"],
        )

        # Wait for startup
        time.sleep(2.0)

        # --- First link ---
        link_id_1, ok = t.establish_esp32_link(rust_lines, ESP32C6_DEST)
        t.check(ok, "First link established")
        if not ok:
            t.dump_output("Rust stdout", rust_lines)
            return

        # Close the first link
        t.close_esp32_link(link_id_1)

        # Wait for LINK_CLOSED
        closed_line = t.wait_for_line(rust_lines, "LINK_CLOSED", timeout=10)
        t.check(closed_line is not None, "First link closed (LINK_CLOSED received)")

        # Give ESP32 time to process the close
        time.sleep(1.0)

        # --- Second link (proves slot was freed) ---
        after_idx = len(rust_lines)
        link_id_2, ok = t.establish_esp32_link(rust_lines, ESP32C6_DEST, after_index=after_idx)
        t.check(ok, "Second link established (slot was freed)")
        if not ok:
            t.dump_output("Rust stdout", rust_lines)
            return

        # Send channel message on new link
        t._log("sending channel message on second link...")
        t.send_rust(f"channel {link_id_2} 0001 teardown-test-msg")

        # Wait for echo
        echo_line = t.wait_for_line(rust_lines, "CHANNEL_MSG", timeout=5)
        got_echo = echo_line is not None and "echo:teardown-test-msg" in (echo_line or "")
        # Fallback: check all lines if wait_for_line matched a different CHANNEL_MSG
        if not got_echo:
            got_echo = t.has_line(rust_lines, "CHANNEL_MSG", contains="echo:teardown-test-msg")
        t.check(got_echo, "Channel echo works on second link")

        # Close second link
        t.close_esp32_link(link_id_2)

        # Dump output
        t.dump_output("Rust stdout", rust_lines)


if __name__ == "__main__":
    main()
