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

from interop_helpers import InteropTest


def main():
    with InteropTest("esp32c6-teardown", default_port=0, default_timeout=30.0) as t:
        # Start rete-linux connected to ESP32 over serial
        rust_lines = t.start_rust_serial()

        # Discover ESP32 destination hash from its announce
        esp32_dest = t.discover_esp32_dest(rust_lines, timeout=15)
        if esp32_dest is None:
            t.check(False, "Discover ESP32 destination hash")
            t.dump_output("Rust stdout", rust_lines)
            return

        # --- First link ---
        link_id_1, ok = t.establish_esp32_link(rust_lines, esp32_dest)
        t.check(ok, "First link established")
        if not ok:
            t.dump_output("Rust stdout", rust_lines)
            return

        # Close the first link (pass rust_lines for proper polling)
        t.close_esp32_link(link_id_1, rust_lines=rust_lines, timeout=10)

        # Verify LINK_CLOSED was seen (close_esp32_link already polled for it)
        closed = t.has_line(rust_lines, "LINK_CLOSED")
        t.check(closed, "First link closed (LINK_CLOSED received)")

        # Give ESP32 time to process the close
        time.sleep(1.0)

        # --- Second link (proves slot was freed) ---
        after_idx = len(rust_lines)
        link_id_2, ok = t.establish_esp32_link(rust_lines, esp32_dest, after_index=after_idx)
        t.check(ok, "Second link established (slot was freed)")
        if not ok:
            t.dump_output("Rust stdout", rust_lines)
            return

        # Send channel message on new link
        t._log("sending channel message on second link...")
        echo_start = len(rust_lines)
        t.send_rust(f"channel {link_id_2} 0001 teardown-test-msg")

        # Wait for echo — use wait_for_line_after to skip the greeting CHANNEL_MSG
        echo_line = t.wait_for_line_after(
            rust_lines, "CHANNEL_MSG", echo_start, timeout=10,
        )
        got_echo = echo_line is not None and "echo:teardown-test-msg" in (echo_line or "")
        # Fallback: check all lines after the greeting
        if not got_echo:
            for line in rust_lines[echo_start:]:
                if "CHANNEL_MSG" in line and "echo:teardown-test-msg" in line:
                    got_echo = True
                    break
        t.check(got_echo, "Channel echo works on second link")

        # Close second link
        t.close_esp32_link(link_id_2, rust_lines=rust_lines)

        # Dump output
        t.dump_output("Rust stdout", rust_lines)


if __name__ == "__main__":
    main()
