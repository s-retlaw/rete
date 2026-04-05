#!/usr/bin/env python3
"""Docker-isolated robustness interop test.

Topology (Docker Compose):
  rnsd:          Python rnsd transport node (port published to host)
  rust-node:     rete --connect rnsd:4242
  python-valid:  robustness_valid.py (announces on stdin command)

The test injects malformed packets via raw TCP socket connected to
rnsd's published host port, then verifies Rust survives each injection.

Tests:
  1. Truncated packet (< 19 bytes)
  2. Oversized packet (> 500-byte MTU)
  3. Announce with corrupted signature
  4. PROOF with non-existent destination hash
  5. Random garbage bytes
  6. Valid -> garbage -> valid recovery
  7. Empty HDLC frame
  8. Escape-heavy HDLC frame

Usage:
  cd tests/interop
  uv run python docker_robustness_interop.py
"""

import os
import socket
import time

from docker_helpers import DockerTopologyTest

# HDLC constants
FLAG = 0x7E
ESC = 0x7D
ESC_MASK = 0x20


def hdlc_encode(data: bytes) -> bytes:
    out = bytearray([FLAG])
    for b in data:
        if b == FLAG or b == ESC:
            out.append(ESC)
            out.append(b ^ ESC_MASK)
        else:
            out.append(b)
    out.append(FLAG)
    return bytes(out)


def build_truncated_packet() -> bytes:
    return os.urandom(10)


def build_oversized_packet() -> bytes:
    flags = 0x08
    hops = 0
    dest_hash = os.urandom(16)
    context = 0x00
    payload = os.urandom(600 - 19)
    return bytes([flags, hops]) + dest_hash + bytes([context]) + payload


def build_corrupt_announce() -> bytes:
    flags = 0x01
    hops = 0
    dest_hash = os.urandom(16)
    context = 0x00
    pub_key = os.urandom(64)
    name_hash = os.urandom(10)
    random_hash = os.urandom(10)
    bad_signature = os.urandom(64)
    payload = pub_key + name_hash + random_hash + bad_signature
    return bytes([flags, hops]) + dest_hash + bytes([context]) + payload


def build_proof_nonexistent_dest() -> bytes:
    flags = 0x03
    hops = 0
    dest_hash = os.urandom(16)
    context = 0x00
    payload = os.urandom(32 + 64)
    return bytes([flags, hops]) + dest_hash + bytes([context]) + payload


def build_escape_heavy_packet() -> bytes:
    flags = 0x08
    hops = 0
    dest_hash = os.urandom(16)
    context = 0x00
    payload = bytes([FLAG if i % 2 == 0 else ESC for i in range(100)])
    return bytes([flags, hops]) + dest_hash + bytes([context]) + payload


def send_raw(sock, data):
    try:
        sock.sendall(data)
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass


def main():
    with DockerTopologyTest("docker-robustness", "tcp-robustness.yml", timeout=90) as t:
        t.start()

        # Wait for nodes to be ready
        t.wait_for_line("rust-node", "IDENTITY:", timeout=30)
        t.wait_for_line("python-valid", "PY_VALID_ANNOUNCED", timeout=30)
        time.sleep(2)

        # Get rnsd's published port on the host
        host_port = t.get_host_port("rnsd", 4242)
        if not host_port:
            t.check(False, "Could not get rnsd host port")
            return
        print(f"[docker-robustness] rnsd published on host port {host_port}")

        # Connect raw socket to rnsd via host port
        raw_sock = socket.create_connection(("127.0.0.1", host_port), timeout=5.0)
        raw_sock.settimeout(2.0)
        time.sleep(1)

        def verify_rust_alive(test_name):
            t.send_to_stdin("python-valid", "ANNOUNCE")
            time.sleep(1.5)
            # Check Rust container is still running
            container_id = t._get_container_id("rust-node")
            if not container_id:
                return False
            import subprocess
            result = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", container_id],
                capture_output=True, text=True,
            )
            return result.stdout.strip() == "true"

        # TEST 1: Truncated packet
        send_raw(raw_sock, hdlc_encode(build_truncated_packet()))
        time.sleep(0.5)
        t.check(verify_rust_alive("truncated"),
                "Rust survived truncated packet (< 19 bytes)")

        # TEST 2: Oversized packet
        send_raw(raw_sock, hdlc_encode(build_oversized_packet()))
        time.sleep(0.5)
        t.check(verify_rust_alive("oversized"),
                "Rust survived oversized packet (> 500-byte MTU)")

        # TEST 3: Corrupt announce
        send_raw(raw_sock, hdlc_encode(build_corrupt_announce()))
        time.sleep(0.5)
        t.check(verify_rust_alive("corrupt-announce"),
                "Rust survived announce with corrupted signature")

        # TEST 4: PROOF nonexistent dest
        send_raw(raw_sock, hdlc_encode(build_proof_nonexistent_dest()))
        time.sleep(0.5)
        t.check(verify_rust_alive("proof-nonexistent"),
                "Rust survived PROOF with non-existent destination hash")

        # TEST 5: Random garbage
        send_raw(raw_sock, os.urandom(200))
        time.sleep(0.5)
        t.check(verify_rust_alive("raw-garbage"),
                "Rust survived raw garbage (no HDLC framing)")

        # TEST 6: Valid -> garbage -> valid recovery
        t.send_to_stdin("python-valid", "ANNOUNCE")
        time.sleep(1)
        send_raw(raw_sock, os.urandom(150))
        time.sleep(0.5)
        t.send_to_stdin("python-valid", "ANNOUNCE")
        time.sleep(1.5)
        t.check(verify_rust_alive("valid-garbage-valid"),
                "Rust survived valid-garbage-valid recovery sequence")

        # TEST 7: Empty HDLC frame
        send_raw(raw_sock, bytes([FLAG, FLAG]))
        time.sleep(0.5)
        t.check(verify_rust_alive("empty-hdlc"),
                "Rust survived empty HDLC frame")

        # TEST 8: Escape-heavy packet
        pkt = build_escape_heavy_packet()
        encoded = hdlc_encode(pkt)
        send_raw(raw_sock, encoded)
        time.sleep(0.5)
        t.check(verify_rust_alive("escape-heavy"),
                "Rust survived escape-heavy HDLC frame")

        try:
            raw_sock.close()
        except Exception:
            pass

        if t.failed > 0:
            t.dump_logs("rust-node", "Rust node")
            t.dump_logs("python-valid", "Python valid client")
            t.dump_logs("rnsd", "rnsd")


if __name__ == "__main__":
    main()
