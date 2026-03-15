#!/usr/bin/env python3
"""Python reference ↔ ESP32 interop test over serial.

Proves that data encrypted/signed by the Python RNS reference implementation
can be correctly decrypted and processed by the Rust rete implementation on
the ESP32-C6, and vice versa.

Flow:
  1. Python sends ANNOUNCE → ESP32 validates signature + learns identity
  2. Python sends encrypted DATA "ping:<timestamp>" → ESP32
  3. ESP32 decrypts, reads, echoes back "echo:ping:<timestamp>" (encrypted)
  4. Python receives + decrypts echo → verifies round-trip

Usage:
  cd tests/interop
  uv run python serial_interop.py [--port /dev/ttyUSB0] [--baud 115200]
"""

import argparse
import hashlib
import os
import struct
import sys
import tempfile
import shutil
import time

import serial as pyserial
import RNS

# ---------------------------------------------------------------------------
# Bootstrap — throwaway Reticulum instance (needed for crypto internals)
# ---------------------------------------------------------------------------
_tmpdir = tempfile.mkdtemp(prefix="rete_serial_interop_")
_r = RNS.Reticulum(configdir=_tmpdir, loglevel=RNS.LOG_CRITICAL)

# ---------------------------------------------------------------------------
# HDLC framing (matches rete_core::hdlc)
# ---------------------------------------------------------------------------
FLAG = 0x7E
ESC = 0x7D
ESC_MASK = 0x20


def hdlc_encode(data: bytes) -> bytes:
    out = bytearray([FLAG])
    for b in data:
        if b == FLAG:
            out.extend([ESC, FLAG ^ ESC_MASK])
        elif b == ESC:
            out.extend([ESC, ESC ^ ESC_MASK])
        else:
            out.append(b)
    out.append(FLAG)
    return bytes(out)


class HdlcDecoder:
    def __init__(self):
        self.buf = bytearray()
        self.in_frame = False
        self.escape_next = False

    def feed(self, data: bytes) -> list:
        """Feed raw bytes, return list of complete frames."""
        frames = []
        for b in data:
            if self.escape_next:
                self.buf.append(b ^ ESC_MASK)
                self.escape_next = False
            elif b == ESC:
                self.escape_next = True
            elif b == FLAG:
                if self.in_frame and self.buf:
                    frames.append(bytes(self.buf))
                self.buf = bytearray()
                self.in_frame = True
            elif self.in_frame:
                self.buf.append(b)
        return frames


# ---------------------------------------------------------------------------
# Identity from Rust-compatible seed (matches Identity::from_seed)
# ---------------------------------------------------------------------------
def identity_from_seed(seed_str: str) -> RNS.Identity:
    """Create Identity using same derivation as Rust's Identity::from_seed().

    prv[0:32] = SHA-256(seed), prv[32:64] = SHA-256(prv[0:32])
    """
    h1 = hashlib.sha256(seed_str.encode()).digest()
    h2 = hashlib.sha256(h1).digest()
    prv = h1 + h2
    id_ = RNS.Identity(create_keys=False)
    id_.load_private_key(prv)
    return id_


# ---------------------------------------------------------------------------
# Destination hash computation (matches rete_core::destination_hash)
# ---------------------------------------------------------------------------
def compute_dest_hash(app_name: str, aspects: list, identity_hash: bytes) -> bytes:
    expanded = ".".join([app_name] + aspects)
    name_hash = hashlib.sha256(expanded.encode()).digest()[:10]
    material = name_hash + identity_hash
    return hashlib.sha256(material).digest()[:16]


def compute_name_hash(app_name: str, aspects: list) -> bytes:
    expanded = ".".join([app_name] + aspects)
    return hashlib.sha256(expanded.encode()).digest()[:10]


# ---------------------------------------------------------------------------
# Packet construction (matches rete_core wire format)
# ---------------------------------------------------------------------------
APP_NAME = "rete"
ASPECTS = ["example", "v1"]


def build_announce(identity: RNS.Identity) -> bytes:
    """Build a raw ANNOUNCE packet (HEADER_1, SINGLE, BROADCAST)."""
    pub_key = identity.get_public_key()  # 64 bytes
    id_hash = RNS.Identity.truncated_hash(pub_key)  # 16 bytes
    dest_hash = compute_dest_hash(APP_NAME, ASPECTS, id_hash)
    name_hash = compute_name_hash(APP_NAME, ASPECTS)

    # random_hash: 5 random bytes || 5 timestamp bytes
    random_part = os.urandom(5)
    ts = int(time.time())
    ts_bytes = struct.pack(">Q", ts)[-5:]  # last 5 bytes of big-endian u64
    random_hash = random_part + ts_bytes

    # Sign: dest_hash || pub_key || name_hash || random_hash
    signed_data = dest_hash + pub_key + name_hash + random_hash
    signature = identity.sign(signed_data)

    # Announce payload: pub_key || name_hash || random_hash || signature
    payload = pub_key + name_hash + random_hash + signature

    # flags: header_type=0, context=0, transport=0, dest_type=0(SINGLE), pkt_type=1(ANNOUNCE)
    flags = 0x01
    raw = bytes([flags, 0x00]) + dest_hash + bytes([0x00]) + payload
    return raw


def build_data_packet(plaintext: bytes, recipient: RNS.Identity) -> bytes:
    """Build a raw DATA packet encrypted to recipient (HEADER_1, SINGLE)."""
    pub_key = recipient.get_public_key()
    id_hash = RNS.Identity.truncated_hash(pub_key)
    dest_hash = compute_dest_hash(APP_NAME, ASPECTS, id_hash)

    ciphertext = recipient.encrypt(plaintext)

    # flags: header_type=0, context=0, transport=0, dest_type=0(SINGLE), pkt_type=0(DATA)
    flags = 0x00
    raw = bytes([flags, 0x00]) + dest_hash + bytes([0x00]) + ciphertext
    return raw


# ---------------------------------------------------------------------------
# Main test
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Python ↔ ESP32 serial interop")
    parser.add_argument("--port", default="/dev/ttyUSB0", help="Serial port")
    parser.add_argument("--baud", type=int, default=115200, help="Baud rate")
    parser.add_argument("--timeout", type=int, default=10, help="Receive timeout (s)")
    args = parser.parse_args()

    # --- Create identities ---
    # ESP32 identity (same seed as firmware)
    esp32 = identity_from_seed("rete-esp32c6-serial")
    esp32_pub = esp32.get_public_key()
    esp32_id_hash = RNS.Identity.truncated_hash(esp32_pub)
    esp32_dest = compute_dest_hash(APP_NAME, ASPECTS, esp32_id_hash)

    # Our identity (Python side)
    us = identity_from_seed("python-serial-interop")
    our_pub = us.get_public_key()
    our_id_hash = RNS.Identity.truncated_hash(our_pub)
    our_dest = compute_dest_hash(APP_NAME, ASPECTS, our_id_hash)

    print(f"[python] ESP32 dest:  {esp32_dest.hex()}")
    print(f"[python] Our dest:    {our_dest.hex()}")

    # --- Open serial port ---
    ser = pyserial.Serial(args.port, args.baud, timeout=0.1)
    decoder = HdlcDecoder()

    try:
        # Step 1: Send our announce (so ESP32 learns our identity)
        announce_raw = build_announce(us)
        ser.write(hdlc_encode(announce_raw))
        ser.flush()
        print("[python] sent ANNOUNCE")

        # Brief delay for ESP32 to process the announce
        time.sleep(0.3)

        # Step 2: Send encrypted DATA with a unique ping
        ts = int(time.time())
        ping_msg = f"ping:{ts}".encode()
        data_raw = build_data_packet(ping_msg, esp32)
        ser.write(hdlc_encode(data_raw))
        ser.flush()
        print(f"[python] sent DATA: ping:{ts}")

        # Step 3: Wait for echo
        deadline = time.time() + args.timeout
        echo_text = None

        while time.time() < deadline:
            chunk = ser.read(512)
            if not chunk:
                continue

            frames = decoder.feed(chunk)
            for frame in frames:
                if len(frame) < 19:
                    continue
                flags = frame[0]
                pkt_type = flags & 0x03
                if pkt_type != 0:  # not DATA
                    continue

                dest = frame[2:18]
                if dest != our_dest:
                    continue

                ciphertext = frame[19:]
                try:
                    plaintext = us.decrypt(ciphertext)
                    echo_text = plaintext.decode("utf-8", errors="replace")
                    print(f"[python] received DATA: {echo_text}")
                except Exception as e:
                    print(f"[python] decrypt failed: {e}")

            if echo_text is not None:
                break

        # Step 4: Verify
        expected = f"echo:ping:{ts}"
        if echo_text == expected:
            print(f"PASS: echo matches '{expected}'")
        elif echo_text is not None:
            print(f"FAIL: expected '{expected}', got '{echo_text}'")
            sys.exit(1)
        else:
            print(f"FAIL: no echo received within {args.timeout}s")
            sys.exit(1)

    finally:
        ser.close()
        shutil.rmtree(_tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
