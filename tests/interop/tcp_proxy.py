#!/usr/bin/env python3
"""TCP MITM proxy that logs decoded Reticulum packets with timestamps.

Sits between two TCP endpoints (e.g. Rust rete and rnsd), passing
all bytes transparently while parsing and logging HDLC-framed Reticulum
packets.

Usage as library:
    proxy = TcpProxy(listen_port=5000, target_port=4242, label="proxy1")
    proxy.start()       # starts in background thread
    ...
    proxy.dump_log()    # print all captured packets
    proxy.stop()

Usage standalone:
    python tcp_proxy.py --listen 5000 --target 4242 --label proxy1
"""

import hashlib
import select
import socket
import struct
import sys
import threading
import time

# HDLC constants (matching rete-core/src/hdlc.rs)
FLAG = 0x7E
ESC = 0x7D
ESC_MASK = 0x20

# Reticulum header sizes
TRUNCATED_HASH_LEN = 16
HEADER_1_OVERHEAD = 2 + TRUNCATED_HASH_LEN + 1  # flags + hops + dest_hash + context
HEADER_2_OVERHEAD = 2 + 2 * TRUNCATED_HASH_LEN + 1  # flags + hops + tid + dest_hash + context

# Packet types
PACKET_TYPES = {0: "DATA", 1: "ANNOUNCE", 2: "LINKREQUEST", 3: "PROOF"}
DEST_TYPES = {0: "SINGLE", 1: "GROUP", 2: "PLAIN", 3: "LINK"}
HEADER_TYPES = {0: "H1", 1: "H2"}


def hdlc_unescape(data: bytes) -> bytes:
    """Unescape HDLC byte-stuffed data."""
    out = bytearray()
    escape = False
    for b in data:
        if escape:
            out.append(b ^ ESC_MASK)
            escape = False
        elif b == ESC:
            escape = True
        else:
            out.append(b)
    return bytes(out)


def compute_packet_hash(raw: bytes) -> str:
    """Compute the Reticulum packet hash (SHA-256, full 32 bytes).

    hashable = (raw[0] & 0x0F) || raw[2:]   for HEADER_1
    hashable = (raw[0] & 0x0F) || raw[18:]  for HEADER_2
    """
    if len(raw) < 2:
        return "???"
    flags = raw[0]
    header_type = (flags >> 6) & 0x01
    masked_flags = flags & 0x0F
    if header_type == 1:  # H2
        if len(raw) < 18:
            return "???"
        hashable = bytes([masked_flags]) + raw[18:]
    else:  # H1
        hashable = bytes([masked_flags]) + raw[2:]
    return hashlib.sha256(hashable).hexdigest()[:16]


def decode_packet(raw: bytes) -> dict:
    """Decode a raw Reticulum packet into a dict of fields."""
    if len(raw) < HEADER_1_OVERHEAD:
        return {"error": f"too short ({len(raw)} bytes)"}

    flags = raw[0]
    hops = raw[1]
    header_type = (flags >> 6) & 0x01
    context_flag = (flags >> 5) & 0x01
    transport_type = (flags >> 4) & 0x01
    dest_type = (flags >> 2) & 0x03
    packet_type = flags & 0x03

    info = {
        "len": len(raw),
        "flags": f"0x{flags:02x}",
        "header": HEADER_TYPES.get(header_type, "?"),
        "transport": "TRANSPORT" if transport_type else "BROADCAST",
        "dest_type": DEST_TYPES.get(dest_type, "?"),
        "pkt_type": PACKET_TYPES.get(packet_type, "?"),
        "context_flag": bool(context_flag),
        "hops": hops,
        "pkt_hash": compute_packet_hash(raw),
    }

    if header_type == 1:  # H2
        if len(raw) < HEADER_2_OVERHEAD:
            info["error"] = "H2 too short"
            return info
        info["transport_id"] = raw[2:18].hex()
        info["dest_hash"] = raw[18:34].hex()
        info["context"] = f"0x{raw[34]:02x}"
        info["payload_len"] = len(raw) - HEADER_2_OVERHEAD
        payload = raw[HEADER_2_OVERHEAD:]
    else:  # H1
        info["dest_hash"] = raw[2:18].hex()
        info["context"] = f"0x{raw[18]:02x}"
        info["payload_len"] = len(raw) - HEADER_1_OVERHEAD
        payload = raw[HEADER_1_OVERHEAD:]

    # Decode announce payload
    if packet_type == 1 and len(payload) >= 148:  # ANNOUNCE
        pub_key = payload[0:64]
        name_hash = payload[64:74]
        random_hash = payload[74:84]
        # Compute identity hash from pub_key
        identity_hash = hashlib.sha256(pub_key).digest()[:16].hex()
        info["identity_hash"] = identity_hash
        info["name_hash"] = name_hash.hex()
        info["random_hash"] = random_hash.hex()
        if len(payload) > 148:
            info["app_data_len"] = len(payload) - 148

    return info


def format_packet(info: dict, direction: str, elapsed_ms: float, label: str) -> str:
    """Format a decoded packet as a single log line."""
    if "error" in info:
        return f"[{elapsed_ms:8.1f}ms] {label} {direction:4s} ERROR: {info['error']}"

    parts = [
        f"[{elapsed_ms:8.1f}ms]",
        f"{label}",
        f"{direction:4s}",
        f"{info['header']}",
        f"{info['pkt_type']:12s}",
        f"{info['dest_type']:6s}",
        f"{info['transport']}",
        f"hops={info['hops']}",
        f"dest={info['dest_hash'][:16]}",
    ]

    if "transport_id" in info:
        parts.append(f"tid={info['transport_id'][:16]}")

    parts.append(f"hash={info['pkt_hash']}")
    parts.append(f"len={info['len']}")

    if info.get("context_flag"):
        parts.append("CF=1")

    if "identity_hash" in info:
        parts.append(f"id={info['identity_hash'][:16]}")

    if "app_data_len" in info:
        parts.append(f"appdata={info['app_data_len']}b")

    return " ".join(parts)


class HdlcExtractor:
    """Extract HDLC frames from a byte stream."""

    def __init__(self):
        self._buf = bytearray()
        self._in_frame = False

    def feed(self, data: bytes):
        """Feed bytes and yield complete unescaped frames."""
        frames = []
        for b in data:
            if b == FLAG:
                if self._in_frame and len(self._buf) > 0:
                    frames.append(hdlc_unescape(bytes(self._buf)))
                self._buf.clear()
                self._in_frame = True
            elif self._in_frame:
                self._buf.append(b)
        return frames


class TcpProxy:
    """Transparent TCP proxy with Reticulum packet logging."""

    def __init__(self, listen_port: int, target_host: str = "127.0.0.1",
                 target_port: int = 4242, label: str = "proxy"):
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.label = label
        self.log = []  # list of (elapsed_ms, direction, info_dict, formatted_str)
        self._start_time = None
        self._stop = threading.Event()
        self._thread = None
        self._lock = threading.Lock()

    def start(self):
        """Start the proxy in a background thread."""
        self._start_time = time.monotonic()
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop the proxy."""
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _elapsed_ms(self):
        return (time.monotonic() - self._start_time) * 1000.0

    def _log_packet(self, direction: str, raw: bytes):
        elapsed = self._elapsed_ms()
        info = decode_packet(raw)
        formatted = format_packet(info, direction, elapsed, self.label)
        with self._lock:
            self.log.append((elapsed, direction, info, formatted))
        print(formatted, flush=True)

    def _run(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", self.listen_port))
        server.listen(1)
        server.settimeout(1.0)

        try:
            while not self._stop.is_set():
                try:
                    client_sock, _ = server.accept()
                except socket.timeout:
                    continue

                # Connect to target
                target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    target_sock.connect((self.target_host, self.target_port))
                except Exception as e:
                    print(f"[{self.label}] failed to connect to target: {e}", flush=True)
                    client_sock.close()
                    continue

                # Relay loop
                self._relay(client_sock, target_sock)
                client_sock.close()
                target_sock.close()
        finally:
            server.close()

    def _relay(self, client_sock, target_sock):
        """Bidirectional relay with packet extraction."""
        client_extractor = HdlcExtractor()
        target_extractor = HdlcExtractor()

        client_sock.setblocking(False)
        target_sock.setblocking(False)

        while not self._stop.is_set():
            readable, _, _ = select.select(
                [client_sock, target_sock], [], [], 0.1
            )

            for sock in readable:
                try:
                    data = sock.recv(65536)
                except (ConnectionError, OSError):
                    data = b""

                if not data:
                    return  # connection closed

                if sock is client_sock:
                    # Client -> Target (Rust -> rnsd)
                    try:
                        target_sock.sendall(data)
                    except (ConnectionError, OSError):
                        return
                    for frame in client_extractor.feed(data):
                        self._log_packet(">>>", frame)
                else:
                    # Target -> Client (rnsd -> Rust)
                    try:
                        client_sock.sendall(data)
                    except (ConnectionError, OSError):
                        return
                    for frame in target_extractor.feed(data):
                        self._log_packet("<<<", frame)

    def dump_log(self):
        """Print all captured packets."""
        with self._lock:
            for _, _, _, formatted in self.log:
                print(formatted)

    def get_log(self):
        """Return log entries."""
        with self._lock:
            return list(self.log)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Reticulum TCP packet proxy")
    parser.add_argument("--listen", type=int, required=True, help="Port to listen on")
    parser.add_argument("--target", type=int, required=True, help="Target port to connect to")
    parser.add_argument("--label", default="proxy", help="Label for log lines")
    args = parser.parse_args()

    proxy = TcpProxy(
        listen_port=args.listen,
        target_port=args.target,
        label=args.label,
    )
    print(f"[{args.label}] listening on :{args.listen} -> :{args.target}", flush=True)
    proxy.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        proxy.stop()


if __name__ == "__main__":
    main()
