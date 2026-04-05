#!/usr/bin/env python3
"""Transparent TCP proxy that logs every HDLC-framed RNS packet.

Sits between two RNS nodes (e.g. rete and rnsd), forwarding all
bytes transparently while decoding and logging each HDLC frame as a
parsed RNS packet.

Usage:
    python rns_proxy.py --listen 4292 --target 4291

    client (rete) --TCP--> :4292 (proxy) --TCP--> :4291 (rnsd)

Programmatic:
    from rns_proxy import start_tcp_proxy
    proxy = start_tcp_proxy(listen_port=4292, target_port=4291)
    # ... run tests ...
    proxy.stop()

Output goes to stderr so it does not interfere with test stdout parsing.
Uses only stdlib modules.
"""

import argparse
import select
import socket
import struct
import sys
import threading
import time


# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

HDLC_FLAG = 0x7E
HDLC_ESC = 0x7D
HDLC_ESC_XOR = 0x20

HEADER_TYPE_NAMES = {0: "HEADER_1", 1: "HEADER_2"}
PACKET_TYPE_NAMES = {0: "DATA", 1: "ANNOUNCE", 2: "LINKREQUEST", 3: "PROOF"}
DEST_TYPE_NAMES = {0: "SINGLE", 1: "GROUP", 2: "PLAIN", 3: "LINK"}
TRANSPORT_TYPE_NAMES = {0: "BROADCAST", 1: "TRANSPORT"}

CONTEXT_NAMES = {
    0x00: "NONE",
    0x01: "RESOURCE",
    0x02: "RESOURCE_ADV",
    0x03: "RESOURCE_REQ",
    0x04: "RESOURCE_HMU",
    0x05: "RESOURCE_PRF",
    0x06: "RESOURCE_ICL",
    0x07: "RESOURCE_RCL",
    0x09: "REQUEST",
    0x0A: "RESPONSE",
    0x0E: "CHANNEL",
    0xFA: "KEEPALIVE",
    0xFB: "LINKIDENTIFY",
    0xFC: "LINKCLOSE",
    0xFD: "LINKPROOF",
    0xFE: "LRRTT",
    0xFF: "LRPROOF",
}


# ---------------------------------------------------------------------------
# HDLC frame decoder
# ---------------------------------------------------------------------------

class HdlcDecoder:
    """Incremental HDLC frame decoder.

    Feed raw bytes via feed(). Complete un-escaped frames are returned
    by feed() as a list. The FLAG delimiters are stripped; empty frames
    (back-to-back flags) are silently dropped.
    """

    def __init__(self):
        self._buf = bytearray()
        self._in_frame = False
        self._escape = False

    def feed(self, data: bytes) -> list[bytes]:
        """Process raw bytes, return list of complete frames."""
        frames = []
        for b in data:
            if b == HDLC_FLAG:
                if self._in_frame and len(self._buf) > 0:
                    frames.append(bytes(self._buf))
                self._buf.clear()
                self._in_frame = True
                self._escape = False
            elif not self._in_frame:
                # Discard bytes outside a frame
                continue
            elif b == HDLC_ESC:
                self._escape = True
            elif self._escape:
                self._buf.append(b ^ HDLC_ESC_XOR)
                self._escape = False
            else:
                self._buf.append(b)
        return frames


# ---------------------------------------------------------------------------
# RNS packet parser
# ---------------------------------------------------------------------------

def parse_flags(flags_byte: int) -> dict:
    """Decompose the RNS flags byte into its fields."""
    return {
        "header_type": (flags_byte >> 6) & 0x03,
        "context_flag": (flags_byte >> 5) & 0x01,
        "transport_type": (flags_byte >> 4) & 0x01,
        "dest_type": (flags_byte >> 2) & 0x03,
        "packet_type": flags_byte & 0x03,
    }


def parse_packet(raw: bytes) -> dict | None:
    """Parse an RNS packet from a complete HDLC frame payload.

    Returns a dict with parsed fields, or None if the frame is too short
    to contain a valid packet.
    """
    if len(raw) < 2:
        return None

    flags_byte = raw[0]
    f = parse_flags(flags_byte)
    hops = raw[1]

    info = {
        "flags_byte": flags_byte,
        "header_type": f["header_type"],
        "header_type_name": HEADER_TYPE_NAMES.get(f["header_type"], "?"),
        "context_flag": f["context_flag"],
        "transport_type": f["transport_type"],
        "transport_type_name": TRANSPORT_TYPE_NAMES.get(f["transport_type"], "?"),
        "dest_type": f["dest_type"],
        "dest_type_name": DEST_TYPE_NAMES.get(f["dest_type"], "?"),
        "packet_type": f["packet_type"],
        "packet_type_name": PACKET_TYPE_NAMES.get(f["packet_type"], "?"),
        "hops": hops,
        "raw_len": len(raw),
    }

    if f["header_type"] == 0:
        # HEADER_1: flags(1) + hops(1) + dest_hash(16) + context(1) + payload
        if len(raw) < 19:
            info["error"] = f"HEADER_1 too short ({len(raw)} bytes)"
            return info
        info["dest_hash"] = raw[2:18].hex()
        info["context"] = raw[18]
        info["context_name"] = CONTEXT_NAMES.get(raw[18], f"0x{raw[18]:02x}")
        payload = raw[19:]
        info["payload_len"] = len(payload)
        info["payload_head"] = payload[:64].hex()
    elif f["header_type"] == 1:
        # HEADER_2: flags(1) + hops(1) + transport_id(16) + dest_hash(16) + context(1) + payload
        if len(raw) < 35:
            info["error"] = f"HEADER_2 too short ({len(raw)} bytes)"
            return info
        info["transport_id"] = raw[2:18].hex()
        info["dest_hash"] = raw[18:34].hex()
        info["context"] = raw[34]
        info["context_name"] = CONTEXT_NAMES.get(raw[34], f"0x{raw[34]:02x}")
        payload = raw[35:]
        info["payload_len"] = len(payload)
        info["payload_head"] = payload[:64].hex()
    else:
        info["error"] = f"unknown header_type {f['header_type']}"

    return info


def format_packet(direction: str, info: dict) -> str:
    """Format a parsed packet dict into a human-readable log line."""
    ts = time.time()
    us = int((ts % 1) * 1_000_000)
    ts_str = time.strftime("%H:%M:%S", time.localtime(ts)) + f".{us:06d}"

    parts = [f"[{ts_str}] {direction}"]

    if info is None:
        parts.append("  <too short to parse>")
        return " ".join(parts)

    flags_str = (
        f"{info['header_type_name']} "
        f"{info['transport_type_name']} "
        f"{info['dest_type_name']} "
        f"{info['packet_type_name']}"
    )
    parts.append(f"flags=0x{info['flags_byte']:02x}({flags_str})")
    parts.append(f"hops={info['hops']}")

    if "error" in info:
        parts.append(f"ERROR: {info['error']}")
        return " ".join(parts)

    if "transport_id" in info:
        parts.append(f"via={info['transport_id'][:16]}...")

    parts.append(f"dest={info['dest_hash']}")
    parts.append(f"ctx={info['context_name']}")
    parts.append(f"payload={info['payload_len']}B")

    if info["payload_len"] > 0:
        head = info["payload_head"]
        if info["payload_len"] > 64:
            head += "..."
        parts.append(f"[{head}]")

    return " ".join(parts)


# ---------------------------------------------------------------------------
# TCP proxy core
# ---------------------------------------------------------------------------

class TcpProxy:
    """Transparent TCP proxy with HDLC/RNS packet logging.

    Listens on `listen_port`, and for each accepted client connects to
    `target_host:target_port`. Bytes are forwarded transparently in both
    directions; HDLC frames are decoded and logged to stderr.
    """

    def __init__(
        self,
        listen_port: int,
        target_port: int,
        target_host: str = "127.0.0.1",
        listen_host: str = "127.0.0.1",
        log_file=None,
    ):
        self.listen_port = listen_port
        self.target_port = target_port
        self.target_host = target_host
        self.listen_host = listen_host
        self._log_file = log_file or sys.stderr
        self._stop = threading.Event()
        self._server_sock = None
        self._threads: list[threading.Thread] = []
        self._lock = threading.Lock()
        self._sessions: list[dict] = []

    def _log(self, msg: str):
        try:
            self._log_file.write(msg + "\n")
            self._log_file.flush()
        except (OSError, ValueError):
            pass

    def start(self):
        """Bind the listen socket and start the accept loop in a thread."""
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.listen_host, self.listen_port))
        self._server_sock.listen(4)
        self._server_sock.settimeout(0.5)
        self._log(
            f"[proxy] listening on {self.listen_host}:{self.listen_port} "
            f"-> {self.target_host}:{self.target_port}"
        )
        t = threading.Thread(target=self._accept_loop, daemon=True)
        t.start()
        with self._lock:
            self._threads.append(t)

    def stop(self):
        """Signal all threads to stop and close sockets."""
        self._stop.set()
        # Close all session sockets to unblock selects
        with self._lock:
            for sess in self._sessions:
                for s in (sess.get("client"), sess.get("server")):
                    if s:
                        try:
                            s.close()
                        except OSError:
                            pass
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
        # Wait for threads to finish
        with self._lock:
            threads = list(self._threads)
        for t in threads:
            t.join(timeout=3.0)
        self._log("[proxy] stopped")

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                client_sock, client_addr = self._server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            self._log(f"[proxy] client connected from {client_addr}")

            # Connect to target
            try:
                server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_sock.connect((self.target_host, self.target_port))
            except OSError as e:
                self._log(f"[proxy] failed to connect to target: {e}")
                client_sock.close()
                continue

            session = {"client": client_sock, "server": server_sock}
            with self._lock:
                self._sessions.append(session)

            t = threading.Thread(
                target=self._relay_session,
                args=(client_sock, server_sock),
                daemon=True,
            )
            t.start()
            with self._lock:
                self._threads.append(t)

    def _relay_session(self, client_sock: socket.socket, server_sock: socket.socket):
        """Bidirectional relay for one client<->server session."""
        client_decoder = HdlcDecoder()
        server_decoder = HdlcDecoder()

        try:
            while not self._stop.is_set():
                readable, _, _ = select.select(
                    [client_sock, server_sock], [], [], 0.25
                )
                for sock in readable:
                    try:
                        data = sock.recv(4096)
                    except OSError:
                        data = b""

                    if not data:
                        self._log("[proxy] session closed")
                        return

                    if sock is client_sock:
                        # client -> server
                        try:
                            server_sock.sendall(data)
                        except OSError:
                            return
                        frames = client_decoder.feed(data)
                        direction = "client -> server"
                    else:
                        # server -> client
                        try:
                            client_sock.sendall(data)
                        except OSError:
                            return
                        frames = server_decoder.feed(data)
                        direction = "server -> client"

                    for frame in frames:
                        info = parse_packet(frame)
                        self._log(format_packet(direction, info))
        finally:
            for s in (client_sock, server_sock):
                try:
                    s.close()
                except OSError:
                    pass


# ---------------------------------------------------------------------------
# Programmatic API
# ---------------------------------------------------------------------------

def start_tcp_proxy(
    listen_port: int,
    target_port: int,
    target_host: str = "127.0.0.1",
    listen_host: str = "127.0.0.1",
    log_file=None,
) -> TcpProxy:
    """Launch a proxy in background threads and return the proxy object.

    Call proxy.stop() when done.
    """
    proxy = TcpProxy(
        listen_port=listen_port,
        target_port=target_port,
        target_host=target_host,
        listen_host=listen_host,
        log_file=log_file,
    )
    proxy.start()
    return proxy


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Transparent TCP proxy with RNS/HDLC packet logging"
    )
    parser.add_argument(
        "--listen",
        type=int,
        required=True,
        help="Port to listen on for incoming connections",
    )
    parser.add_argument(
        "--target",
        type=int,
        required=True,
        help="Port to connect to (the real RNS node)",
    )
    parser.add_argument(
        "--target-host",
        default="127.0.0.1",
        help="Target host (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--listen-host",
        default="127.0.0.1",
        help="Listen host (default: 127.0.0.1)",
    )
    args = parser.parse_args()

    proxy = TcpProxy(
        listen_port=args.listen,
        target_port=args.target,
        target_host=args.target_host,
        listen_host=args.listen_host,
    )
    proxy.start()

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[proxy] shutting down...", file=sys.stderr)
        proxy.stop()


if __name__ == "__main__":
    main()
