"""Transparent Unix socket proxy with HDLC frame logging.

Sits between a Python RNS client and the daemon, forwarding all bytes
bidirectionally while logging each decoded HDLC frame with timestamps.

Usage:
    proxy = SocketProxy(daemon_socket="\0rns/default", proxy_socket="\0rns/proxy/default")
    proxy.start()  # Returns (proxy_socket_path, log_lines)
"""

import os
import socket
import threading
import time


HDLC_FLAG = 0x7E
HDLC_ESC = 0x7D
HDLC_ESC_MASK = 0x20


def decode_hdlc_frames(data):
    """Extract HDLC frames from raw bytes. Returns list of decoded frame bytes."""
    frames = []
    in_frame = False
    escape = False
    buf = bytearray()

    for byte in data:
        if byte == HDLC_FLAG:
            if in_frame and len(buf) > 0:
                frames.append(bytes(buf))
                buf = bytearray()
            in_frame = True
            escape = False
        elif not in_frame:
            continue
        elif byte == HDLC_ESC:
            escape = True
        elif escape:
            buf.append(byte ^ HDLC_ESC_MASK)
            escape = False
        else:
            buf.append(byte)

    return frames


def describe_frame(frame):
    """Produce a human-readable description of an RNS packet frame."""
    if len(frame) < 2:
        return f"len={len(frame)} (too short)"

    flags = frame[0]
    hops = frame[1]
    header_type = (flags >> 6) & 0x03
    context_flag = (flags >> 5) & 1
    transport_type = (flags >> 4) & 1
    dest_type = (flags >> 2) & 3
    pkt_type = flags & 3

    h = "H2" if header_type == 1 else "H1"
    dtype = ["SINGLE", "GROUP", "PLAIN", "LINK"][dest_type]
    ptype = ["DATA", "ANNOUNCE", "LINKREQ", "PROOF"][pkt_type]
    tt = "TRANSPORT" if transport_type else "BROADCAST"

    if h == "H2" and len(frame) > 34:
        ctx = frame[34]
        dest_hex = frame[18:26].hex()
    elif len(frame) > 18:
        ctx = frame[18]
        dest_hex = frame[2:10].hex()
    else:
        ctx = -1
        dest_hex = frame[2:min(10, len(frame))].hex()

    return f"{h} {ptype} {dtype} {tt} hops={hops} ctx=0x{ctx:02x} cflag={context_flag} dest={dest_hex}.. len={len(frame)}"


class SocketProxy:
    """Transparent proxy for abstract-namespace Unix sockets with frame logging."""

    def __init__(self, daemon_socket, proxy_socket, label="proxy"):
        self.daemon_socket = daemon_socket
        self.proxy_socket = proxy_socket
        self.label = label
        self.log_lines = []
        self._stop = threading.Event()
        self._server_thread = None
        self._client_counter = 0

    def _log(self, direction, client_id, raw_bytes):
        """Log HDLC frames from raw bytes."""
        ts = time.monotonic()
        frames = decode_hdlc_frames(raw_bytes)
        for frame in frames:
            desc = describe_frame(frame)
            line = f"[{ts:.4f}] [{self.label}] client={client_id} {direction} {desc}"
            self.log_lines.append(line)

    def _relay(self, src, dst, direction, client_id):
        """Forward bytes from src to dst, logging frames."""
        try:
            while not self._stop.is_set():
                data = src.recv(65536)
                if not data:
                    break
                self._log(direction, client_id, data)
                dst.sendall(data)
        except (OSError, BrokenPipeError):
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def _handle_client(self, client_sock, client_id):
        """Handle one client connection: connect to daemon, relay both directions."""
        try:
            daemon_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            daemon_sock.connect(self.daemon_socket)
        except Exception as e:
            self.log_lines.append(f"[{time.monotonic():.4f}] [{self.label}] client={client_id} CONNECT_FAIL {e}")
            client_sock.close()
            return

        self.log_lines.append(f"[{time.monotonic():.4f}] [{self.label}] client={client_id} CONNECTED")

        # Bidirectional relay
        c2d = threading.Thread(target=self._relay, args=(client_sock, daemon_sock, "C->D", client_id), daemon=True)
        d2c = threading.Thread(target=self._relay, args=(daemon_sock, client_sock, "D->C", client_id), daemon=True)
        c2d.start()
        d2c.start()
        c2d.join()
        d2c.join()

        self.log_lines.append(f"[{time.monotonic():.4f}] [{self.label}] client={client_id} DISCONNECTED")
        client_sock.close()
        daemon_sock.close()

    def _server_loop(self):
        """Accept client connections and spawn relay threads."""
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(self.proxy_socket)
        server.listen(5)
        server.settimeout(1.0)

        while not self._stop.is_set():
            try:
                client_sock, _ = server.accept()
                self._client_counter += 1
                cid = self._client_counter
                threading.Thread(target=self._handle_client, args=(client_sock, cid), daemon=True).start()
            except socket.timeout:
                continue

        server.close()

    def start(self):
        """Start the proxy server in a background thread."""
        self._server_thread = threading.Thread(target=self._server_loop, daemon=True)
        self._server_thread.start()

    def stop(self):
        """Stop the proxy."""
        self._stop.set()
        if self._server_thread:
            self._server_thread.join(timeout=3)

    def dump_log(self):
        """Print all logged frames."""
        for line in self.log_lines:
            print(line)
