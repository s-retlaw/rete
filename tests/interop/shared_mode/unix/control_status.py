#!/usr/bin/env python3
"""S1-UNX-CTRL-001: Stock Python rnstatus queries rete-shared over Unix.

Topology:
  Rust daemon (rete-shared) in Unix shared mode
  + Python RNS client that queries interface_stats via the RPC control socket

Usage:
  cargo build -p rete-daemon --bin rete-shared
  cd tests/interop
  uv run python shared_mode/unix/control_status.py [--rust-binary PATH]
"""

import hashlib
import hmac
import os
import pickle
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shared_mode_helpers import SharedModeTest, parse_args


def rpc_query_raw(sock_path, authkey, request_dict):
    """Connect to a Unix control socket, authenticate, send a pickle RPC
    request, and return the decoded response dict."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(sock_path)

    # Read challenge
    challenge = _read_message(s)
    assert challenge.startswith(b"#CHALLENGE#"), f"bad challenge: {challenge[:30]}"

    # Python multiprocessing.connection._create_response computes HMAC
    # over everything after #CHALLENGE# (the "message"), and prefixes
    # the response with {digest_name}.
    message = challenge[len(b"#CHALLENGE#"):]
    if b"{sha256}" in challenge:
        digest = hmac.new(authkey, message, "sha256").digest()
        prefix = b"{sha256}"
    else:
        digest = hmac.new(authkey, message, "md5").digest()
        prefix = b""

    # Send digest
    _write_message(s, prefix + digest)

    # Read welcome
    result = _read_message(s)
    if result != b"#WELCOME#":
        s.close()
        return None  # auth failed

    # Send request
    _write_message(s, pickle.dumps(request_dict, protocol=2))

    # Read response
    response_bytes = _read_message(s)
    s.close()

    return pickle.loads(response_bytes)


def rpc_query_tcp(host, port, authkey, request_dict):
    """Connect to a TCP control port, authenticate, send a pickle RPC
    request, and return the decoded response dict."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((host, port))

    # Read challenge
    challenge = _read_message(s)
    assert challenge.startswith(b"#CHALLENGE#"), f"bad challenge: {challenge[:30]}"

    if b"{sha256}" in challenge:
        nonce = challenge[challenge.index(b"{sha256}") + len(b"{sha256}"):]
        digest = hmac.new(authkey, nonce, "sha256").digest()
        prefix = b"{sha256}"
    else:
        nonce = challenge[len(b"#CHALLENGE#"):]
        digest = hmac.new(authkey, nonce, "md5").digest()
        prefix = b""

    _write_message(s, prefix + digest)

    result = _read_message(s)
    if result != b"#WELCOME#":
        s.close()
        return None

    _write_message(s, pickle.dumps(request_dict, protocol=2))

    response_bytes = _read_message(s)
    s.close()

    return pickle.loads(response_bytes)


def _read_message(sock):
    """Read a 4-byte length-prefixed message."""
    length_bytes = _recv_exact(sock, 4)
    length = struct.unpack(">I", length_bytes)[0]
    return _recv_exact(sock, length)


def _write_message(sock, payload):
    """Write a 4-byte length-prefixed message."""
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def _recv_exact(sock, n):
    """Receive exactly n bytes."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError(f"expected {n} bytes, got {len(data)}")
        data += chunk
    return data


def derive_authkey(identity_file_path):
    """Derive the RPC authkey from the daemon's identity file.
    authkey = SHA-256(identity_private_key_bytes) (matches Python RNS)."""
    with open(identity_file_path, "rb") as f:
        prv_bytes = f.read()
    return hashlib.sha256(prv_bytes).digest()


def main():
    args = parse_args()
    t = SharedModeTest("S1-UNX-CTRL-001", rust_binary=args.rust_binary)

    try:
        print("Starting rete-shared daemon (Unix mode)...")
        t.start_daemon(instance_type="unix")
        time.sleep(0.3)

        # Derive authkey from daemon identity
        identity_path = os.path.join(t.data_dir, "identity")
        t.check(os.path.isfile(identity_path), "Identity file exists")
        authkey = derive_authkey(identity_path)

        # Query interface_stats via Unix control socket
        sock_path = "\0rns/default/rpc"
        print("Querying interface_stats via Unix control socket...")
        response = rpc_query_raw(sock_path, authkey, {"get": "interface_stats"})
        t.check(response is not None, "RPC query returned a response")

        if response:
            t.check("interfaces" in response, "Response has 'interfaces' key")
            t.check("rxb" in response, "Response has 'rxb' key")
            t.check("txb" in response, "Response has 'txb' key")
            t.check("rss" in response, "Response has 'rss' key")

            ifaces = response.get("interfaces", [])
            t.check(len(ifaces) >= 1, f"At least 1 interface (got {len(ifaces)})")

            if ifaces:
                iface = ifaces[0]
                name = iface.get("name", "")
                t.check(
                    "Shared Instance" in name,
                    f"Interface name contains 'Shared Instance': {name}",
                )
                t.check(
                    iface.get("type") == "LocalServerInterface",
                    f"Interface type is LocalServerInterface: {iface.get('type')}",
                )
                t.check(
                    iface.get("status") is True,
                    f"Interface status is True: {iface.get('status')}",
                )

    finally:
        t.finish()


if __name__ == "__main__":
    main()
