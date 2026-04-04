#!/usr/bin/env python3
"""Probe: capture RPC control plane wire format.

Starts rnsd, then intercepts the raw bytes of the multiprocessing.connection
HMAC auth exchange and a complete RPC request/response cycle.

This probe captures:
- HMAC auth challenge bytes
- HMAC auth response bytes
- HMAC welcome bytes
- Raw pickle bytes for {"get": "interface_stats"} request
- Raw pickle bytes for the response
- Pickle protocol version and opcodes used

Output goes to tests/fixtures/shared-instance/{unix,tcp}/control-status-query/
"""

import hashlib
import hmac as hmac_mod
import io
import json
import os
import pickle
import pickletools
import socket
import struct
import subprocess
import sys
import tempfile
import time
import traceback

from probe_helpers import write_fixture, stop_process


def pickle_opcodes(data):
    """Extract pickle opcodes from raw bytes for documentation."""
    out = io.StringIO()
    try:
        pickletools.dis(data, output=out)
    except Exception as e:
        out.write(f"\n(parse error: {e})")
    return out.getvalue()


def capture_rpc_raw(addr, family, authkey, mode):
    """Capture raw RPC bytes using low-level socket operations.

    We do the multiprocessing.connection protocol manually to capture
    every byte on the wire.
    """
    scenario = "control-status-query"
    captured = {}

    # --- Step 1: Connect at socket level ---
    if family == "AF_UNIX":
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(addr)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(addr)

    def recv_bytes_raw():
        """Read a length-prefixed message from the connection."""
        header = b""
        while len(header) < 4:
            chunk = sock.recv(4 - len(header))
            if not chunk:
                raise EOFError("connection closed")
            header += chunk
        length = struct.unpack("!I", header)[0]
        data = b""
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                raise EOFError("connection closed")
            data += chunk
        return header + data  # return with length prefix for capture

    def send_bytes_raw(data):
        """Send a length-prefixed message."""
        header = struct.pack("!I", len(data))
        sock.sendall(header + data)
        return header + data  # return full wire bytes

    # --- Step 2: Auth exchange ---
    # Server sends CHALLENGE
    challenge_wire = recv_bytes_raw()
    challenge_payload = challenge_wire[4:]  # strip length prefix
    captured["challenge_wire"] = challenge_wire
    print(f"  challenge: {len(challenge_wire)} bytes total, payload={len(challenge_payload)}")
    print(f"  challenge prefix: {challenge_payload[:20]}")

    # Parse challenge: strip #CHALLENGE# prefix
    challenge_prefix = b"#CHALLENGE#"
    if not challenge_payload.startswith(challenge_prefix):
        print(f"  ERROR: unexpected challenge prefix: {challenge_payload[:30]}")
        sock.close()
        return None

    challenge_message = challenge_payload[len(challenge_prefix):]
    print(f"  challenge message: {len(challenge_message)} bytes")
    print(f"  challenge message starts with: {challenge_message[:20]}")

    # Detect digest name from challenge
    digest_name = None
    if challenge_message.startswith(b"{") and b"}" in challenge_message[:30]:
        end = challenge_message.index(b"}")
        digest_name = challenge_message[1:end].decode("ascii")
        print(f"  detected digest: {digest_name}")

    if digest_name:
        mac = hmac_mod.new(authkey, challenge_message, digest_name).digest()
        response_payload = b"{%s}%s" % (digest_name.encode(), mac)
    else:
        # Legacy MD5
        mac = hmac_mod.new(authkey, challenge_message, "md5").digest()
        response_payload = mac
        digest_name = "md5"

    auth_response_wire = send_bytes_raw(response_payload)
    captured["auth_response_wire"] = auth_response_wire
    print(f"  response: {len(auth_response_wire)} bytes, digest={digest_name}")

    # Server sends WELCOME or FAILURE
    welcome_wire = recv_bytes_raw()
    welcome_payload = welcome_wire[4:]
    captured["welcome_wire"] = welcome_wire
    print(f"  welcome: {welcome_payload}")

    if welcome_payload != b"#WELCOME#":
        print(f"  ERROR: auth failed: {welcome_payload}")
        sock.close()
        return None

    # --- Step 2b: Mutual auth (server challenges us back) ---
    # Now WE must also challenge the server (mutual auth)
    # Actually — the Listener.accept() calls deliver_challenge then answer_challenge
    # The Client() constructor calls answer_challenge then deliver_challenge
    # So after we answered the server's challenge and got WELCOME,
    # we must now deliver our own challenge to the server and verify its response.

    # Send our challenge
    our_nonce = os.urandom(40)
    our_challenge_msg = b"{sha256}" + our_nonce
    our_challenge_wire = send_bytes_raw(b"#CHALLENGE#" + our_challenge_msg)
    captured["our_challenge_wire"] = our_challenge_wire

    # Receive server's response
    server_response_wire = recv_bytes_raw()
    server_response_payload = server_response_wire[4:]
    captured["server_response_wire"] = server_response_wire

    # Verify server's response
    if server_response_payload.startswith(b"{"):
        end = server_response_payload.index(b"}")
        resp_digest = server_response_payload[1:end].decode("ascii")
        resp_mac = server_response_payload[end + 1:]
        expected = hmac_mod.new(authkey, our_challenge_msg, resp_digest).digest()
        server_auth_ok = hmac_mod.compare_digest(expected, resp_mac)
    else:
        expected = hmac_mod.new(authkey, our_challenge_msg, "md5").digest()
        server_auth_ok = hmac_mod.compare_digest(expected, server_response_payload)

    print(f"  server auth ok: {server_auth_ok}")

    # Send WELCOME to server
    welcome_back_wire = send_bytes_raw(b"#WELCOME#")
    captured["welcome_back_wire"] = welcome_back_wire

    # --- Step 3: RPC request ---
    request_obj = {"get": "interface_stats"}
    request_pickle = pickle.dumps(request_obj, protocol=2)
    captured["request_pickle"] = request_pickle
    request_wire = send_bytes_raw(request_pickle)
    captured["request_wire"] = request_wire
    print(f"  request pickle: {len(request_pickle)} bytes (protocol 2)")

    # --- Step 4: RPC response ---
    response_wire = recv_bytes_raw()
    response_pickle = response_wire[4:]
    captured["response_pickle"] = response_pickle
    captured["response_wire"] = response_wire
    print(f"  response pickle: {len(response_pickle)} bytes")

    response_obj = pickle.loads(response_pickle)
    captured["response_obj"] = response_obj
    print(f"  response type: {type(response_obj).__name__}")
    if isinstance(response_obj, dict):
        print(f"  response keys: {list(response_obj.keys())[:10]}")

    sock.close()

    # --- Write fixtures ---
    # Auth bytes
    write_fixture(mode, scenario, "rpc_auth.bin",
                  captured["challenge_wire"] + captured["auth_response_wire"] + captured["welcome_wire"])

    # Request/response pickle
    write_fixture(mode, scenario, "rpc_request.bin", request_pickle)
    write_fixture(mode, scenario, "rpc_response.bin", response_pickle)

    # Pickle disassembly
    request_dis = pickle_opcodes(request_pickle)
    response_dis = pickle_opcodes(response_pickle)

    # Metadata
    metadata = {
        "scenario": scenario,
        "mode": mode,
        "rns_version": "1.1.4",
        "auth_digest": digest_name,
        "challenge_total_bytes": len(captured["challenge_wire"]),
        "challenge_message_bytes": len(challenge_message),
        "request_pickle_bytes": len(request_pickle),
        "request_pickle_protocol": 2,
        "response_pickle_bytes": len(response_pickle),
        "response_type": type(response_obj).__name__,
        "mutual_auth": True,
        "server_auth_ok": server_auth_ok,
        "capture_date": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    write_fixture(mode, scenario, "metadata.json",
                  json.dumps(metadata, indent=2))

    # Control log
    write_fixture(mode, scenario, "control.log", f"""\
=== Auth Exchange ===
Challenge wire ({len(captured['challenge_wire'])} bytes): {captured['challenge_wire'].hex()}
Auth response wire ({len(captured['auth_response_wire'])} bytes): {captured['auth_response_wire'].hex()}
Welcome wire ({len(captured['welcome_wire'])} bytes): {captured['welcome_wire'].hex()}
Digest algorithm: {digest_name}
Mutual auth: yes (server_auth_ok={server_auth_ok})

=== Request ===
Object: {request_obj}
Pickle ({len(request_pickle)} bytes): {request_pickle.hex()}

=== Request Pickle Disassembly ===
{request_dis}

=== Response ===
Pickle ({len(response_pickle)} bytes): {response_pickle.hex()}

=== Response Pickle Disassembly ===
{response_dis}
""")

    write_fixture(mode, scenario, "notes.md", f"""\
# Control Status Query — {mode.upper()} Mode

## Auth Protocol
- Python 3.12 `multiprocessing.connection` uses `{{sha256}}` prefixed challenges
- HMAC digest: {digest_name}
- Mutual auth: server challenges client, then client challenges server
- Auth key: SHA-256 of transport identity private key (or explicit rpc_key)

## Wire Format
- Messages are 4-byte big-endian length prefix + payload
- Auth messages are raw bytes (challenge/response/welcome)
- RPC messages are pickle-serialized Python dicts

## Request: `{{"get": "interface_stats"}}`
- Pickle protocol: 2
- Pickle bytes: {len(request_pickle)}
- Opcodes: see control.log for full disassembly

## Response
- Type: {type(response_obj).__name__}
- Pickle bytes: {len(response_pickle)}
- Keys: {list(response_obj.keys())[:10] if isinstance(response_obj, dict) else 'N/A'}
""")

    return captured


def run_probe(mode="unix"):
    """Start rnsd and capture RPC exchange."""
    with tempfile.TemporaryDirectory() as config_dir:
        config_path = os.path.join(config_dir, "config")

        if mode == "unix":
            with open(config_path, "w") as f:
                f.write("""\
[reticulum]
  share_instance = Yes
  enable_transport = No

[logging]
  loglevel = 7
""")
            rpc_addr = "\0rns/default/rpc"
            rpc_family = "AF_UNIX"
        else:
            data_port = 47428
            ctrl_port = 47429
            with open(config_path, "w") as f:
                f.write(f"""\
[reticulum]
  share_instance = Yes
  shared_instance_type = tcp
  shared_instance_port = {data_port}
  instance_control_port = {ctrl_port}
  enable_transport = No

[logging]
  loglevel = 7
""")
            rpc_addr = ("127.0.0.1", ctrl_port)
            rpc_family = "AF_INET"

        print(f"[probe] starting rnsd ({mode})...")
        proc = subprocess.Popen(
            ["rnsd", "--config", config_dir, "-vvv"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        time.sleep(5)

        if proc.poll() is not None:
            _, stderr = proc.communicate()
            print(f"[probe] rnsd died: {stderr.decode(errors='replace')[-500:]}")
            return False

        # Derive the authkey from the daemon's identity file.
        # authkey = SHA-256(transport_identity_private_key)
        identity_path = os.path.join(config_dir, "storage", "transport_identity")
        if not os.path.exists(identity_path):
            print(f"[probe] identity file not found at {identity_path}")
            stop_process(proc)
            return False

        with open(identity_path, "rb") as f:
            private_key = f.read()
        authkey = hashlib.sha256(private_key).digest()
        print(f"[probe] authkey: {len(authkey)} bytes (from {identity_path})")

        try:
            captured = capture_rpc_raw(rpc_addr, rpc_family, authkey, mode)
            success = captured is not None
        except Exception as e:
            print(f"[probe] RPC capture failed: {e}")
            traceback.print_exc()
            success = False

        stop_process(proc)
        return success


def run_probe_subprocess(mode):
    """Run a single probe in a subprocess to avoid RNS singleton issues."""
    result = subprocess.run(
        [sys.executable, __file__, f"--mode={mode}"],
        capture_output=True, text=True, timeout=60,
    )
    print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    return result.returncode == 0


if __name__ == "__main__":
    # Support --mode=X for subprocess invocation
    mode_arg = None
    for arg in sys.argv[1:]:
        if arg.startswith("--mode="):
            mode_arg = arg.split("=", 1)[1]

    if mode_arg:
        # Single-mode subprocess run
        ok = run_probe(mode_arg)
        sys.exit(0 if ok else 1)
    else:
        # Main entry: run each mode in its own subprocess
        ok = True
        ok = run_probe_subprocess("unix") and ok
        ok = run_probe_subprocess("tcp") and ok
        if ok:
            print("\n[probe] control: ALL OK")
        else:
            print("\n[probe] control: SOME CHECKS FAILED")
            sys.exit(1)
