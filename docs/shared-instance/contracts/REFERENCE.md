# Shared-Mode Reference Contract

Created: 2026-04-02
Reference date: 2026-04-02
Frozen: 2026-04-04

## Pinned Reference Version

All shared-mode compatibility work targets this exact version:

- **Python RNS version:** 1.1.4
- **Git commit:** `1b50b7f446e096cc9f893f5f45d24ea266889b4d`
- **Repository:** <https://github.com/markqvist/Reticulum>
- **Local clone:** `/tmp/Reticulum` (in devcontainer)
- **Pin date:** 2026-04-04

Golden traces, probe scripts, and E2E tests MUST be run against this version.
If upstream changes after this date, compatibility is still measured against
the pinned version above.

## Upstream Documentation

Primary shared-instance references:

- Reticulum system/shared-instance guide:
  - <https://reticulum.network/manual/using.html>
- Reticulum API reference:
  - <https://reticulum.network/manual/reference.html>

## Upstream Python Modules

These modules are the Python implementation references for shared-mode behavior:

- Reticulum core/shared-instance setup:
  - <https://github.com/markqvist/Reticulum/blob/master/RNS/Reticulum.py>
- Local shared attach behavior:
  - <https://github.com/markqvist/Reticulum/blob/master/RNS/Interfaces/LocalInterface.py>
- Backbone/epoll server behavior:
  - <https://github.com/markqvist/Reticulum/blob/master/RNS/Interfaces/BackboneInterface.py>
- Transport/shared-state behavior:
  - <https://github.com/markqvist/Reticulum/blob/master/RNS/Transport.py>
- Shared daemon entrypoint:
  - <https://github.com/markqvist/Reticulum/blob/master/RNS/Utilities/rnsd.py>
- Shared status utility:
  - <https://github.com/markqvist/Reticulum/blob/master/RNS/Utilities/rnstatus.py>
- Path/status utility behavior:
  - <https://github.com/markqvist/Reticulum/blob/master/RNS/Utilities/rnpath.py>

## Compatibility Notes By Subsystem

### Shared Attach

Freeze:

- instance naming behavior
- local attach transport expectations
- attach/detach/reconnect behavior
- client session registration expectations

Primary references:

- `using.html`
- `LocalInterface.py`
- `Reticulum.py`

### Shared Control / Status

Freeze:

- in-scope status/control request shapes
- auth/permission expectations where `rpc_key` applies
- utility compatibility needed for v1

Primary references:

- `Reticulum.py`
- `rnsd.py`
- `rnstatus.py`
- `rnpath.py`

### Shared State

Freeze:

- what lives in the daemon as canonical state
- what is session-scoped
- what must survive client disconnect
- what must survive daemon restart

Primary references:

- `Reticulum.py`
- `Transport.py`

### Config

Freeze semantics for the in-scope shared-mode settings:

- `share_instance`
- `instance_name`
- `shared_instance_type`
- `shared_instance_port`
- `instance_control_port`
- `rpc_key`

Primary references:

- `using.html`
- `Reticulum.py`
- `rnsd.py`

## Local Starting Points In This Repo

Current relevant local code and docs:

- Shared attach starting point:
  - [../../../crates/rete-tokio/src/local.rs](../../../crates/rete-tokio/src/local.rs)
- Hosted example current surface:
  - [../../../examples/daemon/src/main.rs](../../../examples/daemon/src/main.rs)
- Architectural prerequisite:
  - [../../ARCHITECTURAL_REVIEW_2026-04-01.md](../../ARCHITECTURAL_REVIEW_2026-04-01.md)

These are starting points, not the compatibility contract.

## Two-Socket Architecture

The Python shared instance uses two separate sockets:

### Data Socket (Shared Instance Port)

- **Unix mode:** abstract-namespace socket `\0rns/{instance_name}`
- **TCP mode:** `127.0.0.1:{shared_instance_port}` (default 37428)
- **Protocol:** HDLC-framed RNS packets only (FLAG=0x7E, ESC=0x7D, ESC_MASK=0x20)
- **No handshake**, no control messages, no heartbeat on this socket
- Client disconnect triggers `shared_connection_disappeared()` in Transport.py

### Control/RPC Socket (Instance Control Port)

- **Unix mode:** abstract-namespace socket `\0rns/{instance_name}/rpc`
- **TCP mode:** `127.0.0.1:{instance_control_port}` (default 37429)
- **Protocol:** Python `multiprocessing.connection` (length-prefixed + HMAC auth + pickle)
- **Ephemeral:** one connection per request/response pair, then close
- **Auth:** HMAC challenge-response using `authkey` (see below)

### Default Port Assignment

| Setting | Default Value | Source |
|---------|--------------|--------|
| `shared_instance_port` (data) | 37428 | `Reticulum.py` |
| `instance_control_port` (rpc) | 37429 | `Reticulum.py` |

### RPC Auth Protocol (multiprocessing.connection)

The auth handshake follows CPython's `multiprocessing.connection`:

1. Server sends: `#CHALLENGE#` + 20 random hex bytes (ASCII)
2. Client responds: HMAC digest of the challenge message
3. Server verifies, sends `#WELCOME#` or `#FAILURE#`
4. Then client verifies server in the same way (mutual auth)

**HMAC algorithm:** Python 3.12+ uses `{sha256}` prefix in challenge messages,
so the digest is HMAC-SHA256. Legacy Python (<3.12) used HMAC-MD5 without
a prefix. The Rust implementation must handle both: if the challenge message
starts with `{sha256}`, use HMAC-SHA256 and prefix the response with `{sha256}`;
if no prefix, use HMAC-MD5 (legacy). Verified via golden traces 2026-04-04.

**Authkey derivation** (when no explicit `rpc_key`):
```python
authkey = RNS.Identity.full_hash(RNS.Transport.identity.get_private_key())
```
This is `SHA-256(transport_identity_private_key)` — a 32-byte key.

When `rpc_key` is explicitly set in config, it is used as-is (hex-decoded).

### RPC Message Format

Messages are pickle-serialized Python dicts, framed with a 4-byte big-endian length prefix.

### In-Scope RPC Commands

Frozen from `Reticulum.py` `rpc_loop()`:

**GET operations:**
- `{"get": "interface_stats"}`
- `{"get": "path_table", "max_hops": int}`
- `{"get": "rate_table"}`
- `{"get": "next_hop_if_name", "destination_hash": bytes}`
- `{"get": "next_hop", "destination_hash": bytes}`
- `{"get": "first_hop_timeout", "destination_hash": bytes}`
- `{"get": "link_count"}`
- `{"get": "packet_rssi", "packet_hash": bytes}`
- `{"get": "packet_snr", "packet_hash": bytes}`
- `{"get": "packet_q", "packet_hash": bytes}`
- `{"get": "blackholed_identities"}`

**DROP operations:**
- `{"drop": "path", "destination_hash": bytes}`
- `{"drop": "all_via", "destination_hash": bytes}`
- `{"drop": "announce_queues"}`

**BLACKHOLE operations:**
- `{"blackhole_identity": bytes, "until": float, "reason": str}`
- `{"unblackhole_identity": bytes}`

## Pickle Opcodes Observed in Golden Traces

Captured 2026-04-04 from RNS 1.1.4. These are the exact opcodes the Rust
pickle decoder must handle.

### Request Pickle (Protocol 2)

RPC requests use pickle protocol 2 (`\x80\x02` header).

| Opcode | Byte | Description |
|--------|------|-------------|
| `PROTO` | `\x80` | Protocol version marker (arg: 2) |
| `EMPTY_DICT` | `}` | Push empty dict |
| `BINPUT` | `q` | Store top of stack in memo by 1-byte index |
| `BINUNICODE` | `X` | Push unicode string (4-byte little-endian length + UTF-8) |
| `SETITEM` | `s` | Pop value, pop key, add to dict on stack |
| `STOP` | `.` | End of pickle stream |

**Example:** `{"get": "interface_stats"}` encodes as 39 bytes:
```
80 02 7d 71 00 58 03000000 676574 71 01 58 0f000000 696e746572666163655f7374617473 71 02 73 2e
```

### Response Pickle (Protocol 4)

RPC responses use pickle protocol 4 (`\x80\x04\x95` header with frame length).

| Opcode | Byte | Description |
|--------|------|-------------|
| `PROTO` | `\x80` | Protocol version marker (arg: 4) |
| `FRAME` | `\x95` | Frame length (8-byte little-endian) |
| `EMPTY_DICT` | `}` | Push empty dict |
| `MEMOIZE` | `\x94` | Store top of stack in next memo slot |
| `MARK` | `(` | Push mark onto stack |
| `SHORT_BINUNICODE` | `\x8c` | Push short unicode (1-byte length + UTF-8) |
| `EMPTY_LIST` | `]` | Push empty list |
| `BININT1` | `K` | Push 1-byte unsigned int |
| `BININT` | `J` | Push 4-byte signed int (little-endian) |
| `BINFLOAT` | `G` | Push 8-byte IEEE 754 float (big-endian) |
| `NONE` | `N` | Push None |
| `NEWTRUE` | `\x88` | Push True |
| `SHORT_BINBYTES` | `C` | Push short bytes (1-byte length + raw) |
| `SETITEMS` | `u` | Pop mark..top as key/value pairs into dict |
| `APPEND` | `a` | Append top of stack to list below it |
| `BINGET` | `h` | Push item from memo by 1-byte index |
| `STOP` | `.` | End of pickle stream |

### Minimum Rust Decoder Scope

The Rust pickle decoder must handle these 19 unique opcodes:

**Protocol 2 (requests):** `PROTO`, `EMPTY_DICT`, `BINPUT`, `BINUNICODE`, `SETITEM`, `STOP`

**Protocol 4 (responses, adds):** `FRAME`, `MEMOIZE`, `MARK`, `SHORT_BINUNICODE`,
`EMPTY_LIST`, `BININT1`, `BININT`, `BINFLOAT`, `NONE`, `NEWTRUE`, `SHORT_BINBYTES`,
`SETITEMS`, `APPEND`, `BINGET`

**Not yet observed but likely in other RPC responses:** `NEWFALSE` (`\x89`),
`TUPLE` (`t`), `EMPTY_TUPLE` (`)`)

## multiprocessing.connection Wire Format (from Golden Traces)

Captured 2026-04-04 from RNS 1.1.4. Byte-level specification for the Rust
implementation.

### Message Framing

Every message on the control socket uses:
```
[4-byte big-endian unsigned length] [payload bytes]
```

### Auth Handshake

The server initiates authentication. Observed as a 3-message exchange
(server authenticates client):

**Message 1 — CHALLENGE (server -> client):**
```
Length: 59 bytes (0x0000003B)
Payload: #CHALLENGE#{sha256}<40-random-bytes>
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
         11 bytes tag + 8 bytes algo + 40 bytes nonce
```

**Message 2 — DIGEST (client -> server):**
```
Length: 40 bytes (0x00000028)
Payload: {sha256}<32-byte-HMAC-SHA256-digest>
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
         8 bytes algo prefix + 32 bytes digest
```
Digest = `HMAC-SHA256(authkey, challenge_payload)` where `challenge_payload`
is the full payload from Message 1 (59 bytes).

**Message 3 — WELCOME (server -> client):**
```
Length: 9 bytes (0x00000009)
Payload: #WELCOME#
```

If auth fails, server sends `#FAILURE#` instead.

**Note:** CPython's `multiprocessing.connection` supports mutual auth (client
also challenges server), making it a 6-message exchange. The golden traces
captured a 3-message exchange (one-way). The Rust implementation should handle
both: always respond to incoming challenges, and optionally initiate a
challenge as client.

### Post-Auth RPC Messages

After auth completes, the same 4-byte-length framing is used:

**Request (client -> server):**
```
[4-byte length] [pickle protocol 2 payload]
```

**Response (server -> client):**
```
[4-byte length] [pickle protocol 4 payload]
```

### Observed Byte Sizes

| Message | Unix | TCP |
|---------|------|-----|
| Auth CHALLENGE | 63 (4+59) | 63 (4+59) |
| Auth DIGEST | 44 (4+40) | 44 (4+40) |
| Auth WELCOME | 13 (4+9) | 13 (4+9) |
| RPC request (`interface_stats`) | 43 (4+39) | 43 (4+39) |
| RPC response (`interface_stats`) | 456 (4+452) | 450 (4+446) |

Response size differs between Unix and TCP because the interface name differs
(`Shared Instance[rns/default]` vs `Shared Instance[47428]`).
