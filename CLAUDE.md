# rete — Claude Code Project Prompt

Reticulum Network Stack (RNS) implementation in Rust — `no_std`, runtime-agnostic,
validated against the Python reference.

## Git workflow

Do NOT commit or push unless explicitly asked by the user.

## Verification — REQUIRED before finishing any coding task

After making changes, you MUST run the full test suite before reporting completion:

```bash
# Unit tests
cargo test --workspace

# E2E interop tests (from tests/interop/)
cd tests/interop && for test in live_interop link_interop channel_interop resource_interop relay_interop transport_relay_interop path_request_interop proof_routing_interop ifac_interop robustness_interop; do
  uv run python ${test}.py --rust-binary ../../target/debug/rete-linux --timeout 45
done
```

If any E2E test fails, investigate and fix before declaring the task done.
Timing-sensitive tests may need `--timeout 60`. A test that passes with
longer timeout but fails with shorter is acceptable — note it but don't
block on it.

---

## Reference material

### Python reference (the authoritative protocol spec)
- **Repository:** https://github.com/markqvist/Reticulum
- **Key files to read first:**
  - `RNS/Packet.py` — wire format, packet types, flags byte layout
  - `RNS/Identity.py` — keypairs, ECDH, encryption, signing, destination hashing
  - `RNS/Transport.py` — path tables, announce handling, routing (~2500 lines, read carefully)
  - `RNS/Destination.py` — address model, destination hash computation
- The Python code IS the protocol spec. Any behavior difference from it is a bug.

### This project
- **Project name:** `rete` (Latin: net/mesh)
- **Crates.io names reserved:** `rete`, `rete-core`, `rete-transport`, `rete-stack`,
  `rete-embassy`, `rete-tokio`, `rete-iface-kiss`, `rete-iface-serial`, `rete-iface-tcp`
- **Related project (different scope):** https://github.com/BeechatNetworkSystemsLtd/Reticulum-rs
  — Tokio-based, not no_std. `rete` is distinct: no_std, runtime-agnostic, Embassy-native.

### Test vectors
- `tests/interop/vectors.json` — 72 vectors generated from Python RNS 1.1.4
- `generate_test_vectors.py` — regenerate with `python3 generate_test_vectors.py --out tests/interop/vectors.json`
- All crypto, packet parsing, and hash computations must match these vectors exactly.

---

## Architecture

```
rete/
├── crates/
│   ├── rete-core/          no_std, no alloc, no async — packet wire format + crypto
│   ├── rete-transport/     no_std + alloc, no async  — routing, path tables, announces
│   ├── rete-stack/         async traits only, no executor dependency
│   ├── rete-embassy/       Embassy executor integration
│   ├── rete-tokio/         Tokio integration (hosted/gateway nodes)
│   ├── rete-iface-kiss/    KISS TNC serial interface
│   ├── rete-iface-serial/  Raw serial interface
│   └── rete-iface-tcp/     TCP interface
└── examples/
    ├── linux/              Hosted — Tokio or embassy-std
    ├── esp32s3/            ESP32-S3 bare metal
    └── rp2040/             Raspberry Pi Pico 2W bare metal
```

## Runtime agnosticism — critical design principle

`rete-core` and `rete-transport` must have **zero async dependencies**.
They are pure state machines driven by the caller.

`rete-stack` defines the async `ReteInterface` trait — no executor import.

`rete-embassy` and `rete-tokio` are the only crates that import executor machinery.
This means the same `rete-core` and `rete-transport` binaries run under Embassy,
Tokio, or any future runtime without recompilation.

---

## Protocol wire format quick reference

### Flags byte (raw[0])
```
Bits 7:6  header_type     0=HEADER_1  1=HEADER_2
Bit  5    context_flag    0=unset     1=set
Bit  4    transport_type  0=BROADCAST 1=TRANSPORT
Bits 3:2  dest_type       0=SINGLE  1=GROUP  2=PLAIN  3=LINK
Bits 1:0  packet_type     0=DATA  1=ANNOUNCE  2=LINKREQUEST  3=PROOF

flags = (header_type<<6)|(context_flag<<5)|(transport_type<<4)|(dest_type<<2)|packet_type
```

### HEADER_1 layout
```
raw[0]    flags
raw[1]    hops (0 when sent, incremented by repeaters)
raw[2:18] destination_hash (16 bytes)
raw[18]   context byte (0x00 = normal)
raw[19:]  payload (plaintext for PLAIN; ciphertext for SINGLE)
```

### HEADER_2 layout
```
raw[0]    flags
raw[1]    hops
raw[2:18] transport_id (16 bytes — identity hash of relay)
raw[18:34] destination_hash
raw[34]   context byte
raw[35:]  payload
```

### Packet hash
```
hashable = (raw[0] & 0x0F) || raw[2:]         HEADER_1
hashable = (raw[0] & 0x0F) || raw[18:]        HEADER_2
hash     = SHA-256(hashable)                   FULL 32 bytes, NOT truncated
```
Invariant to hop count and transport type changes.

### Key sizes
```
Identity pub_key:  64 bytes = X25519_pub[32] || Ed25519_pub[32]
Identity prv_key:  64 bytes = X25519_prv[32] || Ed25519_prv[32]
Identity hash:     16 bytes = SHA-256(pub_key)[0:16]
Dest hash:         16 bytes = SHA-256(name_hash || identity_hash)[0:16]
Name hash:         10 bytes = SHA-256(expanded_name.encode())[0:10]
Packet hash:       32 bytes = SHA-256(hashable_part)  (full, not truncated)
Ed25519 signature: 64 bytes
```

### Destination hash computation
```
expanded      = dot-join(app_name, aspect1, aspect2, ...)  e.g. "testapp.aspect1"
name_hash     = SHA-256(expanded.encode('utf-8'))[0:10]
addr_material = name_hash [+ identity_hash if not PLAIN]
dest_hash     = SHA-256(addr_material)[0:16]
```

### Announce payload layout (NOT encrypted)
```
[0:64]   pub_key     X25519_pub[32] || Ed25519_pub[32]
[64:74]  name_hash   SHA-256(expanded_name)[0:10]
[74:84]  random_hash 5_rand_bytes || 5_timestamp_bytes
[84:148] signature   Ed25519(dest_hash || pub_key || name_hash || random_hash [|| app_data])
[148:]   app_data    optional
```

### Encryption (SINGLE destination)
```
Ciphertext = ephemeral_X25519_pub[32] || AES_IV[16] || aes_cbc_body

Encrypt:
  shared = X25519(ephemeral_prv, recipient_X25519_pub)
  key    = HKDF-SHA256(ikm=shared, length=32)
  ct     = AES-128-CBC(key=key[0:16], iv=random[16], plaintext, padding=PKCS7)

Decrypt:
  shared = X25519(recipient_X25519_prv, ciphertext[0:32])
  key    = HKDF-SHA256(ikm=shared, length=32)
  pt     = AES-128-CBC-decrypt(key=key[0:16], iv=ciphertext[32:48], ciphertext[48:])
```

---

## Crypto crates

All are `no_std` compatible. Use these exact crates:

```toml
x25519-dalek  = { version = "2", default-features = false, features = ["zeroize"] }
ed25519-dalek = { version = "2", default-features = false, features = ["zeroize"] }
aes           = { version = "0.8", default-features = false }
cbc           = { version = "0.1", default-features = false }
sha2          = { version = "0.10", default-features = false }
hkdf          = { version = "0.12", default-features = false }
```

---

## Implementation order

Start here — do not skip ahead:

1. **Clone the Python reference**
   ```bash
   git clone https://github.com/markqvist/Reticulum /tmp/Reticulum
   ```
   Read `RNS/Packet.py` and `RNS/Identity.py` in full before writing Rust.

2. **Complete `rete-core/src/identity.rs`**
   - Fill in `Identity::from_private_key` — derive X25519 and Ed25519 public keys
   - Fill in `Identity::sign` and `Identity::verify`
   - Fill in `Identity::encrypt` and `Identity::decrypt`
   - Validate every function against `tests/interop/vectors.json`

3. **Validate `rete-core` against test vectors**
   Write a test that loads `tests/interop/vectors.json` and runs every section.
   All assertions must pass before moving to transport.

4. **Implement `rete-transport`**
   The struct skeletons exist. Focus on:
   - `Transport::ingest(packet)` — processes an inbound parsed packet
   - Announce re-transmission backoff (study `RNS/Transport.py` carefully)
   - Path expiry logic

5. **Implement `rete-stack` + `rete-embassy`**
   - `rete-stack`: refine the `ReteInterface` trait
   - `rete-embassy`: Embassy tasks for rx/tx/announce/expiry

6. **Linux example** — interop test against `rnsd`
   ```bash
   pip install rns
   rnsd &   # run Python reference node
   cargo run -p rete-example-linux -- --tcp 127.0.0.1:4242
   ```

7. **Hardware examples** — ESP32-S3 and RP2040

---

## Tricky things — read this before implementing

- **Transport.py is ~2500 lines** of stateful Python. The announce
  re-transmission backoff and path expiry rules are subtle. Read it twice.

- **Packet hash masks upper nibble of flags**, not just hops.
  `hashable = (raw[0] & 0x0F) || raw[2:]` — easy to get wrong.

- **Truncated hashes are 16 bytes everywhere** (identity, destination, transport_id)
  EXCEPT packet_hash which is full 32-byte SHA-256. Do not truncate it.

- **Announce signature covers specific fields in a specific order:**
  `dest_hash || pub_key || name_hash || random_hash [|| app_data]`
  app_data is included in the signed blob but appended AFTER the signature
  in the payload.

- **X25519 in Python RNS uses the `cryptography` library** which follows
  RFC 7748. `x25519-dalek` also follows RFC 7748 — they are compatible.

- **RNG on embedded** — `ed25519-dalek` and `x25519-dalek` need a `CryptoRng`.
  Abstract this behind a trait so `rete-core` stays runtime-agnostic:
  ```rust
  pub fn encrypt<R: RngCore + CryptoRng>(&self, plaintext: &[u8], rng: &mut R, out: &mut [u8])
  ```

- **ESP32-S3 RNG**: use `esp-hal`'s `Rng` peripheral.
  **RP2040 RNG**: use `embassy-rp`'s `RoscRng` or feed from ROSC.

---

## What is explicitly out of scope (Phase 2+)

Do NOT implement these yet — get core protocol working first:

- Links (`RNS/Link.py`) — connection-oriented sessions
- Channels / Buffer (`RNS/Channel.py`, `RNS/Buffer.py`) — reliable streams over links
- LXMF — the message protocol built on top of RNS
- AutoInterface — mDNS-based peer discovery
- I2P interface
- Shared instance IPC (Unix socket between local programs)
- Interface Access Codes (private network segments)

---

## Connection to TNC workspace

This project is designed to eventually integrate with a dual-mode
LoRa/packet-radio TNC workspace that already has:
- `crates/ax25/` — AX.25 frame codec (`no_std`)
- `crates/kiss/` — KISS framing (`no_std`)
- `crates/modem/` — Bell 202 AFSK modem (`no_std`)

`rete-iface-kiss` should reuse the `kiss` crate from that workspace.
Long-term vision: single Embassy firmware image that operates as both
a MeshCore-compatible KISS TNC and a Reticulum transport node.
