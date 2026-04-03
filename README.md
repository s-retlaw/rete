# rete

A `no_std`, runtime-agnostic implementation of the
[Reticulum Network Stack (RNS)](https://github.com/markqvist/Reticulum) in Rust.

> ⚠️ **Early development.** Wire format is being validated against the Python
> reference implementation. Not yet suitable for production use.

## What is Reticulum?

Reticulum is a cryptography-based networking stack for building resilient,
decentralised mesh networks over LoRa, packet radio, WiFi, serial, and more.
It provides end-to-end encryption, initiator anonymity, and self-configuring
multi-hop routing with no central authority or infrastructure required.

The [Python reference implementation](https://github.com/markqvist/Reticulum)
is the authoritative protocol specification. `rete` provides a compatible
implementation that runs natively on embedded targets.

## Why rete?

The Python reference runs well on Linux/Raspberry Pi but cannot run on
bare-metal microcontrollers. `rete` targets:

- **ESP32-S3** and **Raspberry Pi Pico 2W** via Embassy
- **Linux/macOS** for development and gateway nodes — same codebase
- **Any async runtime** — Embassy, Tokio, or your own (see below)
- Full wire-format interoperability with the Python RNS reference

*rete* (noun) — Latin for *net* or *mesh*. The word Reticulum shares the
same root.

## Runtime agnosticism

The core crates have zero async dependencies:

```
rete-core        → no_std, no alloc, no async — pure packet + crypto
rete-transport   → no_std + alloc, no async  — routing state machine
rete-stack       → async traits only, no executor
rete-embassy     → Embassy executor integration
rete-tokio       → Tokio integration (hosted/server nodes)
```

You choose the runtime. The protocol logic is the same either way.

## Crate structure

```
rete/
├── crates/
│   ├── rete-core/          no_std, no alloc — packet parsing & crypto
│   ├── rete-transport/     no_std + alloc   — routing, path tables, announces
│   ├── rete-stack/         async traits     — runtime-agnostic interface
│   ├── rete-embassy/       Embassy integration
│   ├── rete-tokio/         Tokio integration
│   ├── rete-iface-kiss/    KISS TNC serial interface
│   ├── rete-iface-serial/  Raw serial interface
│   └── rete-iface-tcp/     TCP interface
└── examples/
    ├── linux/              Hosted — embassy-std or tokio executor
    ├── esp32s3/            ESP32-S3 bare metal
    └── rp2040/             Raspberry Pi Pico 2W bare metal
```

## Protocol compatibility

> The Python code in the Reticulum repository is the Reference Implementation.
> Compatibility with the Reticulum Protocol is defined as having full
> interoperability and sufficient functional parity with this reference.

Wire format test vectors are generated directly from the Python reference using
`generate_test_vectors.py` and committed at `tests/interop/vectors.json`.
All packet parsing, crypto operations, and hash computations are validated
against these vectors before any code ships.

## Key protocol facts

| Property | Value |
|---|---|
| MTU | 500 bytes |
| Truncated hash length | 16 bytes |
| Name hash length | 10 bytes |
| Identity key | X25519 + Ed25519 (64 bytes each, combined) |
| Encryption | ECDH → HKDF → AES-256-CBC + HMAC-SHA256 |
| Signing | Ed25519 |

## Implementation status

| Crate | Status | Notes |
|---|---|---|
| `rete-core` | ✅ Complete | Wire format, crypto, identity |
| `rete-transport` | ✅ Complete | Path tables, announce handling, resources, links, channels |
| `rete-stack` | ✅ Complete | Async trait definitions, NodeCore |
| `rete-embassy` | ✅ Complete | Embassy task layer |
| `rete-tokio` | ✅ Complete | Tokio task layer |
| `rete-iface-kiss` | ✅ Complete | KISS TNC framing |
| `rete-iface-tcp` | ✅ Complete | TCP transport |
| `rete-lxmf-core` | ✅ Complete | LXMF message codec (`no_std + alloc`) |
| `rete-lxmf` | ✅ Complete | LXMF router, delivery, propagation (hosted) |
| Links / Channels | ✅ Complete | Connection-oriented sessions, reliable streams |

## Getting started

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Embedded targets
rustup target add thumbv6m-none-eabi        # RP2040
# ESP32-S3 via esp-rs toolchain: https://esp-rs.github.io/book/

# Python reference (for test vector generation + interop testing)
pip install rns

# Build and test (hosted crates)
cargo build
cargo test

# Regenerate test vectors (run after any Python RNS update)
python3 generate_test_vectors.py --out tests/interop/vectors.json
```

## Relationship to other projects

- **[markqvist/Reticulum](https://github.com/markqvist/Reticulum)** — the
  authoritative Python reference implementation. `rete` is wire-compatible
  with it.
- **[BeechatNetworkSystemsLtd/Reticulum-rs](https://github.com/BeechatNetworkSystemsLtd/Reticulum-rs)** —
  another Rust port, Tokio-based, targets different use cases.
  `rete` focuses on `no_std` embedded targets and runtime agnosticism.

## Contributing

1. Run `cargo test` — all tests must pass
2. Regenerate vectors if any protocol behavior changes:
   `python3 generate_test_vectors.py --out tests/interop/vectors.json`
3. Open an issue before PRs that affect wire format or crypto

## License

MIT OR Apache-2.0 at your option.

The Reticulum Protocol was dedicated to the Public Domain in 2016 by
[Mark Qvist](https://github.com/markqvist).
