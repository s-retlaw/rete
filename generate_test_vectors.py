#!/usr/bin/env python3
"""
Reticulum Test Vector Generator for rns-rs
===========================================

Generates deterministic test vectors from the Python Reticulum reference
implementation (https://github.com/markqvist/Reticulum) for use as ground
truth in Rust unit tests.

Usage:
    pip install rns
    python3 generate_test_vectors.py --out tests/interop/vectors.json

Each vector includes:
  - All inputs (hex-encoded bytes, strings, integers)
  - All intermediate values (hashes, derived keys, etc.)
  - The final expected output
  - A human-readable description and layout notes

Rust usage example:
    let v: TestVectors = serde_json::from_str(
        include_str!("../tests/interop/vectors.json")
    ).unwrap();

Wire format quick reference
---------------------------
HEADER_1 (no transport hop):
  [0]      flags byte:  (header_type<<6)|(context_flag<<5)|(transport_type<<4)|(dest_type<<2)|packet_type
  [1]      hops         (0 when freshly sent)
  [2:18]   destination_hash  (16 bytes = TRUNCATED_HASHLENGTH/8)
  [18]     context byte (0x00 = normal data)
  [19:]    payload      (plaintext for PLAIN dest; ciphertext for SINGLE)

HEADER_2 (with transport hop):
  [0]      flags byte   (header_type bit set to 1)
  [1]      hops
  [2:18]   transport_id (16 bytes — identity hash of relaying node)
  [18:34]  destination_hash
  [34]     context byte
  [35:]    payload

Key sizes:
  X25519 pub/prv:   32 bytes each
  Ed25519 pub/prv:  32 bytes each
  Identity pub_key: 64 bytes = X25519_pub[32] || Ed25519_pub[32]
  Identity prv_key: 64 bytes = X25519_prv[32] || Ed25519_prv[32]
  Identity hash:    16 bytes = SHA-256(pub_key)[0:16]
  Dest hash:        16 bytes = SHA-256(name_hash || identity_hash)[0:16]
  Name hash:        10 bytes = SHA-256("app.aspect1.aspect2".encode())[0:10]
  Packet hash:      32 bytes = SHA-256((flags & 0x0F) || raw[2:])
                               NOTE: full 32 bytes, NOT truncated
"""

import sys
import os
import json
import hashlib
import tempfile
import argparse
import time

import RNS

# ---------------------------------------------------------------------------
# Bootstrap — throwaway config dir, no network interfaces
# ---------------------------------------------------------------------------
_tmpdir = tempfile.mkdtemp(prefix="rns_testvec_")
_r = RNS.Reticulum(configdir=_tmpdir, loglevel=RNS.LOG_CRITICAL)

# Destination registry — tracks created destinations to avoid duplicate
# registration errors (RNS raises if you create the same dest twice).
_dest_registry: dict = {}


def get_dest(identity, direction, dest_type, app_name, *aspects, label=""):
    """
    Get-or-create a Destination, avoiding duplicate registration errors.
    'label' is an optional disambiguator for same app+aspect combos.
    """
    id_hash = identity.hash.hex() if identity else "none"
    key = (id_hash, direction, dest_type, app_name, aspects, label)
    if key not in _dest_registry:
        _dest_registry[key] = RNS.Destination(
            identity, direction, dest_type, app_name, *aspects
        )
    return _dest_registry[key]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def h(b: bytes) -> str:
    """Bytes to lowercase hex string."""
    return b.hex()


def fixed_identity(seed_label: str) -> RNS.Identity:
    """
    Create a deterministic Identity from a label string.

    Derives a 64-byte private key from SHA-512(label), giving reproducible
    test vectors that are stable across runs and Python/Rust.
    """
    seed = hashlib.sha512(seed_label.encode()).digest()  # 64 bytes
    id_ = RNS.Identity(create_keys=False)
    id_.load_private_key(seed)
    return id_


def packet_hashable_part(raw: bytes, header_type: int) -> bytes:
    """
    Compute hashable_part exactly as Python RNS does.

    From Packet.get_hashable_part():
      HEADER_1: (raw[0] & 0x0F) || raw[2:]
      HEADER_2: (raw[0] & 0x0F) || raw[DST_LEN+2:]   (skips transport_id)

    Masks upper nibble of flags (strips header_type/context_flag/transport_type)
    and skips hops byte (raw[1]) — making the hash hop-count-invariant.
    """
    DST_LEN = RNS.Reticulum.TRUNCATED_HASHLENGTH // 8  # 16
    if header_type == RNS.Packet.HEADER_2:
        return bytes([raw[0] & 0x0F]) + raw[DST_LEN + 2:]
    else:
        return bytes([raw[0] & 0x0F]) + raw[2:]


# Cache fixed identities to avoid re-creating them
_identity_cache: dict = {}


def get_identity(label: str) -> RNS.Identity:
    if label not in _identity_cache:
        _identity_cache[label] = fixed_identity(label)
    return _identity_cache[label]


# ---------------------------------------------------------------------------
# Section: constants
# ---------------------------------------------------------------------------

def gen_constants() -> dict:
    """Protocol constants that Rust must match exactly."""
    return {
        "_description": "Fundamental protocol constants from the Python reference",
        "MTU":                           500,
        "PLAIN_MDU":                     RNS.Packet.PLAIN_MDU,
        "ENCRYPTED_MDU":                 RNS.Packet.ENCRYPTED_MDU,
        "TRUNCATED_HASHLENGTH_bits":     RNS.Reticulum.TRUNCATED_HASHLENGTH,
        "TRUNCATED_HASHLENGTH_bytes":    RNS.Reticulum.TRUNCATED_HASHLENGTH // 8,
        "NAME_HASH_LENGTH_bits":         RNS.Identity.NAME_HASH_LENGTH,
        "NAME_HASH_LENGTH_bytes":        RNS.Identity.NAME_HASH_LENGTH // 8,
        "packet_type_DATA":              RNS.Packet.DATA,
        "packet_type_ANNOUNCE":          RNS.Packet.ANNOUNCE,
        "packet_type_LINKREQUEST":       RNS.Packet.LINKREQUEST,
        "packet_type_PROOF":             RNS.Packet.PROOF,
        "dest_type_SINGLE":              RNS.Destination.SINGLE,
        "dest_type_GROUP":               RNS.Destination.GROUP,
        "dest_type_PLAIN":               RNS.Destination.PLAIN,
        "dest_type_LINK":                RNS.Destination.LINK,
        "header_type_1":                 RNS.Packet.HEADER_1,
        "header_type_2":                 RNS.Packet.HEADER_2,
        "identity_pub_key_bytes":        64,
        "identity_prv_key_bytes":        64,
        "x25519_key_bytes":              32,
        "ed25519_key_bytes":             32,
        "ed25519_signature_bytes":       64,
    }


# ---------------------------------------------------------------------------
# Section: identity vectors
# ---------------------------------------------------------------------------

def gen_identity_vectors() -> list:
    """
    Identity creation and hash computation.

    Key layout (both pub and prv are 64 bytes):
      pub_key = X25519_pub[0:32]  || Ed25519_pub[32:64]
      prv_key = X25519_prv[0:32]  || Ed25519_prv[32:64]

    Identity hash = SHA-256(pub_key)[0:16]
    """
    vectors = []
    for label in ["alice", "bob", "carol", "relay_node_1", "van_bot"]:
        id_ = get_identity(label)
        pub = id_.get_public_key()
        prv = id_.get_private_key()

        expected_hash = hashlib.sha256(pub).digest()[:16]
        assert expected_hash == id_.hash

        vectors.append({
            "_description":      f"Identity '{label}' — derived from SHA-512(label)",
            "seed_label":        label,
            "private_key_hex":   h(prv),
            "public_key_hex":    h(pub),
            "x25519_prv_hex":    h(prv[0:32]),
            "x25519_pub_hex":    h(pub[0:32]),
            "ed25519_prv_hex":   h(prv[32:64]),
            "ed25519_pub_hex":   h(pub[32:64]),
            "identity_hash_hex": h(id_.hash),
            "_note": "identity_hash = SHA-256(pub_key)[0:16]  (truncated to 16 bytes)",
        })
    return vectors


# ---------------------------------------------------------------------------
# Section: destination hash vectors
# ---------------------------------------------------------------------------

def gen_destination_hash_vectors() -> list:
    """
    Destination address hash computation.

    Step 1: expanded   = dot-join(app_name, *aspects)   e.g. "testapp.aspect1"
    Step 2: name_hash  = SHA-256(expanded.encode('utf-8'))[0:10]
    Step 3: if identity:  addr_material = name_hash || identity.hash
            else:         addr_material = name_hash
    Step 4: dest_hash  = SHA-256(addr_material)[0:16]
    """
    vectors = []
    id_alice = get_identity("alice")
    id_bob   = get_identity("bob")

    cases = [
        (id_alice, "alice", "testapp",   ["aspect1"]),
        (id_alice, "alice", "testapp",   ["aspect1", "aspect2"]),
        (id_alice, "alice", "chat",      ["message"]),
        (id_alice, "alice", "rns_rs",    ["bot", "commands"]),
        (id_bob,   "bob",   "testapp",   ["aspect1"]),
        (id_bob,   "bob",   "sensor",    ["temperature", "living_room"]),
        (None,     None,    "broadcast", []),
    ]

    for id_obj, id_label, app_name, aspects in cases:
        dest_hash = RNS.Destination.hash(id_obj, app_name, *aspects)
        expanded  = RNS.Destination.expand_name(None, app_name, *aspects)
        name_hash = hashlib.sha256(expanded.encode("utf-8")).digest()[:10]

        addr_material = name_hash + (id_obj.hash if id_obj else b"")
        expected      = hashlib.sha256(addr_material).digest()[:16]
        assert expected == dest_hash

        vectors.append({
            "_description":      (
                f"Destination hash: app='{app_name}' aspects={aspects} "
                f"identity='{id_label}'"
            ),
            "app_name":          app_name,
            "aspects":           aspects,
            "expanded_name":     expanded,
            "name_hash_hex":     h(name_hash),
            "identity_hash_hex": h(id_obj.hash) if id_obj else None,
            "addr_material_hex": h(addr_material),
            "dest_hash_hex":     h(dest_hash),
            "_steps": [
                "expanded      = dot-join(app_name, *aspects)",
                "name_hash     = SHA-256(expanded.encode('utf-8'))[0:10]",
                "addr_material = name_hash [+ identity_hash if not PLAIN]",
                "dest_hash     = SHA-256(addr_material)[0:16]",
            ],
        })
    return vectors


# ---------------------------------------------------------------------------
# Section: flags byte vectors
# ---------------------------------------------------------------------------

def gen_packet_flags_vectors() -> list:
    """
    Flags byte (raw[0]) encoding.

    Bit layout (MSB first):
      [7:6]  header_type    0=HEADER_1  1=HEADER_2
      [5]    context_flag   0=unset     1=set
      [4]    transport_type 0=BROADCAST 1=TRANSPORT
      [3:2]  dest_type      0=SINGLE  1=GROUP  2=PLAIN  3=LINK
      [1:0]  packet_type    0=DATA  1=ANNOUNCE  2=LINKREQUEST  3=PROOF

    flags = (header_type<<6) | (context_flag<<5) | (transport_type<<4)
            | (dest_type<<2) | packet_type
    """
    vectors = []
    cases = [
        (0, 0, 0, RNS.Destination.SINGLE, RNS.Packet.DATA),
        (0, 0, 0, RNS.Destination.PLAIN,  RNS.Packet.DATA),
        (0, 0, 0, RNS.Destination.GROUP,  RNS.Packet.DATA),
        (0, 0, 0, RNS.Destination.LINK,   RNS.Packet.DATA),
        (0, 0, 0, RNS.Destination.SINGLE, RNS.Packet.ANNOUNCE),
        (0, 0, 0, RNS.Destination.SINGLE, RNS.Packet.LINKREQUEST),
        (0, 0, 0, RNS.Destination.SINGLE, RNS.Packet.PROOF),
        (0, 0, 0, RNS.Destination.LINK,   RNS.Packet.PROOF),
        (1, 0, 0, RNS.Destination.SINGLE, RNS.Packet.DATA),
        (0, 1, 0, RNS.Destination.SINGLE, RNS.Packet.DATA),
        (0, 0, 1, RNS.Destination.SINGLE, RNS.Packet.DATA),
        (1, 0, 1, RNS.Destination.SINGLE, RNS.Packet.ANNOUNCE),
    ]
    for ht, cf, tt, dt, pt in cases:
        flags = (ht << 6) | (cf << 5) | (tt << 4) | (dt << 2) | pt
        vectors.append({
            "_description": (
                f"flags=0x{flags:02x}: header_type={ht} context_flag={cf} "
                f"transport_type={tt} dest_type={dt} packet_type={pt}"
            ),
            "header_type":    ht,
            "context_flag":   cf,
            "transport_type": tt,
            "dest_type":      dt,
            "packet_type":    pt,
            "flags_byte":     flags,
            "flags_hex":      f"0x{flags:02x}",
        })
    return vectors


# ---------------------------------------------------------------------------
# Section: data packet vectors
# ---------------------------------------------------------------------------

def gen_data_packet_vectors() -> list:
    """
    DATA packet wire format for PLAIN and SINGLE (encrypted) destinations.
    """
    vectors = []
    id_alice = get_identity("alice")

    # PLAIN packets
    d_plain = get_dest(
        None, RNS.Destination.OUT, RNS.Destination.PLAIN,
        "broadcast", "channel"
    )
    for payload in [b"hello world", b"", b"A" * 80, b"\x00\x01\x02\x03\xff"]:
        pkt = RNS.Packet(d_plain, payload)
        pkt.pack()
        raw = pkt.raw

        assert raw[1]    == 0
        assert raw[2:18] == d_plain.hash
        assert raw[18]   == 0x00
        assert raw[19:]  == payload

        hp = packet_hashable_part(raw, RNS.Packet.HEADER_1)
        assert hashlib.sha256(hp).digest() == pkt.packet_hash

        vectors.append({
            "_description":      f"PLAIN DATA packet — payload={payload!r}",
            "dest_type":         "PLAIN",
            "dest_hash_hex":     h(d_plain.hash),
            "plaintext_hex":     h(payload),
            "plaintext_len":     len(payload),
            "raw_hex":           h(raw),
            "raw_len":           len(raw),
            "flags_byte":        raw[0],
            "hops":              raw[1],
            "context_byte":      raw[18],
            "packet_hash_hex":   h(pkt.packet_hash),
            "hashable_part_hex": h(hp),
            "_layout": "flags[1] || hops[1] || dest_hash[16] || context[1] || payload",
        })

    # ENCRYPTED packets (SINGLE destination)
    d_out = get_dest(
        id_alice, RNS.Destination.OUT, RNS.Destination.SINGLE,
        "testapp", "data_test"
    )
    for payload in [b"secret message", b"van: temp=68 bat=87 heater=off"]:
        pkt = RNS.Packet(d_out, payload)
        pkt.pack()
        raw = pkt.raw

        decrypted = id_alice.decrypt(raw[19:])
        assert decrypted == payload

        hp = packet_hashable_part(raw, RNS.Packet.HEADER_1)
        assert hashlib.sha256(hp).digest() == pkt.packet_hash

        vectors.append({
            "_description":      f"ENCRYPTED DATA packet to alice — payload={payload!r}",
            "dest_type":         "SINGLE",
            "dest_hash_hex":     h(d_out.hash),
            "recipient_x25519_prv_hex": h(id_alice.get_private_key()[0:32]),
            "recipient_x25519_pub_hex": h(id_alice.get_public_key()[0:32]),
            "plaintext_hex":     h(payload),
            "plaintext_len":     len(payload),
            "raw_hex":           h(raw),
            "raw_len":           len(raw),
            "flags_byte":        raw[0],
            "ciphertext_hex":    h(raw[19:]),
            "packet_hash_hex":   h(pkt.packet_hash),
            "hashable_part_hex": h(hp),
            "_note": (
                "ciphertext = ephemeral_X25519_pub[32] || AES_IV[16] || aes_body. "
                "Decrypt with recipient X25519 prv via ECDH -> HKDF -> AES-128-CBC."
            ),
        })

    return vectors


# ---------------------------------------------------------------------------
# Section: announce packet vectors
# ---------------------------------------------------------------------------

def gen_announce_packet_vectors() -> list:
    """
    ANNOUNCE packet wire format.

    Announce payload (NOT encrypted):
      [0:64]   identity.get_public_key()     X25519_pub[32] || Ed25519_pub[32]
      [64:74]  name_hash                     SHA-256(expanded_name.encode())[0:10]
      [74:84]  random_hash                   5_rand_bytes || 5_timestamp_bytes
      [84:148] Ed25519 signature of:
                 dest_hash || pub_key || name_hash || random_hash [|| app_data]
      [148:]   app_data (optional)

    Full wire (HEADER_1):
      raw[0]    = 0x01   flags: ANNOUNCE, SINGLE, HEADER_1
      raw[1]    = 0x00   hops
      raw[2:18] = destination_hash
      raw[18]   = 0x00   context
      raw[19:]  = announce payload
    """
    vectors = []
    fixed_ts = 1700000000

    for label in ["alice", "bob", "van_bot"]:
        id_  = get_identity(label)
        d_in = get_dest(
            id_, RNS.Destination.IN, RNS.Destination.SINGLE,
            "testapp", "aspect1", label=label
        )

        random_hash = bytes(5) + fixed_ts.to_bytes(5, "big")

        # Without app_data
        signed_data   = d_in.hash + id_.get_public_key() + d_in.name_hash + random_hash
        signature     = id_.sign(signed_data)
        announce_data = id_.get_public_key() + d_in.name_hash + random_hash + signature

        assert id_.validate(signature, signed_data)

        pkt = RNS.Packet(d_in, announce_data, RNS.Packet.ANNOUNCE)
        pkt.pack()
        raw = pkt.raw

        assert raw[0]    == 0x01
        assert raw[1]    == 0x00
        assert raw[2:18] == d_in.hash
        assert raw[18]   == 0x00
        assert raw[19:]  == announce_data

        hp = packet_hashable_part(raw, RNS.Packet.HEADER_1)
        assert hashlib.sha256(hp).digest() == pkt.packet_hash

        vectors.append({
            "_description":         f"ANNOUNCE for '{label}' — no app_data",
            "identity_label":       label,
            "private_key_hex":      h(id_.get_private_key()),
            "public_key_hex":       h(id_.get_public_key()),
            "identity_hash_hex":    h(id_.hash),
            "dest_hash_hex":        h(d_in.hash),
            "name_hash_hex":        h(d_in.name_hash),
            "random_hash_hex":      h(random_hash),
            "fixed_timestamp":      fixed_ts,
            "signed_data_hex":      h(signed_data),
            "signature_hex":        h(signature),
            "announce_payload_hex": h(announce_data),
            "announce_payload_len": len(announce_data),
            "raw_hex":              h(raw),
            "raw_len":              len(raw),
            "packet_hash_hex":      h(pkt.packet_hash),
            "hashable_part_hex":    h(hp),
            "_payload_layout": {
                "pub_key":   "payload[0:64]   X25519_pub[32] || Ed25519_pub[32]",
                "name_hash": "payload[64:74]  SHA-256(expanded_name)[0:10]",
                "rand_hash": "payload[74:84]  5_rand || 5_timestamp",
                "signature": "payload[84:148] Ed25519(dest_hash||pub_key||name_hash||rand_hash)",
            },
        })

        # With app_data
        app_data        = b"node:sensor:outdoor:v1"
        signed_data_app = (
            d_in.hash + id_.get_public_key() + d_in.name_hash + random_hash + app_data
        )
        sig_app         = id_.sign(signed_data_app)
        ann_data_app    = (
            id_.get_public_key() + d_in.name_hash + random_hash + sig_app + app_data
        )

        assert id_.validate(sig_app, signed_data_app)

        pkt_app = RNS.Packet(d_in, ann_data_app, RNS.Packet.ANNOUNCE)
        pkt_app.pack()

        vectors.append({
            "_description":         f"ANNOUNCE for '{label}' — WITH app_data",
            "identity_label":       label,
            "public_key_hex":       h(id_.get_public_key()),
            "dest_hash_hex":        h(d_in.hash),
            "name_hash_hex":        h(d_in.name_hash),
            "random_hash_hex":      h(random_hash),
            "app_data_hex":         h(app_data),
            "app_data_utf8":        app_data.decode(),
            "signed_data_hex":      h(signed_data_app),
            "signature_hex":        h(sig_app),
            "announce_payload_hex": h(ann_data_app),
            "raw_hex":              h(pkt_app.raw),
            "raw_len":              len(pkt_app.raw),
            "packet_hash_hex":      h(pkt_app.packet_hash),
            "_note": (
                "With app_data, signature covers: "
                "dest_hash||pub_key||name_hash||rand_hash||app_data. "
                "app_data is appended AFTER the signature in the payload."
            ),
        })

    return vectors


# ---------------------------------------------------------------------------
# Section: Ed25519 signing vectors
# ---------------------------------------------------------------------------

def gen_signing_vectors() -> list:
    """
    Ed25519 sign and verify.

    Tests crypto independently of packet handling.
    Includes valid signatures and tampered-message failure cases.
    """
    vectors = []
    for label in ["alice", "bob"]:
        id_     = get_identity(label)
        ed_prv  = h(id_.get_private_key()[32:64])
        ed_pub  = h(id_.get_public_key()[32:64])

        messages = [
            b"hello from reticulum",
            b"",
            b"\x00" * 32,
            hashlib.sha256(b"some data to sign").digest(),
            b"van telemetry packet",
        ]

        for msg in messages:
            sig = id_.sign(msg)
            assert id_.validate(sig, msg)

            vectors.append({
                "_description":    f"Ed25519 sign — identity='{label}' msg={msg!r}",
                "identity_label":  label,
                "ed25519_prv_hex": ed_prv,
                "ed25519_pub_hex": ed_pub,
                "message_hex":     h(msg),
                "message_len":     len(msg),
                "signature_hex":   h(sig),
                "signature_len":   len(sig),
                "verify_result":   True,
            })

            if len(msg) > 0:
                tampered = bytes([msg[0] ^ 0xFF]) + msg[1:]
                assert not id_.validate(sig, tampered)
                vectors.append({
                    "_description":         f"Ed25519 verify FAIL — tampered, identity='{label}'",
                    "identity_label":       label,
                    "ed25519_pub_hex":      ed_pub,
                    "original_message_hex": h(msg),
                    "tampered_message_hex": h(tampered),
                    "signature_hex":        h(sig),
                    "verify_result":        False,
                    "_note": "signature was created over original_message_hex",
                })

    return vectors


# ---------------------------------------------------------------------------
# Section: encryption vectors
# ---------------------------------------------------------------------------

def gen_encryption_vectors() -> list:
    """
    ECDH + AES-128-CBC encryption and decryption.

    Ciphertext layout:
      ephemeral_X25519_pub[32] || AES_IV[16] || aes_cbc_body

    Ciphertext is non-deterministic (ephemeral key), so these vectors
    provide Python-produced ciphertext that Rust must decrypt correctly.
    """
    vectors = []
    id_alice = get_identity("alice")
    d_out    = get_dest(
        id_alice, RNS.Destination.OUT, RNS.Destination.SINGLE,
        "testapp", "enc_test"
    )

    plaintexts = [
        b"hello",
        b"van: temp=68 bat=87 heater=off",
        b"\x00" * 32,
        bytes(range(64)),
        b"A" * (RNS.Packet.ENCRYPTED_MDU - 1),
    ]

    for pt in plaintexts:
        ct        = d_out.encrypt(pt)
        decrypted = id_alice.decrypt(ct)
        assert decrypted == pt

        vectors.append({
            "_description":    f"Encrypt/decrypt — plaintext_len={len(pt)}",
            "recipient_x25519_prv_hex": h(id_alice.get_private_key()[0:32]),
            "recipient_x25519_pub_hex": h(id_alice.get_public_key()[0:32]),
            "plaintext_hex":   h(pt),
            "plaintext_len":   len(pt),
            "ciphertext_hex":  h(ct),
            "ciphertext_len":  len(ct),
            "_layout":         "ciphertext = ephemeral_X25519_pub[32] || AES_IV[16] || aes_body",
            "_decrypt_steps": [
                "ephemeral_pub = ciphertext[0:32]",
                "iv            = ciphertext[32:48]",
                "body          = ciphertext[48:]",
                "shared_secret = X25519(recipient_prv, ephemeral_pub)",
                "key_material  = HKDF(shared_secret, length=32)",
                "plaintext     = AES-128-CBC-decrypt(key=key_material[0:16], iv=iv, data=body)",
            ],
        })

    return vectors


# ---------------------------------------------------------------------------
# Section: packet hash vectors
# ---------------------------------------------------------------------------

def gen_packet_hash_vectors() -> list:
    """
    Packet hash computation.

    packet_hash = SHA-256(hashable_part)    [FULL 32 bytes, NOT truncated]

    hashable_part for HEADER_1:
      = (raw[0] & 0x0F) || raw[2:]
        Strips upper nibble of flags (header_type/context_flag/transport_type)
        Skips hops byte at raw[1]

    Result is hop-count-invariant: the same packet has the same hash
    at every hop.
    """
    vectors = []
    d_plain = get_dest(
        None, RNS.Destination.OUT, RNS.Destination.PLAIN,
        "broadcast", "hash_test"
    )

    for payload in [b"test", b"hello world", b"A" * 50, b""]:
        pkt = RNS.Packet(d_plain, payload)
        pkt.pack()
        raw = pkt.raw

        hp       = packet_hashable_part(raw, RNS.Packet.HEADER_1)
        expected = hashlib.sha256(hp).digest()
        assert expected == pkt.packet_hash

        vectors.append({
            "_description":      f"Packet hash — payload={payload!r}",
            "raw_hex":           h(raw),
            "hashable_part_hex": h(hp),
            "packet_hash_hex":   h(pkt.packet_hash),
            "packet_hash_len":   len(pkt.packet_hash),
            "_formula": (
                "hashable_part = (raw[0] & 0x0F) || raw[2:]  [HEADER_1]. "
                "packet_hash = SHA-256(hashable_part)  [32 bytes, full, NOT truncated]"
            ),
        })

        # Same packet with hops incremented — hash must be identical
        raw_hopped      = bytearray(raw)
        raw_hopped[1]   = 5
        hp_hopped       = packet_hashable_part(bytes(raw_hopped), RNS.Packet.HEADER_1)
        hash_hopped     = hashlib.sha256(hp_hopped).digest()
        assert hash_hopped == pkt.packet_hash

        vectors.append({
            "_description":      f"Packet hash hop-invariance — payload={payload!r} hops=5",
            "raw_hex":           h(raw_hopped),
            "hashable_part_hex": h(hp_hopped),
            "packet_hash_hex":   h(hash_hopped),
            "_note": "Identical to hops=0 hash above — hops byte excluded from hashable_part",
        })

    return vectors


# ---------------------------------------------------------------------------
# Section: round-trip parse vectors
# ---------------------------------------------------------------------------

def gen_roundtrip_vectors() -> list:
    """
    Full pack -> fromPacked round-trips.

    Integration tests verifying that the Rust parser correctly recovers
    all fields from raw bytes produced by the Python reference.
    """
    vectors = []
    d_plain = get_dest(
        None, RNS.Destination.OUT, RNS.Destination.PLAIN,
        "broadcast", "roundtrip"
    )

    cases = [
        (d_plain, b"hello world",  "PLAIN DATA — short"),
        (d_plain, b"",             "PLAIN DATA — empty"),
        (d_plain, b"\xff\x00\xab", "PLAIN DATA — binary"),
        (d_plain, b"X" * 200,      "PLAIN DATA — longer"),
    ]

    for dest, payload, label in cases:
        pkt = RNS.Packet(dest, payload)
        pkt.pack()
        raw = pkt.raw

        pkt2 = RNS.Packet.__new__(RNS.Packet)
        pkt2.raw = raw
        ok = pkt2.unpack()
        assert ok
        assert pkt2.destination_hash == pkt.destination_hash
        assert pkt2.packet_type      == pkt.packet_type
        assert pkt2.header_type      == pkt.header_type
        assert pkt2.destination_type == pkt.destination.type
        assert pkt2.data             == payload
        assert pkt2.hops             == 0

        vectors.append({
            "_description":  f"Round-trip: {label}",
            "raw_hex":       h(raw),
            "raw_len":       len(raw),
            "flags_byte":    raw[0],
            "hops":          raw[1],
            "dest_hash_hex": h(pkt.destination_hash),
            "packet_type":   pkt.packet_type,
            "header_type":   pkt.header_type,
            "dest_type":     pkt.destination.type,
            "context_byte":  pkt.context,
            "payload_hex":   h(payload),
            "payload_len":   len(payload),
            "packet_hash_hex": h(pkt.packet_hash),
        })

    return vectors


# ---------------------------------------------------------------------------
# Section: resource advertisement vectors
# ---------------------------------------------------------------------------

def gen_resource_advertisement_vectors() -> list:
    """
    Resource advertisement format vectors.

    A Resource advertisement is a msgpack-encoded payload sent over a Link
    with context=CONTEXT_RESOURCE_ADV (0x02).

    The advertisement contains information about the resource being offered,
    including its hash, size, segment count, random hash, initial hashmap
    (part hashes), and flags.

    resource_hash = SHA-256(data || random_hash)   [full 32 bytes]

    Advertisement format (Python RNS uses a msgpack dict with keys):
      "t" = transfer_size (encrypted data size)
      "d" = data_size (original uncompressed size)
      "n" = num_parts (total parts count)
      "h" = resource_hash (32 bytes)
      "r" = random_hash (4 bytes)
      "o" = original_hash (hash of first segment)
      "i" = segment_index (1 for initial advertisement)
      "l" = total_segments (total advertisement segments)
      "q" = request_id (None if unsolicited)
      "f" = flags (bitfield: encryption, compression, etc.)
      "m" = hashmap (initial part hashes, 4 bytes each)

    The Rust implementation uses a simpler msgpack array:
      [resource_hash[32], total_size, segment_count, random_hash[4], hashmap_bytes, flags_byte]

    These vectors validate the resource_hash computation and basic layout.
    """
    vectors = []

    test_cases = [
        (b"hello resource", "short payload"),
        (b"test_resource_data_12345 " * 40, "~1KB payload"),
        (b"\x00" * 500, "500 null bytes"),
        (b"A" * 1000, "1000 x 0x41"),
        (b"", "empty payload"),
    ]

    for data, label in test_cases:
        # Use a fixed random_hash for reproducibility
        random_hash = hashlib.sha256(data + b"fixed_random_seed").digest()[:4]

        # resource_hash = SHA-256(data || random_hash) — matches Python RNS
        resource_hash = hashlib.sha256(data + random_hash).digest()

        # Compute part hashes (4-byte truncated SHA-256 of each segment)
        mdu = 431  # typical link MDU
        segments = []
        if len(data) == 0:
            segments.append(b"")
        else:
            for i in range(0, len(data), mdu):
                segments.append(data[i:i + mdu])

        part_hashes = []
        for seg in segments:
            ph = hashlib.sha256(seg).digest()[:4]
            part_hashes.append(ph)

        hashmap_bytes = b"".join(part_hashes)

        vectors.append({
            "_description": f"Resource advertisement — {label} ({len(data)} bytes)",
            "data_hex": h(data),
            "data_len": len(data),
            "random_hash_hex": h(random_hash),
            "resource_hash_hex": h(resource_hash),
            "resource_hash_len": len(resource_hash),
            "segment_count": len(segments),
            "mdu": mdu,
            "part_hashes_hex": [h(ph) for ph in part_hashes],
            "hashmap_bytes_hex": h(hashmap_bytes),
            "_note": (
                "resource_hash = SHA-256(data || random_hash). "
                "part_hash = SHA-256(segment_data)[0:4] for each segment."
            ),
        })

    return vectors


# ---------------------------------------------------------------------------
# Section: LXMF message vectors
# ---------------------------------------------------------------------------

def gen_lxmf_message_vectors() -> list:
    """
    LXMF message format vectors.

    An LXMF message has this wire layout:
      [destination_hash: 16 bytes]
      [source_hash: 16 bytes]
      [signature: 64 bytes]
      [msgpack_payload]

    The msgpack_payload is a list:
      [timestamp, title_bytes, content_bytes, fields_dict]

    message_hash = SHA-256(dest_hash || source_hash || msgpack_payload)

    The signature covers: message_hash (signed by source identity).

    These vectors are generated WITHOUT the lxmf package to avoid
    a hard dependency. They use raw construction matching the LXMF spec.
    The msgpack encoding uses umsgpack (bundled with RNS) or msgpack.
    """
    # Try to import a msgpack library
    _msgpack_pack = None
    try:
        import umsgpack
        _msgpack_pack = umsgpack.packb
    except ImportError:
        try:
            import msgpack
            _msgpack_pack = lambda obj: msgpack.packb(obj, use_bin_type=True)
        except ImportError:
            return [{
                "_description": "LXMF vectors skipped - no msgpack library available",
                "_note": "Install umsgpack or msgpack to generate LXMF vectors",
            }]

    vectors = []
    id_alice = get_identity("alice")
    id_bob = get_identity("bob")

    # Compute destination hashes for messaging
    # LXMF uses "lxmf" app name with "delivery" aspect
    alice_lxmf_dest_hash = RNS.Destination.hash(
        id_alice, "lxmf", "delivery"
    )
    bob_lxmf_dest_hash = RNS.Destination.hash(
        id_bob, "lxmf", "delivery"
    )

    test_cases = [
        {
            "label": "simple text message",
            "source": id_alice,
            "source_label": "alice",
            "dest_hash": bob_lxmf_dest_hash,
            "dest_label": "bob",
            "timestamp": 1700000000.0,
            "title": "Hello",
            "content": "This is a test message from Alice to Bob.",
            "fields": {},
        },
        {
            "label": "message with fields",
            "source": id_bob,
            "source_label": "bob",
            "dest_hash": alice_lxmf_dest_hash,
            "dest_label": "alice",
            "timestamp": 1700001000.0,
            "title": "Reply",
            "content": "Got your message!",
            "fields": {0x01: b"field_value_1"},  # field type 0x01
        },
        {
            "label": "empty content message",
            "source": id_alice,
            "source_label": "alice",
            "dest_hash": bob_lxmf_dest_hash,
            "dest_label": "bob",
            "timestamp": 1700002000.0,
            "title": "",
            "content": "",
            "fields": {},
        },
    ]

    for case in test_cases:
        source = case["source"]
        dest_hash = case["dest_hash"]
        source_hash = source.hash

        title_bytes = case["title"].encode("utf-8")
        content_bytes = case["content"].encode("utf-8")

        # Build msgpack payload: [timestamp, title, content, fields]
        payload_list = [
            case["timestamp"],
            title_bytes,
            content_bytes,
            case["fields"],
        ]
        msgpack_payload = _msgpack_pack(payload_list)

        # message_hash = SHA-256(dest_hash || source_hash || msgpack_payload)
        message_hash = hashlib.sha256(
            dest_hash + source_hash + msgpack_payload
        ).digest()

        # Signature covers the message hash
        signature = source.sign(message_hash)

        # Full packed message: dest_hash[16] || source_hash[16] || signature[64] || msgpack_payload
        packed = dest_hash + source_hash + signature + msgpack_payload

        vectors.append({
            "_description": f"LXMF message — {case['label']}",
            "source_label": case["source_label"],
            "dest_label": case["dest_label"],
            "source_hash_hex": h(source_hash),
            "dest_hash_hex": h(dest_hash),
            "timestamp": case["timestamp"],
            "title": case["title"],
            "content": case["content"],
            "title_bytes_hex": h(title_bytes),
            "content_bytes_hex": h(content_bytes),
            "fields": {str(k): h(v) if isinstance(v, bytes) else v
                       for k, v in case["fields"].items()},
            "msgpack_payload_hex": h(msgpack_payload),
            "msgpack_payload_len": len(msgpack_payload),
            "message_hash_hex": h(message_hash),
            "signature_hex": h(signature),
            "packed_hex": h(packed),
            "packed_len": len(packed),
            "_layout": {
                "dest_hash": "packed[0:16]",
                "source_hash": "packed[16:32]",
                "signature": "packed[32:96]  Ed25519(SHA-256(dest_hash||source_hash||msgpack_payload))",
                "msgpack_payload": "packed[96:]  msgpack([timestamp, title, content, fields])",
            },
        })

    return vectors


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate Reticulum test vectors for rns-rs"
    )
    parser.add_argument(
        "--out", "-o", default=None,
        help="Output file (default: stdout)",
    )
    args = parser.parse_args()

    rns_version = getattr(RNS, "__version__", None)
    if rns_version is None:
        try:
            import importlib.metadata
            rns_version = importlib.metadata.version("rns")
        except Exception:
            rns_version = "unknown"

    sections = {
        "constants":                gen_constants(),
        "identity_vectors":         gen_identity_vectors(),
        "destination_hash_vectors": gen_destination_hash_vectors(),
        "packet_flags_vectors":     gen_packet_flags_vectors(),
        "data_packet_vectors":      gen_data_packet_vectors(),
        "announce_packet_vectors":  gen_announce_packet_vectors(),
        "signing_vectors":          gen_signing_vectors(),
        "encryption_vectors":       gen_encryption_vectors(),
        "packet_hash_vectors":      gen_packet_hash_vectors(),
        "roundtrip_vectors":        gen_roundtrip_vectors(),
        "resource_advertisement_vectors": gen_resource_advertisement_vectors(),
        "lxmf_message_vectors":     gen_lxmf_message_vectors(),
    }

    doc = {
        "_generator":    "generate_test_vectors.py",
        "_rns_version":  rns_version,
        "_generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "_description": (
            "Test vectors generated from the Python Reticulum reference implementation. "
            "All byte values are lowercase hex strings. "
            "These are ground truth for rns-rs wire format compliance testing."
        ),
        **sections,
    }

    output = json.dumps(doc, indent=2)

    if args.out:
        out_dir = os.path.dirname(args.out)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(args.out, "w") as f:
            f.write(output)
        total = sum(len(v) if isinstance(v, list) else 1 for v in sections.values())
        print(
            f"Written to {args.out}  "
            f"({total} vectors across {len(sections)} sections)",
            file=sys.stderr,
        )
        for name, val in sections.items():
            count = len(val) if isinstance(val, list) else "dict"
            print(f"  {name}: {count}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
