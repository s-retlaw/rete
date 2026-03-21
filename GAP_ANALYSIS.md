# Python RNS vs Rust `rete` — Master Gap Analysis

Generated: 2026-03-21
Based on: 8 parallel deep-comparison agents reading every core Python file against Rust equivalents.

## P0: PROTOCOL BUGS (Rust rejects valid Python packets)

### P0-1: Ratchet-Bearing Announce Rejection
- **Status:** DONE
- **Rust:** `announce.rs:54-57` — hardcoded `signature = payload[84..148]`
- **Python:** `Identity.py:405-412` — when `context_flag=1`, 32 ratchet bytes at `payload[84..116]`, signature at `payload[116..180]`
- **Also:** `signed_data` must include ratchet bytes (Python line 425)
- **Impact:** Rust reads garbage as signature, rejects all ratchet-bearing announces
- **Fix:** Pass `context_flag` to `validate_announce()`, adjust offsets conditionally
- **Test:** `tests/interop/ratchet_announce_interop.py`

---

## P1: MISSING FEATURES (prevent interop scenarios)

### P1-1: Ratchet Key System (entire subsystem absent)
- **Status:** DONE
- **Python:** `Identity.py:269-387` — generate, store, rotate, clean ratchets; ratchet-aware encrypt/decrypt with fallback
- **Rust:** zero ratchet code
- **Impact:** Can't decrypt messages from Python nodes using rotated ratchets
- **Test:** `tests/interop/ratchet_encrypt_interop.py`

### P1-2: Request Handler Registration
- **Status:** DONE
- **Python:** `Destination.py:380-397` — `register_request_handler(path, generator, ALLOW_NONE/ALL/LIST)`
- **Rust:** Wire format in `request.rs` but no handler dispatch or policy
- **Impact:** Can't serve RPC-style requests
- **Test:** `tests/interop/request_handler_interop.py`

### P1-3: Path Request Forwarding
- **Status:** DONE
- **Python:** `Transport.py:2540-2816` — floods path requests to all interfaces, deduplication, grace periods
- **Rust:** `transport.rs:1738` — returns `Invalid` for unknown paths, doesn't forward
- **Impact:** Rust relay nodes break mesh path discovery

### P1-4: KISS Interface (stub)
- **Status:** DONE
- **Rust:** `rete-iface-kiss/src/lib.rs` — 4 lines
- **Impact:** No LoRa/TNC connectivity
- **Test:** Unit tests for KISS framing (FEND/FESC/TFEND/TFESC)

### P1-5: Announce Retransmission Jitter
- **Status:** DONE
- **Python:** `Transport.py:1728` — `random(0..PATHFINDER_RW)` jitter (0-0.5s)
- **Rust:** `transport.rs:2338` — deterministic exponential backoff, no jitter
- **Impact:** Synchronized floods on multi-repeater networks
- **Fix:** Add `PATHFINDER_RW` constant, use RNG in `pending_outbound()` delay

### P1-6: LOCAL_REBROADCASTS_MAX Not Tracked
- **Status:** DONE
- **Python:** `Transport.py:76,523` — stops retransmit after hearing local rebroadcast
- **Rust:** retransmits unconditionally up to PATHFINDER_R
- **Impact:** Doubles announce traffic on dense networks
- **Fix:** Add counter to `PendingAnnounce`, suppress on heard rebroadcast

---

## P2: API GAPS (feature exists but incomplete)

### P2-1: ProveApp Callback
- **Status:** DONE
- **Rust:** `rete-stack/src/lib.rs:42` — declares `ProveApp` enum variant, "not yet handled"
- **Python:** `Destination.py:359` — per-packet proof decision callback
- **Impact:** Can't selectively prove packets
- **Test:** `tests/interop/prove_app_interop.py`

### P2-2: Destination Type Diversity
- **Status:** DONE
- **Rust:** `node_core.rs` always registers `Single, In`
- **Python:** supports `OUT`, `GROUP`, `PLAIN` with distinct behaviors

### P2-3: AP/Roaming Path Expiry
- **Status:** DONE
- **Python:** AP=1 day (86400s), Roaming=6 hours (21600s), default=7 days (604800s)
- **Rust:** Fixed 7-day expiry for all paths (`PATH_EXPIRES = 604800`)
- **Impact:** Stale paths on AP/roaming interfaces
- **Fix:** Add interface mode to `Path` struct, use appropriate expiry in `tick()`

### P2-4: Receipt Table Too Small
- **Status:** DONE
- **Rust:** 64 entries (`transport.rs:303`); Python: 1024
- **Impact:** Gateway nodes lose proof tracking under load
- **Fix:** Make configurable per platform (64 embedded, 1024 hosted)

### P2-5: link.identify() Missing
- **Status:** DONE
- **Python:** `Link.py:459-475` — initiator reveals identity to responder via LINKIDENTIFY
- **Rust:** not implemented

### P2-6: Resource Metadata Support
- **Status:** DONE
- **Python:** arbitrary msgpack metadata (filename, MIME type) prepended to first segment
- **Rust:** no metadata field in Resource API

### P2-7: Stream/Buffer/Resource bz2 Decompression
- **Status:** DONE
- **Python:** auto-compresses streams and resources with bz2
- **Rust:** parses compressed flag but never decompresses
- **Impact:** Compressed data from Python arrives unusable

### P2-8: Missing Context Constants
- **Status:** DONE
- **Constants:** `CACHE_REQUEST` (0x08), `PATH_RESPONSE` (0x0B), `COMMAND` (0x0C), `COMMAND_STATUS` (0x0D)

---

## P3: BEHAVIOR DIFFS (not currently breaking interop)

### P3-1: Channel Window Fixed at 4
- **Status:** DONE
- **Python:** adaptive 2-48 based on RTT classification (fast/medium/slow)
- **Rust:** fixed window of 4
- **Impact:** Up to 12x throughput gap on fast links

### P3-2: Channel Timeout Fixed at 15s
- **Status:** DONE
- **Python:** exponential backoff, RTT-aware formula: `1.5^(tries-1) * max(rtt*2.5, 0.025) * (queue_depth + 1.5)`
- **Rust:** fixed 15-second timeout

### P3-3: Stale Link Timeout 25% Longer
- **Status:** DONE
- **Python:** `STALE_TIME = KEEPALIVE * 1.6 = 576s`
- **Rust:** `STALE_TIMEOUT_SECS = KEEPALIVE * 2 = 720s`

### P3-4: Announce Rate Limiting Missing
- **Status:** DONE
- **Python:** `Transport.py:1691-1720` — per-destination rate tracking with grace period and penalty backoff
- **Rust:** none (caller responsibility)

### P3-5: Resource Adaptive Window Missing
- **Status:** DONE
- **Python:** window grows to 75 on fast links based on EIFR measurement
- **Rust:** fixed at initial window (4)

### P3-6: Link Table Missing Hop Validation
- **Status:** DONE
- **Python:** `Transport.py:1512-1549` — validates hop count before forwarding
- **Rust:** `transport.rs:906-925` — forwards unconditionally on link_table match

### P3-7: Dedup Window Capacity Mismatch
- **Status:** DONE
- **Python:** ~1M hashes (two-set culling)
- **Rust:** 128-4096 fixed ring buffer (platform dependent)

### P3-8: Path Request State Tracking
- **Status:** DONE
- **Python:** `PATH_REQUEST_MI = 20s` minimum interval, `PATH_REQUEST_TIMEOUT = 15s`, grace periods
- **Rust:** no path request throttling (caller responsibility)

---

## P4: LXMF-SPECIFIC GAPS

### P4-1: Stamp System (PoW) Missing
- **Status:** DONE
- **Python:** `LXStamper.py` — HKDF-based proof-of-work for propagation node rate limiting
- **Rust:** none

### P4-2: Peer Management Missing
- **Status:** DONE
- **Python:** `LXMPeer.py` — full state machine, offer/response protocol, sync strategies (LAZY/PERSISTENT)
- **Rust:** simplified forward/retrieval jobs

### P4-3: Ticket System Missing
- **Status:** DONE
- **Python:** `LXMessage.py:43-52` — rate-limiting credential for frequent senders, 21-day expiry

### P4-4: Paper Message Format Missing
- **Status:** DONE
- **Python:** `LXMessage.py:685-731` — `lxm://` URI and QR encoding for offline transport

---

## NOT GAPS (verified matches)

These were investigated and confirmed as matching:

- **AES cipher:** Both use AES-256-CBC with 64-byte HKDF-derived keys (Agent 1 false positive)
- **Token format:** `iv[16] || aes_256_cbc_body || hmac_sha256[32]` — identical
- **Packet hash computation:** Both mask upper nibble, use full 32-byte SHA-256
- **Destination hash computation:** Both use `SHA-256(name_hash || identity_hash)[0:16]`
- **Link handshake:** ECDH + HKDF + proof signature — byte-compatible
- **MTU signalling:** 3-byte encoding matches exactly
- **Keepalive protocol:** 0xFF request, 0xFE response — matches
- **Channel envelope wire format:** `msgtype[2] || seq[2] || len[2] || payload` — matches
- **Request/response msgpack format:** `[timestamp, path_hash, data]` / `[request_id, data]` — matches
- **Resource advertisement flags:** 6-bit field layout matches
- **Resource proof format:** `resource_hash[32] || SHA-256(data || resource_hash)[32]` — matches
- **LXMF message pack/unpack/sign:** All match

---

## Sprint Order

1. **Sprint 1 (P0):** Ratchet-bearing announce handling
2. **Sprint 2 (P1):** Ratchet key storage, request handlers, path request forwarding, announce jitter, local rebroadcast tracking, KISS interface
3. **Sprint 3 (P2):** ProveApp, AP/roaming expiry, receipt table, link.identify, contexts
4. **Sprint 4 (P3):** Channel adaptive window, timeout formulas, announce rate limiting, stale timeout
5. **Sprint 5 (P4):** LXMF stamp system, peer management
