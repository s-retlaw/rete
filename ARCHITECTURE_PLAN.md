# Architectural Improvement Plan

## Overview

This plan addresses findings from an architectural review of the rete codebase. Work is ordered to minimize risk: refactorings first (validated by existing E2E tests), then bug fixes (with new tests), then feature work.

**Guiding principle:** Existing E2E tests (`tests/interop/`) remain unchanged throughout. They are the regression safety net. Unit tests are added/modified as needed.

---

## Phase 1: Large File Splits (Refactoring)

All three splits are behavior-preserving refactors. E2E tests must pass after each split with zero changes to test code.

### Phase 1A: Split `transport.rs` (3,964 lines → ~6 modules)

**File:** `crates/rete-transport/src/transport.rs`

The Transport struct has 38 fields serving 6+ distinct concerns. Split into submodules under `crates/rete-transport/src/transport/`:

| Module | Lines (approx) | Responsibility | Key functions |
|--------|----------------|----------------|---------------|
| `mod.rs` | ~200 | Transport struct definition, `ingest()`, `ingest_on()` dispatch, `tick()`, re-exports | Core orchestration |
| `path.rs` | ~50 | Path table CRUD | `get_path`, `insert_path`, `remove_path`, `touch_path` |
| `announce.rs` | ~350 | Announce queue, handling, rate limiting, path requests | `queue_announce`, `handle_announce`, `handle_path_request`, `create_announce` |
| `link.rs` | ~400 | Link lifecycle, handshake, keepalives, close | `initiate_link`, `handle_link_request`, `handle_lrproof`, `handle_link_data`, `build_link_*` |
| `resource.rs` | ~500 | Resource send/recv, split transfers, encryption | `start_resource`, `accept_resource`, `handle_resource_data`, `tick_resources`, `drain_resource_outbound` |
| `receipt.rs` | ~100 | Delivery proofs and receipts | `register_receipt`, `build_proof_packet`, `build_link_proof_packet` |

**Approach:**
- Transport struct stays in `mod.rs` with all fields (they're interconnected)
- Methods move to submodules as `impl Transport<P,A,D,L>` blocks (Rust allows multiple impl blocks)
- `mod.rs` keeps `ingest_on()` as the dispatch coordinator, calling handlers in submodules
- Internal helpers (`prepend_and_encrypt`, `compute_sdu_and_link_mdu`) move with their callers
- Tests move to the module they test

**Validation:** `cargo test --workspace` + all 10 E2E interop tests pass unchanged.

---

### Phase 1B: Split `node_core.rs` (2,900 lines → ~5 modules)

**File:** `crates/rete-stack/src/node_core.rs`

| Module | Lines (approx) | Responsibility | Key functions |
|--------|----------------|----------------|---------------|
| `mod.rs` | ~300 | NodeCore struct, `new()`, config setters, stats, snapshot, re-exports | Core struct + orchestration |
| `destination.rs` | ~150 | Destination registration, lookup, proof strategy | `register_destination`, `register_destination_typed`, `get_destination`, `register_peer` |
| `announce.rs` | ~200 | Announce building, queuing, flushing | `build_announce`, `queue_announce`, `flush_announces`, `initial_announce` |
| `link.rs` | ~200 | Link initiation, channel/stream send, close, identify | `initiate_link`, `send_channel_message`, `send_stream_data`, `close_link`, `link_identify` |
| `ingest.rs` | ~600 | Inbound packet dispatch, request handling, resource buffering | `handle_ingest`, `dispatch_ingest`, `find_request_handler`, `handle_tick` |

**Note:** The existing `crates/rete-stack/src/destination.rs` (the Destination struct itself) is separate from the NodeCore destination management methods. The new `node_core/destination.rs` contains NodeCore's methods for managing destinations, not the Destination struct.

**Approach:** Same as 1A — multiple `impl NodeCore` blocks across submodules, struct stays in `mod.rs`.

**Validation:** `cargo test --workspace` + all 10 E2E interop tests pass unchanged.

---

### Phase 1C: Split `router.rs` (3,285 lines → ~7 modules)

**File:** `crates/rete-lxmf/src/router.rs`

| Module | Lines (approx) | Responsibility | Key functions |
|--------|----------------|----------------|---------------|
| `mod.rs` | ~200 | LxmfRouter struct, `register()`, config, re-exports | Core struct + registration |
| `delivery.rs` | ~100 | Opportunistic & direct message send/receive | `pack_opportunistic`, `send_opportunistic`, `pack_direct`, `send_direct`, `try_parse_lxmf*` |
| `event.rs` | ~200 | Event dispatch | `handle_event`, `handle_event_mut` |
| `propagation.rs` | ~200 | Propagation store API, deposit, retrieval request handling | `propagation_deposit`, `handle_propagation_request`, `start_retrieval_send`, `prune_propagation` |
| `peering.rs` | ~400 | Peer registry + peer sync state machine | `peer`, `unpeer`, `check_peer_syncs`, `advance_sync_on_*`, `handle_offer_request` |
| `forward.rs` | ~200 | Auto-forward store-and-forward delivery | `start_propagation_forward`, `advance_forward_on_*`, `send_stored_message_resource` |
| `codec.rs` | ~150 | Shared msgpack helpers, bz2 compression, announce parsing | `encode_msgpack_uint`, `encode_offer_hashes`, `bz2_compress`, `parse_lxmf_announce_data` |

**Approach:** Same pattern. State machine types (`ForwardJob`, `RetrievalJob`, `SyncJob`) move to their respective modules.

**Validation:** `cargo test --workspace` + all 10 E2E interop tests pass unchanged.

---

## Phase 2: Msgpack Codec Consolidation (Refactoring)

**Problem:** `write_bin()`, `read_bin()`, `read_array_len()`, `read_float64()` are duplicated across:
- `crates/rete-transport/src/request.rs` (private copies)
- `crates/rete-transport/src/resource.rs` (private copies)
- `crates/rete-lxmf/src/message.rs` (pub(crate) copies, partially reused by router)

~150-200 lines of near-identical code. `read_array_len()` in message.rs is missing array32 support that resource.rs has — a latent bug.

**Approach:**
- Add a `msgpack` module to `rete-core` (it's `no_std`, no alloc needed for read helpers; write helpers need caller-provided buffers)
- Consolidate: `write_bin()`, `read_bin()`, `read_array_len()` (with array32), `read_float64()`, `write_array_header()`
- Use a unified error type (simple enum, not `&'static str`)
- Update `request.rs`, `resource.rs`, `message.rs`, and `router/codec.rs` to import from `rete-core::msgpack`
- Delete the private copies

**Why rete-core and not a new crate:** This is ~200 lines of `no_std` code. A new `rete-codec` crate adds dependency management overhead for minimal gain. `rete-core` already handles wire format concerns.

**Validation:** `cargo test --workspace` + all 10 E2E interop tests pass unchanged.

---

## Phase 3: Bug Fixes (Red-Green TDD)

Each bug fix follows: write a failing test → fix the code → verify test passes → run E2E suite.

### Phase 3A: Fix decrypt fallback (P0)

**Bug:** `node_core.rs` (currently `ingest.rs` after Phase 1B) decrypts inbound LocalData with `self.identity.decrypt()` and falls back to raw payload on any error. This:
1. Uses the wrong decryption method (Identity instead of Destination)
2. Silently accepts ciphertext as plaintext on failure
3. Ignores destination type (Single/Group/Plain)

**Fix:**
- Look up the matched Destination in `dispatch_ingest` for LocalData
- Call `destination.decrypt()` (which already correctly handles Single/Group/Plain at `destination.rs:262`)
- On decrypt failure for non-Plain destinations, reject the packet (return error event or drop)
- Remove the `Err(_) => payload.to_vec()` fallback

**New tests:**
- Unit test: Single destination decrypt failure → packet rejected, not delivered as plaintext
- Unit test: Plain destination → data delivered without decryption
- Unit test: Group destination → data decrypted with group token

**Validation:** New unit tests pass + all E2E interop tests pass.

---

### Phase 3B: Fix request handler dispatch (P0)

**Bug:** `find_request_handler()` searches all destinations by `path_hash` only. Two destinations with the same path will race. Dispatch doesn't use the link's bound destination.

**Fix:**
- Change `find_request_handler()` to accept `destination_hash` and match on `(destination_hash, path_hash)`
- In dispatch, resolve the link's `destination_hash` first, then look up the handler scoped to that destination

**New tests:**
- Unit test: Two destinations register same path → requests dispatch to correct destination based on link binding

**Validation:** New unit tests pass + all E2E interop tests pass.

---

### Phase 3C: Persist link identity on LINKIDENTIFY (P0)

**Bug:** LINKIDENTIFY emits `NodeEvent::LinkIdentified` but doesn't store the identity on the Link struct. Downstream code can't query who a link is with.

**Fix:**
- Add `identified_identity: Option<[u8; 64]>` and `identified_hash: Option<[u8; 16]>` fields to the `Link` struct in `crates/rete-transport/src/link.rs`
- In LINKIDENTIFY handling (node_core ingest), after verification, write identity to the Link
- Add `pub fn identified_identity_hash(&self) -> Option<&[u8; 16]>` accessor

**New tests:**
- Unit test: After LINKIDENTIFY, `link.identified_identity_hash()` returns the verified hash
- Unit test: Before LINKIDENTIFY, returns None

**Validation:** New unit tests pass + all E2E interop tests pass.

---

### Phase 3D: Replace unwrap/expect in production paths (P1)

**Locations:**
- `node_core.rs:192` — `expect("app_name + aspects must fit in 128 bytes")`
- `destination.rs:104` — `expect("app_name + aspects must fit in 128 bytes")`
- `stamp.rs:63` — `hk.expand(b"", &mut block).unwrap()`

**Fix:**
- Add `try_new()` / `try_from_bytes()` variants that return `Result`
- Change existing constructors to call `try_*` internally (keep infallible API if buffer size is guaranteed by construction)
- For stamp.rs, propagate the HKDF error

**Validation:** `cargo test --workspace` + all E2E interop tests pass.

---

## Phase 4: Richer Request Handler API

### Phase 4A: RequestContext struct and handler signature

**Current signature:**
```rust
pub type RequestHandlerFn = fn(&str, &[u8], &[u8; 16], &[u8; 16]) -> Option<Vec<u8>>;
```

**New signature:**
```rust
pub struct RequestContext {
    pub destination_hash: [u8; 16],
    pub path: String,
    pub path_hash: [u8; 16],
    pub link_id: [u8; 16],
    pub request_id: [u8; 16],
    pub requested_at: f64,          // from wire format, currently parsed and discarded
    pub remote_identity: Option<[u8; 16]>,  // from Link.identified_identity_hash()
}

pub type RequestHandlerFn = fn(&RequestContext, &[u8]) -> Option<Vec<u8>>;
```

**Changes:**
- Pass `requested_at` timestamp through from `request.rs` parsing (it's already parsed and thrown away)
- Populate `remote_identity` from the link's identified identity (Phase 3C)
- Populate `destination_hash` from the link's bound destination (Phase 3B)
- Update all existing handler registrations in examples/tests

**Validation:** Unit tests + E2E interop tests pass. Example code updated.

---

### Phase 4B: ALLOW_LIST request policy

**Current:**
```rust
pub enum RequestPolicy { AllowNone, AllowAll }
```

**New:**
```rust
pub enum RequestPolicy {
    AllowNone,
    AllowAll,
    AllowList(Vec<[u8; 16]>),  // identity hashes
}
```

**Changes:**
- In request dispatch, when policy is `AllowList`, check `context.remote_identity` against the list
- If `remote_identity` is None (link not identified), reject the request
- Add convenience method `RequestPolicy::allows(&self, identity: Option<&[u8; 16]>) -> bool`

**New tests:**
- Unit test: AllowList with matching identity → allowed
- Unit test: AllowList with non-matching identity → rejected
- Unit test: AllowList with unidentified link → rejected

**Validation:** Unit tests + E2E interop tests pass.

---

## Phase 5: LXMF Portability (no_std split)

### Phase 5A: Create `rete-lxmf-core` crate

**Goal:** Move pure protocol types out of `rete-lxmf` so they can be used in WASM/embedded without std.

**Moves to `rete-lxmf-core` (no_std + alloc):**
- `LxMessage` struct and serialization
- Stamp computation and verification
- LXMF payload codecs
- Message types/constants

**Stays in `rete-lxmf` (std):**
- `LxmfRouter` and all orchestration
- Propagation stores (FileMessageStore, etc.)
- Peer sync, forward, retrieval
- bzip2 compression

**Changes:**
- `rete-lxmf` re-exports core types for backward compatibility
- `sha2` dependency in `rete-lxmf-core` uses `default-features = false` (no std)
- `rete-lxmf` keeps `sha2` with std

**Validation:**
- `cargo build -p rete-lxmf-core --target wasm32-unknown-unknown` succeeds
- `cargo test --workspace` + all E2E interop tests pass

---

### Phase 5B: Remove std::collections from router

**After Phase 1C**, `router/mod.rs` and submodules should use `alloc::collections` or keep std behind a feature flag. Evaluate whether the router itself needs to be no_std or if this is only needed for the core types (Phase 5A may be sufficient).

---

## Phase 6: ResponseCompressionPolicy

**New type:**
```rust
pub enum ResponseCompressionPolicy {
    Default,    // compress if response > threshold (match Python's auto_compress)
    Always,
    Never,
    Below(usize),  // compress if response size < N bytes
}
```

**Changes:**
- Add `compression_policy` field to `RequestHandler`
- In response dispatch, apply bz2 compression according to policy (use existing `compress_fn` callback)
- Default threshold should match Python RNS behavior (investigate Python source for exact value)

**New tests:**
- Unit test: Response above threshold → compressed (with Default policy)
- Unit test: Response with Never policy → not compressed
- Unit test: Response with Always policy → compressed regardless of size

**Validation:** Unit tests + E2E interop tests pass.

---

## Phase 7: RatchetStore Abstraction

**Current state:** `rete-core` has ratchet crypto primitives (`encrypt_with_ratchet`, `decrypt_with_ratchets`, ratchet key ID generation). What's missing is lifecycle orchestration and storage.

**New abstraction in `rete-stack`:**

```rust
pub trait RatchetStore {
    /// Store a ratchet public key seen in an announce
    fn store_announced_ratchet(&mut self, identity_hash: &[u8; 16], ratchet_pub: &[u8; 32]);

    /// Recall the latest ratchet public key for a destination
    fn recall_ratchet(&self, identity_hash: &[u8; 16]) -> Option<[u8; 32]>;

    /// Rotate local ratchet key pair, return new public key for announces
    fn rotate_local_ratchet(&mut self) -> [u8; 32];

    /// Get current local ratchet private key for decryption
    fn local_ratchet_private(&self) -> Option<&[u8; 32]>;

    /// Get previous local ratchet private keys (for in-flight decryption)
    fn previous_ratchet_privates(&self) -> &[[u8; 32]];

    /// Check if ratchet is enforced for a destination (reject non-ratcheted packets)
    fn is_ratchet_enforced(&self, identity_hash: &[u8; 16]) -> bool;
}
```

**Integration points:**
- Announce processing: when ingesting an announce with `context_flag=1`, extract ratchet pub key and call `store_announced_ratchet()`
- Outbound encryption: when encrypting to a destination, check `recall_ratchet()` and use `encrypt_with_ratchet()` if available
- Inbound decryption: try `decrypt_with_ratchets()` using stored private keys
- Announce building: include local ratchet public key if rotation is active
- Enforced ratchet: reject packets from destinations where ratchet is enforced but no ratchet was used

**New tests:**
- Unit test: Announce with ratchet → stored and recalled for subsequent encryption
- Unit test: Ratchet rotation → old keys still work for decryption during transition
- Unit test: Enforced ratchet → non-ratcheted packet rejected
- Interop test: Ratcheted announce round-trip with Python RNS (if Python RNS supports it in test mode)

**Validation:** Unit tests + E2E interop tests pass.

---

## Phase 8: Documentation Update

**After all code phases are complete:**

- **README.md**: Update feature matrix — Links, Channels, LXMF are implemented, not "out of scope"
- **GAP_ANALYSIS.md**: Update ratchet status, link.identify() status, request handler API status
- **docs/WEB_CLIENT_PLAN.md**: Update to reflect `rete-lxmf-core` split
- **CLAUDE.md**: Update "out of scope" section if items have been implemented

**Validation:** Review all docs for accuracy against current codebase state.

---

## Execution Notes

- Each phase is a separate planning session with a subsequent agent
- Phases 1A, 1B, 1C can potentially be parallelized (different files/crates)
- Phase 2 depends on Phase 1C (router codec module)
- Phase 3 depends on Phase 1 (file locations change after splits)
- Phase 4A depends on Phases 3B and 3C (needs link identity and destination-scoped dispatch)
- Phase 4B depends on Phase 4A (needs RequestContext)
- Phase 5 depends on Phase 1C (router split)
- Phase 6 depends on Phase 4A (needs RequestHandler changes)
- Phase 7 can start after Phase 3A (decrypt fix establishes the pattern)
- Phase 8 is last

## Status Tracking

| Phase | Description | Status |
|-------|-------------|--------|
| 1A | Split transport.rs | **Done** |
| 1B | Split node_core.rs | **Done** |
| 1C | Split router.rs | **Done** |
| 2 | Msgpack codec consolidation | **Done** |
| 3A | Fix decrypt fallback | **Done** |
| 3B | Fix request handler dispatch | **Done** |
| 3C | Persist link identity | **Done** |
| 3D | Replace unwrap/expect | Not started |
| 4A | RequestContext + handler signature | Not started |
| 4B | ALLOW_LIST policy | Not started |
| 5A | rete-lxmf-core crate | Not started |
| 5B | Remove std from router | Not started |
| 6 | ResponseCompressionPolicy | Not started |
| 7 | RatchetStore abstraction | Not started |
| 8 | Documentation update | Not started |
