# Architectural Refactor Tracker

Source: [ARCHITECTURAL_REVIEW_2026-04-01.md](ARCHITECTURAL_REVIEW_2026-04-01.md)
Created: 2026-04-02

## Status Overview

| # | Item | Priority | Status | Notes |
|---|------|----------|--------|-------|
| 1 | Resource hash verification skip | P0 | ✅ DONE | Fixed — enforce hash check after decrypt |
| 2 | Resource auto-accept, no policy | P0 | ✅ DONE | ResourceStrategy enum, AcceptNone/AcceptAll/AcceptApp, RESOURCE_RCL |
| 3 | Storage arch (heapless for hosted) | P1 | ✅ DONE | TransportStorage trait; HeaplessStorage + StdStorage backends |
| 4 | Destination/NodeCore modeling | P1 | ✅ DONE | `destination_hashes()` canonical; `decrypt_with_identity()` on Destination |
| 5 | Request/Resource lifecycle parity | P1 | TODO | No RequestReceipt, no resource callbacks |
| 6 | LxmfRouter narrower than upstream | P1 | TODO | No outbound queue, retry, or receipt tracking |
| 7 | Portable LXMF boundary half-finished | P1 | TODO | Lower priority — RNode doesn't need rete-lxmf |
| 8 | Error handling (stringly-typed) | P2 | TODO | Resource + LXMF still use `&'static str` errors |
| 9 | Callbacks too narrow (fn pointers) | P2 | TODO | Can't capture state; need trait-based hooks |
| 10 | Type system underused for hashes | P2 | TODO | Do last — touches every signature |
| 11 | Docs out of date | P2 | TODO | README says AES-128, code uses AES-256; scope wrong |
| 12 | Linux example is a de facto daemon | P2 | TODO | 2000+ line main.rs mixing concerns |

---

## 1. Resource Hash Verification Skip

**Priority:** P0 — Correctness bug
**Status:** ✅ DONE (2026-04-02)

### Problem

`Resource::assemble()` computes `SHA-256(assembled || random_hash)` and compares it to `resource_hash` from the advertisement. When they don't match, it **still marks the resource `Complete` and returns `Ok(assembled)`**.

The comment says verification is skipped because "Python may hash compressed/encrypted payloads differently." That's an acceptable debug note during development but not a shipping state.

### Key Files

- `crates/rete-transport/src/resource.rs:1002-1021` — the `assemble()` method with the skip
- `crates/rete-transport/src/resource.rs:636-789` — resource parsing APIs returning `Result<_, &'static str>`
- `crates/rete-transport/src/resource.rs:947-986` — segment assembly logic

### What to Do

1. **Determine what Python actually hashes.** Read `RNS/Resource.py` — the hash may be over the pre-compression or post-encryption payload. The Rust code needs to hash the same thing.
2. **Add `ResourceState::Failed(ResourceError)` terminal state.** A resource that fails hash verification must not be `Complete`.
3. **Change `assemble()` to return `Err(ResourceError::HashMismatch)` on failure** instead of silently succeeding.
4. **Introduce `ResourceError` enum** replacing all `&'static str` returns in this file (overlaps with item 8).

### Done When

- `assemble()` returns `Err` on hash mismatch
- `ResourceState::Failed` exists and is used
- No resource can reach `Complete` without passing hash verification
- Existing interop tests (`resource_interop`, `resource_large`, `resource_1mb`, `resource_multiseg`) still pass — they exercise the happy path
- A new unit test sends a corrupted segment and asserts `Failed`, not `Complete`

---

## 2. Resource Auto-Accept, No Policy

**Priority:** P0 — Correctness + API gap
**Status:** ✅ DONE (2026-04-02)

### Problem

`NodeCore::ingest()` unconditionally calls `accept_resource()` for every `IngestResult::ResourceOffered`. There is no way for an application to decline a resource offer.

Python exposes `Link.set_resource_strategy(callback=None, strategy=RNS.Resource.ACCEPT_NONE)` with three strategies: `ACCEPT_NONE`, `ACCEPT_ALL`, `ACCEPT_APP` (calls a user callback to decide).

### Key Files

- `crates/rete-stack/src/node_core/ingest.rs:373-397` — the unconditional auto-accept
- `crates/rete-transport/src/resource.rs` — `Resource` struct and state machine
- `crates/rete-transport/src/link.rs` — `Link` struct (resource strategy should live here or near it)
- `crates/rete-stack/src/lib.rs` — `NodeEvent` enum (may need `ResourceRejected` variant)

### What to Do

1. **Add `ResourceStrategy` enum:** `AcceptNone`, `AcceptAll`, `AcceptApp`.
2. **Store strategy per-link** (or on `NodeCore` as a default).
3. **Change `ingest.rs`** to check the strategy before calling `accept_resource()`:
   - `AcceptNone` → emit `NodeEvent::ResourceOffered` but don't accept; let app call an explicit accept method.
   - `AcceptAll` → current behavior.
   - `AcceptApp` → emit event with resource summary; app decides by calling accept/reject.
4. **Add `NodeCore::accept_resource()` and `NodeCore::reject_resource()` public methods** so the app can act on offers.
5. **Default to `AcceptAll`** for backward compatibility with existing tests.

### Done When

- `ResourceStrategy` enum exists
- `AcceptNone` prevents resource acceptance
- `AcceptApp` defers to application
- Existing resource interop tests pass (they use the default `AcceptAll`)
- New test demonstrates `AcceptNone` rejecting an offered resource

---

## 3. Storage Architecture (Heapless for Hosted)

**Priority:** P1
**Status:** ✅ DONE (2026-04-02)

### Solution

Extracted a `TransportStorage` trait with pluggable `StorageMap`, `StorageDeque`, and `StorageSet` collection traits. Two implementations:

- **`HeaplessStorage<P, A, D, L>`** — fixed-size `FnvIndexMap`/`Deque`/`FnvIndexSet` (embedded, `no_std`)
- **`StdStorage`** — heap-allocated `hashbrown::HashMap`/`VecDeque`/`HashSet` (hosted, behind `hosted` feature flag)

`Transport<S: TransportStorage>` replaces `Transport<const P, A, D, L>`. `NodeCore<S>` replaces `NodeCore<const P, A, D, L>`.

### Key Files

- `crates/rete-transport/src/storage.rs` — traits + `HeaplessStorage`
- `crates/rete-transport/src/storage_std.rs` — `StdStorage` (gated behind `hosted` feature)
- `crates/rete-transport/src/transport/mod.rs` — `Transport<S: TransportStorage>`
- `crates/rete-stack/src/node_core/mod.rs` — `NodeCore<S: TransportStorage>`

### Verified

- `HostedNodeCore` now uses heap-allocated collections (no more ~600KB stack)
- `cargo check -p rete-transport --target thumbv6m-none-eabi` passes
- All 561 unit tests pass
- All 49 E2E interop tests pass

---

## 4. Destination / NodeCore Modeling

**Priority:** P1
**Status:** ✅ DONE (2026-04-02)

### Solution

1. **`rete_core::destination_hashes()`** is the single canonical implementation returning `(dest_hash, name_hash)`. The existing `destination_hash()` is now a thin wrapper returning `.0`.
2. **Deleted `compute_dest_hashes()`** from `node_core/mod.rs`. All callers (`Destination::new()`, `register_destination()`, `register_destination_typed()`) use `destination_hashes()` directly.
3. **Added `Destination::decrypt_with_identity()`** — accepts external `&Identity` + ratchet keys. Centralizes decrypt dispatch on Destination without requiring identity ownership (Identity has `ZeroizeOnDrop`, not `Clone`).
4. **Simplified `ingest.rs`** — 30-line match block replaced with single `decrypt_with_identity()` call.

### Key Files

- `crates/rete-core/src/identity.rs` — `destination_hashes()` canonical implementation
- `crates/rete-stack/src/destination.rs` — `decrypt_with_identity()` method + 6 tests
- `crates/rete-stack/src/node_core/destination.rs` — uses `destination_hashes()` directly
- `crates/rete-stack/src/node_core/ingest.rs` — simplified decrypt dispatch

### Verified

- All workspace unit tests pass (91 in rete-stack, 123 in rete-transport, etc.)
- All 53 E2E interop tests pass

---

## 5. Request/Resource Lifecycle Parity

**Priority:** P1
**Status:** TODO

### Problem

`send_request()` returns only `(OutboundPacket, request_id)`. There is no `RequestReceipt`, no tracked status, no timeout, no progress callback. Python exposes `Link.request(path, data, response_callback, failed_callback, progress_callback, timeout)` and `RNS.RequestReceipt`.

Resource lifecycle has a similar gap — no strategy callbacks, no progress/concluded callbacks matching Python's `set_resource_callback`, `set_resource_started_callback`, `set_resource_concluded_callback`.

### Key Files

- `crates/rete-stack/src/node_core/mod.rs:565-592` — `send_request()` return type
- `crates/rete-stack/src/node_core/ingest.rs:278-340` — handler dispatch
- `crates/rete-transport/src/transport/link.rs` — link state
- `crates/rete-transport/src/transport/resource.rs` — resource transfer state

### What to Do

1. **Add `RequestReceipt` struct** with status (Sent, Delivered, Failed, TimedOut), response data, and timing.
2. **Track pending requests in `NodeCore`** keyed by request_id.
3. **Add request timeout logic** to `tick()`.
4. **For resources:** add progress tracking and concluded state accessible from `NodeEvent`.
5. **Design for Rust idioms** — consider returning a handle/future rather than mimicking Python's callback model directly.

### Done When

- `send_request()` returns a `RequestReceipt` or handle
- Request timeout fires and produces a `NodeEvent::RequestFailed` or similar
- Resource progress is observable
- Existing request interop tests pass

---

## 6. LxmfRouter Narrower Than Upstream

**Priority:** P1 — only relevant for hosted nodes, not RNode
**Status:** TODO

### Problem

The Rust `LxmfRouter` handles some delivery/propagation flows but lacks:
- Outbound message queue
- Delivery receipt tracking
- Retry and failure notification
- `handle_outbound()` workflow
- Stamp/ticket policy integration (announces hardcode stamp cost 0)

### Key Files

- `crates/rete-lxmf/src/router/mod.rs:188-321` — router core
- `crates/rete-lxmf/src/router/delivery.rs:15-100` — delivery logic
- `crates/rete-lxmf/src/router/peering.rs` — peer sync
- `crates/rete-lxmf-core/src/stamp.rs` — stamp primitives (not integrated into routing)

### What to Do

1. **Add `OutboundMessage` struct** with status (Queued, Sending, Delivered, Failed) and retry count.
2. **Add outbound queue** with `handle_outbound(message)` entry point.
3. **Integrate stamp cost** — use non-zero cost in announces, enforce on inbound.
4. **Add delivery receipt tracking** — emit events on success/failure.

### Done When

- `handle_outbound()` exists and queues messages
- Retry on failed delivery works
- Non-zero stamp cost is respected
- Existing LXMF interop tests pass

---

## 7. Portable LXMF Boundary Half-Finished

**Priority:** P1 (lowered — RNode doesn't need `rete-lxmf` on MCU)
**Status:** TODO

### Problem

`rete-lxmf` enables `sha2/std` and is not `#![no_std]`. `cargo check -p rete-lxmf --no-default-features --target thumbv6m-none-eabi` fails. The portable contract today is "use `rete-lxmf-core` directly."

### Key Files

- `crates/rete-lxmf/Cargo.toml:9-20` — `sha2` with `features = ["std"]`
- `crates/rete-lxmf/src/lib.rs:1-31` — no `#![no_std]`

### What to Do

**Option A (recommended):** Accept the split — `rete-lxmf-core` is the portable crate, `rete-lxmf` (with router) is hosted-only. Document this clearly.

**Option B:** Make `rete-lxmf` `#![no_std]` + `alloc` with router features gated behind `std`.

### Done When

- Crate docs and README clearly state which crate to use where
- `cargo check -p rete-lxmf-core --target thumbv6m-none-eabi` passes (already does)
- Decision is documented

---

## 8. Error Handling (Stringly-Typed)

**Priority:** P2
**Status:** TODO

### Problem

Several public APIs still return `Result<_, &'static str>`:
- `rete-transport::resource` — multiple functions
- `rete-lxmf-core::message` — `pack()`, `unpack()`

Also: `MsgpackError::as_str()` exists as backward compat, `Destination::new()` uses `Error::MissingField` for a logic error, and there are `expect()` calls on public paths in `rete-lxmf` router.

### Key Files

- `crates/rete-transport/src/resource.rs:636-789, 947-986, 993-1021`
- `crates/rete-lxmf-core/src/message.rs:104-133, 151-187`
- `crates/rete-core/src/msgpack.rs:27-40` — `as_str()` bridge
- `crates/rete-lxmf/src/router/mod.rs:241-250` — `expect()` on dest registration
- `crates/rete-stack/src/destination.rs:82-99` — wrong error variant

### What to Do

1. **Add `ResourceError` enum** in `rete-transport` (ties into item 1).
2. **Add `LxmfMessageError` enum** in `rete-lxmf-core`.
3. **Replace all `&'static str` returns** with the appropriate typed error.
4. **Remove `as_str()` bridge** and fix callers.
5. **Replace `expect()` calls** on public paths with `Result` returns.

### Done When

- No public API returns `&'static str` errors
- No `expect()` on public registration/construction paths
- Tests assert on error variants, not messages

---

## 9. Callbacks Too Narrow (fn Pointers)

**Priority:** P2
**Status:** TODO

### Problem

Extension points use bare `fn` pointers:
- `TransformFn = fn(&[u8]) -> Option<Vec<u8>>`
- `ProveAppFn = fn(&[u8; 16], &[u8; 32], &[u8]) -> bool`
- `RequestHandlerFn = fn(&RequestContext<'_>, &[u8]) -> Option<Vec<u8>>`

Can't capture state. Forces globals or side channels for anything stateful.

### Key Files

- `crates/rete-stack/src/node_core/mod.rs:29-60` — fn pointer type defs
- `crates/rete-stack/src/node_core/mod.rs:120-131` — `RequestHandler` struct

### What to Do

1. **Define a `NodeHooks` trait** with default no-op methods for compression, proof policy, request dispatch.
2. **Or use `Box<dyn Fn(...)>`** behind `alloc` feature for simpler migration.
3. **Keep `no_std` viable** — trait approach works; closures need `alloc`.

### Done When

- At least one hook (e.g., request handler) can capture state
- Existing tests still compile and pass
- `no_std` build still works

---

## 10. Type System Underused for Hashes

**Priority:** P2 — do last (touches every signature)
**Status:** TODO

### Problem

`[u8; 16]` is used for destination hash, identity hash, link ID, request ID, and path hash. Easy to mix them up; compiler can't help.

### Key Files

- `crates/rete-stack/src/node_core/mod.rs:38-54` — `RequestContext` with multiple `[u8; 16]` fields
- Throughout `crates/rete-transport/` — maps keyed by raw arrays

### What to Do

1. **Add newtypes in `rete-core`:** `DestHash`, `IdentityHash`, `LinkId`, `RequestId`, `PathHash`.
2. **Derive `Copy`, `Clone`, `Eq`, `Hash`, `Ord`, `AsRef<[u8]>`.**
3. **Migrate signatures** crate by crate, starting from `rete-core` outward.

### Done When

- Newtypes exist and are used in public APIs
- Compiler prevents mixing hash types
- All tests pass

---

## 11. Docs Out of Date

**Priority:** P2
**Status:** TODO

### Problem

- README says links, channels, LXMF are "out of scope" — they're implemented
- README says AES-128-CBC — code uses AES-256
- CLAUDE.md also says AES-128-CBC
- `rete-stack` says `ProveApp` is "not yet handled" — it is handled in `ingest.rs:160-168`

### Key Files

- `README.md:77-101`
- `CLAUDE.md:163-168`
- `crates/rete-stack/src/lib.rs:96-107`

### What to Do

1. **Update README** to reflect actual implemented scope.
2. **Fix AES-128 → AES-256** in README and CLAUDE.md.
3. **Remove "not yet handled" comment** from ProveApp in rete-stack.
4. **Add portability matrix** — which crates work on which targets.

### Done When

- README matches reality
- No stale "not implemented" claims for implemented features
- AES key size is correct everywhere

---

## 12. Linux Example Is a De Facto Daemon

**Priority:** P2 — long-term, not urgent until external users
**Status:** TODO

### Problem

`examples/linux/src/main.rs` is 2000+ lines mixing identity persistence, config loading, interface bring-up, monitoring, IPC, LXMF orchestration, command parsing, and runtime policy. It's a product, not an example.

### Key Files

- `examples/linux/src/main.rs` — the whole file

### What to Do

1. **Extract reusable hosted logic** into `rete-tokio` or a new `rete-daemon` crate.
2. **Keep `examples/linux`** as a thin example demonstrating the library API.
3. **Move config loading, identity persistence, monitoring** into library code.

### Done When

- `examples/linux/src/main.rs` is under 500 lines
- Extracted logic is reusable by other hosted applications
- All interop tests still pass

---

## Design Decision Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-04-02 | No LXMF on ESP32 RNode | RNode is a TNC/radio modem. LXMF lives on the host. `rete-lxmf-core` (no_std codec) suffices for any embedded message formatting. |
| 2026-04-02 | Item ordering: correctness → structure → lifecycle → LXMF → polish | Fix bugs before refactoring. Refactor before adding features. |
| 2026-04-02 | Default `ResourceStrategy::AcceptAll` | Backward compat with existing tests while adding the policy framework. |
| 2026-04-02 | `TransportStorage` trait with explicit associated types (not GATs) | Embedded impl needs different capacities per role (MAX_PATHS vs MAX_LINKS). Explicit types avoid GAT complexity. |
| 2026-04-02 | `hashbrown` for hosted HashMap/HashSet | `no_std + alloc` compatible, already a transitive dependency. Avoids requiring `std` in rete-transport. |
| 2026-04-02 | `hosted` feature flag on rete-transport/rete-stack | Gates `StdStorage` and `HostedNodeCore` behind opt-in feature. Embedded crates never pull in hashbrown. |
| 2026-04-02 | `decrypt_with_identity()` over type split | Identity has `ZeroizeOnDrop` (not `Clone`). Instead of splitting Destination into LocalDestination/DestinationAddress, added method accepting external `&Identity` + ratchet keys. |
| 2026-04-02 | `destination_hash()` as thin wrapper | ~30 call sites only need dest_hash. Kept as convenience delegating to `destination_hashes().0` rather than updating all callers. |
