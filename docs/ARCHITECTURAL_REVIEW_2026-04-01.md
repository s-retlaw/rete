# Architectural Review of `rete`

Date: 2026-04-01

## Scope

This review covers:

- Workspace structure and crate boundaries.
- Appropriateness of abstractions and separation of concerns.
- Duplication and consistency.
- Error handling.
- `no_std` and portability boundaries for embedded, desktop, and planned WASM use.
- Idiomatic Rust usage.
- Parity against the Python Reticulum and LXMF references for seamless interoperation.

This document is intentionally implementation-oriented. It is meant to be detailed enough that a follow-up agent can pick it up and execute the refactor plan without redoing the whole analysis.

This review complements [GAP_ANALYSIS.md](../GAP_ANALYSIS.md). That file tracks many protocol and feature deltas directly. This review focuses on the architecture that will make those deltas easier or harder to close cleanly.

## Method

I reviewed the workspace manifests, major crate entry points, and the largest implementation files. I focused especially on:

- `crates/rete-core`
- `crates/rete-transport`
- `crates/rete-stack`
- `crates/rete-lxmf-core`
- `crates/rete-lxmf`
- `crates/rete-tokio`
- `examples/daemon`

I also compared the current Rust surface against the official Reticulum API reference, the Reticulum shared-instance documentation, and the upstream LXMF README:

- <https://reticulum.network/manual/reference.html>
- <https://reticulum.network/manual/using.html>
- <https://github.com/markqvist/LXMF>

## Executive Summary

The project is in a better state than its top-level documentation suggests. The core wire/protocol implementation is already substantial, there is a strong interop suite, and the `rete-core` / `rete-transport` / `rete-stack` split is directionally correct. The project already has real packet, link, channel, resource, runtime, and LXMF code, not just scaffolding.

The main architectural problem is concentration of responsibility. `NodeCore` and `Transport` have grown into large stateful service objects that mix protocol engine logic, application policy, callback wiring, storage choices, diagnostics, and portability concerns. That concentration is now starting to create second-order problems:

- hosted memory sizing is being dictated by embedded storage choices,
- protocol parity gaps are hard to close without adding even more special cases,
- the `no_std` story is only partially reflected in the LXMF layer,
- library APIs do not yet model important Python lifecycle concepts such as request receipts, resource acceptance policies, and full LXMF router behavior.

The highest-priority correctness issue is the resource receive path. The current code can mark a resource complete even when hash verification fails, and it auto-accepts every offered resource. That is the most serious issue in this review because it combines correctness, interoperability, and API design problems.

The second major issue is architecture drift between what the workspace says it is and what it actually is. The README and some crate docs still describe a future plan, while the codebase has already implemented much of it. That drift is large enough that it now actively hides the real architecture from contributors.

## What Is Strong Today

- The crate layering is directionally right. `rete-core` handles packet/crypto primitives, `rete-transport` handles transport state, `rete-stack` bridges toward application/runtime use, and runtime-specific crates are split out in the workspace root ([Cargo.toml](../Cargo.toml):1-77).
- The portable core is real, not aspirational. `rete-core`, `rete-transport`, `rete-stack`, and `rete-lxmf-core` are `#![no_std]` crates, and they all checked successfully for `wasm32-unknown-unknown`. `rete-core`, `rete-transport`, `rete-stack`, and `rete-embassy` also checked successfully for `thumbv6m-none-eabi`.
- Interop coverage is already unusually strong. There are 92 Python interop scenarios under `tests/interop`, including announce, link, channel, proof routing, resource transfer, relay, ESP32, local IPC, monitoring, and LXMF flows.
- Much of the core error handling is already on the right track. `rete_core::Error` and `rete_core::msgpack::MsgpackError` are small, explicit enums with `Display` implementations ([crates/rete-core/src/error.rs](../crates/rete-core/src/error.rs):1-46, [crates/rete-core/src/msgpack.rs](../crates/rete-core/src/msgpack.rs):1-47).
- The current implementation already has meaningful Python parity in request handler registration, link/channel behavior, ratchets, path management, and a fair amount of LXMF behavior. This is not a ground-up prototype anymore.

## Priority Findings

### P0: Resource Receive Semantics Are Incorrect and Under-Modeled

#### Problem

The resource receive path is the most serious issue in the codebase right now.

- Resources are auto-accepted unconditionally in `NodeCore` ([crates/rete-stack/src/node_core/ingest.rs](../crates/rete-stack/src/node_core/ingest.rs):373-397).
- The underlying resource parser and assembler still expose `Result<_, &'static str>` APIs instead of typed errors ([crates/rete-transport/src/resource.rs](../crates/rete-transport/src/resource.rs):636-789, 947-986, 993-1021).
- Most importantly, `Resource::assemble()` marks the resource complete even when the computed resource hash does not match the advertised hash ([crates/rete-transport/src/resource.rs](../crates/rete-transport/src/resource.rs):1008-1020).

The comment says verification is skipped because Python may hash compressed/encrypted payloads differently. That may explain an interop mismatch during development, but it is not an acceptable final architecture. A completed resource must mean "integrity verified according to protocol semantics", not "assembled bytes exist".

#### Why It Matters

- It weakens correctness and safety.
- It makes interop failures ambiguous. A bad transfer can look successful.
- It prevents higher-level APIs from exposing resource state honestly.
- It blocks a clean equivalent of Python's `Resource` lifecycle and callback model.

The official Reticulum reference describes resources as handling sequencing, compression, coordination, and checksumming, and it exposes explicit resource acceptance and resource lifecycle callbacks:

- `Link.set_resource_strategy(...)`
- `Link.set_resource_callback(...)`
- `Link.set_resource_started_callback(...)`
- `Link.set_resource_concluded_callback(...)`
- `RNS.Resource(...)`

Reference: <https://reticulum.network/manual/reference.html>

#### Proposed Change

Refactor the resource path into explicit stages with explicit failure states:

1. Parse advertisement into a typed `ResourceAdvertisement`.
2. Create a `ReceivingResource` state machine from that advertisement.
3. Track acceptance policy separately from parsing.
4. Verify the correct hash at completion time according to the actual protocol boundary.
5. Only transition to `Complete` after verification succeeds.
6. Introduce an explicit `Failed(ResourceError)` terminal state.

Also add a real resource acceptance API at the `NodeCore`/link layer:

- `AcceptNone`
- `AcceptAll`
- `AcceptApp`

If `AcceptApp` is used, the application should be called with a typed summary of the offered resource before the first request is sent.

#### Implementation Notes

- Introduce `ResourceError` in `crates/rete-transport/src/resource.rs`.
- Replace all public `Result<_, &'static str>` resource APIs with `Result<_, ResourceError>`.
- Add a typed `ResourceOffer` or `ResourceAdvertisement` model instead of leaking raw msgpack parsing everywhere.
- Move the "what exactly is hashed" rule into one verifier function and document it in code. Do not let the assembler decide protocol semantics ad hoc.
- Change `NodeCore` so `IngestResult::ResourceOffered` does not automatically cause acceptance. It should emit an event, and acceptance should be explicit or policy-driven.
- Add `NodeEvent` variants for resource rejection/failure if necessary.

Suggested files:

- `crates/rete-transport/src/resource.rs`
- `crates/rete-transport/src/transport/resource.rs`
- `crates/rete-stack/src/node_core/ingest.rs`
- `crates/rete-stack/src/lib.rs`

#### Validation

- Add unit tests for hash mismatch, malformed advertisement, and explicit rejection.
- Add an interop test where Python advertises a resource and Rust declines it.
- Add an interop test that intentionally corrupts a resource part and verifies Rust reports failure instead of completion.

### P1: Storage Architecture Is Forcing Hosted Nodes to Behave Like Big MCUs

#### Problem

The transport core uses a single const-generic storage model for both embedded and hosted targets:

- hosted capacities are defined as 1024 paths / 256 announces / 4096 dedup / 32 links ([crates/rete-transport/src/lib.rs](../crates/rete-transport/src/lib.rs):55-87),
- `Transport` stores many large `heapless` maps and deques directly in the struct ([crates/rete-transport/src/transport/mod.rs](../crates/rete-transport/src/transport/mod.rs):418-460),
- `TokioNode` explicitly documents that `HostedNodeCore` is roughly 600 KB and should often be boxed ([crates/rete-tokio/src/lib.rs](../crates/rete-tokio/src/lib.rs):128-155).

This is a structural smell, not just a tuning issue. The same state layout is serving embedded and hosted targets, even though they have different optimization priorities.

#### Why It Matters

- Desktop/server nodes pay a large memory and stack cost for compile-time fixed storage.
- WASM portability becomes harder because the public "portable" API is still shaped by large fixed in-struct state.
- Future parity work such as request receipts, richer LXMF queues, and better routing state will further bloat already-large structs if this is not addressed first.

#### Proposed Change

Split protocol logic from storage backend.

A practical direction is:

- keep transport/link/resource algorithms in a shared `TransportCore`,
- define a `TransportStorage` trait or backend abstraction,
- provide at least two concrete backends:
  - `heapless` backend for embedded,
  - hosted backend backed by `Vec`, `HashMap`, and standard collections.

If a full trait-based backend is too large a change in one pass, a smaller intermediate step is acceptable:

- separate "algorithm/state machine logic" from "state containers",
- box or heap-allocate the large hosted tables,
- move hosted aliases into a distinct hosted-only facade crate.

#### Implementation Notes

- Start with the biggest tables: path table, known identities, reverse table, dedup, announce rate table, request/receipt state.
- Keep the wire logic and table semantics identical across backends.
- Preserve the current const-generic embedded aliases so existing MCU code does not regress.
- Re-measure `HostedNodeCore` after the split; reducing the "boxed because huge" warning should be an explicit goal.

Suggested files:

- `crates/rete-transport/src/transport/mod.rs`
- `crates/rete-transport/src/lib.rs`
- `crates/rete-stack/src/node_core/mod.rs`
- `crates/rete-tokio/src/lib.rs`

#### Validation

- Re-run embedded checks for `thumbv6m-none-eabi`.
- Re-run WASM checks for `wasm32-unknown-unknown`.
- Add a size-oriented regression test or benchmark for hosted node creation.

### P1: `Destination` and `NodeCore` Do Not Model Local Inbound Destinations Cleanly

#### Problem

`Destination` claims to wrap identity, hashing, encryption mode, and proof strategy into one coherent type, but actual use is split:

- `Destination` stores `identity: Option<Identity>` and provides `encrypt()` / `decrypt()` ([crates/rete-stack/src/destination.rs](../crates/rete-stack/src/destination.rs):44-66, 217-286),
- `NodeCore::new()` creates the primary inbound destination with `Destination::from_hashes(...)`, meaning there is no identity inside that `Destination` ([crates/rete-stack/src/node_core/mod.rs](../crates/rete-stack/src/node_core/mod.rs):286-320),
- the same is true for registered additional destinations ([crates/rete-stack/src/node_core/destination.rs](../crates/rete-stack/src/node_core/destination.rs):18-38, 46-78),
- inbound decryption for `DestinationType::Single` is then special-cased in `NodeCore::ingest()` to use `self.identity` directly instead of the destination abstraction ([crates/rete-stack/src/node_core/ingest.rs](../crates/rete-stack/src/node_core/ingest.rs):121-156).

That is a leaky abstraction. The type says one thing and the runtime behavior says another.

There is also direct duplication in destination hashing logic:

- `Destination::new()` computes expanded name, `name_hash`, and `dest_hash` itself ([crates/rete-stack/src/destination.rs](../crates/rete-stack/src/destination.rs):101-127),
- `compute_dest_hashes()` duplicates the same operation ([crates/rete-stack/src/node_core/mod.rs](../crates/rete-stack/src/node_core/mod.rs):266-284),
- `register_destination_typed()` duplicates it again inline ([crates/rete-stack/src/node_core/destination.rs](../crates/rete-stack/src/node_core/destination.rs):53-69).

#### Why It Matters

- It makes inbound destination behavior harder to reason about.
- It increases the chance of drift between primary and secondary destination behavior.
- It makes future support for group/plain/outbound/local-service destinations harder to extend cleanly.

#### Proposed Change

Split "address metadata" from "local crypto context".

One clean design would be:

- `DestinationAddress`: app name, aspects, `dest_hash`, `name_hash`, direction, destination type.
- `LocalDestination`: `DestinationAddress` plus local receive/decrypt/proof/request-handler capabilities.
- `PeerDestination` or `RemoteDestination`: `DestinationAddress` plus remote send/encrypt capabilities.

At minimum, inbound `Single` destinations should not exist in a half-configured state where decryption depends on `NodeCore` bypassing the destination API.

Also centralize destination hashing in one place, ideally in `rete-core`.

#### Implementation Notes

- Remove or narrow `Destination::from_hashes()`. If it survives, restrict it to address-only/outbound-only use.
- Make the primary destination and additional inbound destinations use the same construction path.
- Move destination hash/name hash computation into a single helper and reuse it everywhere.
- Revisit whether `Identity` should be copied into destinations at all, or whether a dedicated local-crypto handle is the right abstraction.

Suggested files:

- `crates/rete-stack/src/destination.rs`
- `crates/rete-stack/src/node_core/mod.rs`
- `crates/rete-stack/src/node_core/destination.rs`
- possibly `crates/rete-core/src/identity.rs`

#### Validation

- Ensure all inbound destination types decrypt through the destination abstraction instead of `NodeCore` special cases.
- Add tests covering primary and secondary inbound destinations through the same path.

### P1: Python Request/Resource Lifecycle Parity Is Still Partial

#### Problem

The Rust implementation has reasonable wire-level support for requests and responses, and it has server-side handler dispatch:

- `RequestContext`, `RequestPolicy`, and request handlers exist in `NodeCore` ([crates/rete-stack/src/node_core/mod.rs](../crates/rete-stack/src/node_core/mod.rs):38-131),
- handler dispatch exists in ingest ([crates/rete-stack/src/node_core/ingest.rs](../crates/rete-stack/src/node_core/ingest.rs):278-340).

But the client-side lifecycle is still under-modeled:

- `send_request()` returns only `(OutboundPacket, request_id)` ([crates/rete-stack/src/node_core/mod.rs](../crates/rete-stack/src/node_core/mod.rs):565-592),
- there is no Rust equivalent of a `RequestReceipt`,
- there is no tracked request status machine,
- there is no progress/failure callback model,
- there is no request timeout behavior exposed at the API level.

The Python reference explicitly exposes:

- `Link.request(path, data=None, response_callback=None, failed_callback=None, progress_callback=None, timeout=None)`
- `RNS.RequestReceipt`

Reference: <https://reticulum.network/manual/reference.html>

Resource lifecycle parity has a similar gap. The Python API exposes resource strategy and resource callbacks as first-class concepts; the Rust stack does not.

#### Why It Matters

- Wire interoperability can pass while the application model is still incomplete.
- Upstream-compatible application ports will be awkward or impossible.
- Higher-level components such as LXMF will keep reimplementing missing lifecycle state internally.

#### Proposed Change

Introduce explicit lifecycle models in the stack layer:

- `RequestReceipt`
- `RequestStatus`
- `PendingRequest`
- `ResourceStrategy`
- `ResourceTransferState`

There are two reasonable implementation directions:

- low-level: expose a pollable lifecycle manager in `NodeCore`/`Transport`,
- high-level: add a hosted application facade that provides callback-driven semantics above the low-level core.

I recommend doing both in layers:

1. typed low-level state in `NodeCore` / `Transport`,
2. optional higher-level API that maps closely to Python ergonomics.

#### Implementation Notes

- Keep request IDs as transport-level identifiers, but track request metadata and timeouts in one place.
- Decide whether multi-packet responses are modeled as resources under the same request receipt or as a separate linked state machine. Do not let this stay implicit.
- Resource acceptance policy should live near link state, not as ad hoc behavior in `NodeCore::ingest()`.

Suggested files:

- `crates/rete-stack/src/node_core/mod.rs`
- `crates/rete-stack/src/node_core/ingest.rs`
- `crates/rete-transport/src/transport/link.rs`
- `crates/rete-transport/src/transport/resource.rs`

#### Validation

- Add Rust-side tests for request timeout, request failure, request progress, and response completion.
- Add interop tests that exercise Python-side `failed_callback` and resource acceptance strategy against the Rust node.

### P1: `LxmfRouter` Is Narrower Than the Upstream `LXMRouter`

#### Problem

The current `rete-lxmf` router has useful building blocks, but its public role is narrower than the name suggests.

What exists today:

- `LXMessage` pack/unpack/sign/verify is implemented in `rete-lxmf-core`.
- `LxmfRouter` registers `lxmf.delivery`, handles some delivery/propgation flows, and provides opportunistic/direct send helpers ([crates/rete-lxmf/src/router/mod.rs](../crates/rete-lxmf/src/router/mod.rs):188-321, [crates/rete-lxmf/src/router/delivery.rs](../crates/rete-lxmf/src/router/delivery.rs):15-100).

What is missing from the architecture:

- a first-class outbound queue,
- delivery receipt tracking,
- retry and failure notification behavior,
- a single high-level "handle outbound message" workflow,
- clear integration of stamp/ticket policy into routing decisions.

The upstream LXMF README describes `LXMRouter` as handling "delivery receipts, outbound and inbound queues" and "path lookup, routing, retries and failure notifications". It also describes it as the primary API surface for applications:

- `lxm_router = LXMF.LXMRouter()`
- `lxm_router.handle_outbound(message)`

Reference: <https://github.com/markqvist/LXMF>

The current Rust router does not yet meet that contract.

There is also an internal split that has not been completed architecturally:

- stamp and ticket primitives exist in `rete-lxmf-core` ([crates/rete-lxmf-core/src/stamp.rs](../crates/rete-lxmf-core/src/stamp.rs):1-139),
- router announce helpers hardcode stamp cost 0 ([crates/rete-lxmf/src/router/mod.rs](../crates/rete-lxmf/src/router/mod.rs):285-299),
- search results show no meaningful stamp/ticket integration outside tests and data structures.

#### Why It Matters

- Ports of real LXMF applications will keep needing their own orchestration layer on top of `rete-lxmf`.
- Message delivery semantics will drift away from upstream expectations even if packet formats match.
- The current router name risks overpromising to users.

#### Proposed Change

Restructure LXMF into two explicit layers:

1. `rete-lxmf-core`
   - pure message/stamp codecs,
   - `no_std` + `alloc`,
   - no transport orchestration.
2. router layer
   - outbound queue,
   - delivery attempts and retries,
   - receipt/failure state,
   - propagation-node interaction,
   - stamp policy and ticket cache,
   - app-facing API such as `handle_outbound()`, `poll()`, or hosted async equivalents.

Also split the router module by concern. The current `router/mod.rs` is close to 2,000 lines and is already carrying too much.

#### Implementation Notes

- Introduce an `LxmfOutboundMessage` or `QueuedLxmfMessage` model with explicit status.
- Decide whether direct and opportunistic delivery are strategy choices on one queue item or separate job types.
- Reuse the existing propagation and peer logic, but move it behind a clearer state machine.
- Integrate non-zero stamp cost and ticket bypass into announce parsing, delivery decisions, and propagation-node logic.

Suggested files:

- `crates/rete-lxmf/src/router/mod.rs`
- `crates/rete-lxmf/src/router/delivery.rs`
- `crates/rete-lxmf/src/router/peering.rs`
- `crates/rete-lxmf/src/peer.rs`
- `crates/rete-lxmf/src/propagation.rs`
- `crates/rete-lxmf-core/src/stamp.rs`

#### Validation

- Add tests for queued retry, failure transition, and receipt completion.
- Add interop scenarios for non-zero stamp cost and ticket-based delivery.

### P1: The Portable LXMF Boundary Is Only Half-Finished

#### Problem

`rete-lxmf-core` is `#![no_std]`, which is correct for a portable message codec. But the `rete-lxmf` facade currently breaks that boundary:

- `crates/rete-lxmf/Cargo.toml` enables `sha2` with `features = ["std"]` ([crates/rete-lxmf/Cargo.toml](../crates/rete-lxmf/Cargo.toml):9-20),
- `crates/rete-lxmf/src/lib.rs` is not `#![no_std]` ([crates/rete-lxmf/src/lib.rs](../crates/rete-lxmf/src/lib.rs):1-31),
- `cargo check -p rete-lxmf --no-default-features --target thumbv6m-none-eabi` currently fails because the crate still requires `std`.

By contrast:

- `cargo check -p rete-core -p rete-transport -p rete-stack -p rete-lxmf-core --target wasm32-unknown-unknown` passed,
- `cargo check -p rete-lxmf --no-default-features --target wasm32-unknown-unknown` passed,
- `cargo check -p rete-lxmf --no-default-features --target thumbv6m-none-eabi` failed.

That means the actual portable contract today is "use `rete-lxmf-core` directly", not "use `rete-lxmf` without router features".

#### Why It Matters

- It muddies the WASM and embedded story.
- It creates avoidable confusion about which crate is safe to depend on from `no_std`.
- It will make future browser/WASM work harder if the facade crate is not cleaned up now.

#### Proposed Change

Make the layering explicit and honest:

- `rete-lxmf-core`: portable message/stamp crate.
- `rete-lxmf`:
  - either becomes `#![no_std]` + `alloc` with all hosted/router features gated,
  - or is split into `rete-lxmf-core` + `rete-lxmf-router` and no longer pretends to be portable.

I recommend the second option. It is clearer.

#### Implementation Notes

- Remove `std`-only dependencies from the portable facade.
- Gate compression and hosted integrations behind explicit features.
- Update README and crate docs to tell users exactly which crate to use on MCU, WASM, and hosted targets.

Suggested files:

- `crates/rete-lxmf/Cargo.toml`
- `crates/rete-lxmf/src/lib.rs`
- workspace docs

#### Validation

- `cargo check -p rete-lxmf --no-default-features --target thumbv6m-none-eabi`
- `cargo check -p rete-lxmf --no-default-features --target wasm32-unknown-unknown`

### P2: Error Handling Is Still Split Between Typed and Stringly APIs

#### Problem

The codebase has partially migrated to good typed errors, but the migration is incomplete.

Good examples:

- `rete_core::Error` ([crates/rete-core/src/error.rs](../crates/rete-core/src/error.rs):1-46)
- `rete_core::msgpack::MsgpackError` ([crates/rete-core/src/msgpack.rs](../crates/rete-core/src/msgpack.rs):1-47)

Problem areas:

- `rete-transport::resource` still returns `&'static str` in multiple public functions ([crates/rete-transport/src/resource.rs](../crates/rete-transport/src/resource.rs):636-789, 947-986, 993-1021),
- `rete-lxmf-core::message` still returns `&'static str` ([crates/rete-lxmf-core/src/message.rs](../crates/rete-lxmf-core/src/message.rs):104-133, 151-187),
- `MsgpackError::as_str()` exists as a backward-compatibility bridge for older stringly callers ([crates/rete-core/src/msgpack.rs](../crates/rete-core/src/msgpack.rs):27-40),
- `Destination::new()` uses `Error::MissingField("Plain destinations must not have an identity")`, which is semantically the wrong error variant for that condition ([crates/rete-stack/src/destination.rs](../crates/rete-stack/src/destination.rs):82-99).

There are also library-level `expect()` calls that should be removed from public API paths, for example LXMF destination registration ([crates/rete-lxmf/src/router/mod.rs](../crates/rete-lxmf/src/router/mod.rs):241-250).

#### Why It Matters

- String errors make recovery behavior weak and inconsistent.
- Hosted applications, WASM bindings, and diagnostic tooling need structured failures.
- Inconsistent error vocabulary makes the architecture harder to extend coherently.

#### Proposed Change

Move to per-module typed error enums with `From` conversions:

- `ResourceError`
- `LxmfMessageError`
- destination construction errors separate from packet/crypto errors

Do not reuse `rete_core::Error` for every invalid state in higher layers. Higher layers need their own vocabulary.

#### Implementation Notes

- Keep `core` errors small and protocol-focused.
- Add `From<MsgpackError>` where appropriate.
- Remove `as_str()` callers as part of the migration.
- Replace `expect()` in public registration/build paths with typed errors.

#### Validation

- Unit tests should assert on specific error variants, not messages.

### P2: Callback/Hooks Are Too Narrow for Real Applications

#### Problem

Several extension points are plain function pointers:

- `TransformFn = fn(&[u8]) -> Option<Vec<u8>>`
- `ProveAppFn = fn(&[u8; TRUNCATED_HASH_LEN], &[u8; 32], &[u8]) -> bool`
- `RequestHandlerFn = fn(&RequestContext<'_>, &[u8]) -> Option<Vec<u8>>`

See [crates/rete-stack/src/node_core/mod.rs](../crates/rete-stack/src/node_core/mod.rs):29-60 and the `RequestHandler` struct at 120-131.

This is significantly narrower than both idiomatic Rust and the upstream Python callback model:

- stateful callbacks cannot capture environment,
- applications are pushed toward globals or side channels,
- `NodeCore` itself ends up carrying more application-specific state because hooks cannot.

#### Why It Matters

- It limits how ergonomic the library can be for hosted applications.
- It makes policy injection awkward.
- It encourages more growth inside `NodeCore`, which is already overloaded.

#### Proposed Change

Introduce a hook trait or builder-owned service object.

For example:

- `NodeHooks` trait with default no-op methods,
- `CompressionProvider`,
- `ProofPolicy`,
- `ResourcePolicy`,
- `RequestDispatcher`.

That preserves `no_std` viability while allowing richer hosted implementations.

If dynamic dispatch is used, keep it behind `alloc` and make it optional. If generic hooks are used, keep defaults ergonomic.

#### Implementation Notes

- Start by replacing the three function-pointer hooks with one grouped abstraction.
- Do not try to make `NodeCore` generic over many unrelated function types. Use a single service trait or trait object.

#### Validation

- Add at least one unit test using a stateful request handler or policy object.

### P2: The Type System Is Underused for Hashes and Identifiers

#### Problem

The same raw array types are used for multiple semantically distinct identifiers:

- destination hash,
- identity hash,
- link ID,
- request ID,
- path hash.

`RequestContext` alone contains several different `[u8; TRUNCATED_HASH_LEN]` fields ([crates/rete-stack/src/node_core/mod.rs](../crates/rete-stack/src/node_core/mod.rs):38-54). The transport layer does the same throughout its maps and APIs.

#### Why It Matters

- It makes accidental mixups easier.
- It leaves correctness that Rust could check to comments and naming discipline.

#### Proposed Change

Introduce small newtypes in `rete-core`:

- `DestHash`
- `IdentityHash`
- `LinkId`
- `RequestId`
- `PathHash`

This is not a cosmetic change. It would materially improve API clarity and reduce class-of-bug risk in a codebase this protocol-heavy.

#### Implementation Notes

- Implement `Copy`, `Clone`, `Eq`, `Hash`, and `AsRef<[u8]>`.
- Do this after the bigger refactors above, because it will touch many signatures.

### P2: Documentation and Crate Narratives Are Significantly Out of Date

#### Problem

Top-level documentation still describes large parts of the implemented system as future work:

- the README says `rete-transport`, `rete-stack`, `rete-embassy`, `rete-tokio`, TCP, KISS, links/channels, and LXMF are planned or out of scope ([README.md](../README.md):88-101),
- the README still says encryption is `AES-128-CBC` ([README.md](../README.md):77-86), while the code and the Reticulum API reference both use AES-256 for packet/group encryption ([crates/rete-core/src/identity.rs](../crates/rete-core/src/identity.rs):33-45, [crates/rete-core/src/token.rs](../crates/rete-core/src/token.rs):1-23, and <https://reticulum.network/manual/reference.html>),
- `rete-stack` still documents `ProofStrategy::ProveApp` as "not yet handled by NodeCore" even though ingest handles it ([crates/rete-stack/src/lib.rs](../crates/rete-stack/src/lib.rs):96-107, [crates/rete-stack/src/node_core/ingest.rs](../crates/rete-stack/src/node_core/ingest.rs):160-168),
- `CLAUDE.md` also still refers to AES-128-CBC ([CLAUDE.md](../CLAUDE.md):163-168).

#### Why It Matters

- New contributors will build the wrong mental model.
- Refactor work will get duplicated because the current architecture is poorly documented.
- It reduces trust in the repo's own guidance.

#### Proposed Change

Treat documentation alignment as part of the architecture work, not cleanup.

At minimum:

- update the README to reflect the real implemented scope,
- document crate roles truthfully,
- document the supported portability matrix,
- document which Python API concepts already map cleanly and which are still partial.

### P2: The Hosted/Desktop Surface Lives Mostly in a Huge Example

#### Problem

`examples/daemon/src/main.rs` is over 2,000 lines and mixes:

- identity persistence,
- config loading,
- interface bring-up,
- monitoring,
- IPC,
- LXMF orchestration,
- command parsing,
- runtime policy.

This example has become a de facto product surface.

At the same time, the Python reference exposes a clear hosted model around `RNS.Reticulum(...)` and shared-instance behavior on the local system:

- exactly one instance per process,
- local processes transparently share a master instance,
- configured interfaces are opened by the master/shared instance.

References:

- <https://reticulum.network/manual/reference.html>
- <https://reticulum.network/manual/using.html>

The Rust code has pieces of this in `rete-tokio` and the Linux example, but not as a clearly supported hosted API or daemon package.

#### Why It Matters

- Hosted adoption will otherwise be driven by copying example code.
- The example file is already too large to be a stable integration boundary.

#### Proposed Change

Promote the hosted application surface into a supported crate or binary:

- `rete-daemon` or similar for the shared instance / IPC / monitoring story,
- keep `examples/daemon` as a thin example on top of that,
- make `rete-tokio` about runtime harnessing, not about also being the deployment surface.

This is especially important if seamless interaction with Python Reticulum processes on desktop is a real goal.

## Python Reference Parity Assessment

### Areas That Are Already Strong

- Packet parsing/building and core crypto are in good shape.
- Announce handling and much of link establishment behavior are implemented.
- Channel support exists and already has real tests.
- Request handler registration and dispatch exist.
- LXMF message codec parity is reasonably strong.
- The interop suite breadth is already a major asset.

### Areas That Are Partial

- Request lifecycle parity:
  - wire format yes,
  - application-facing `RequestReceipt` semantics no.
- Resource lifecycle parity:
  - transfer mechanics exist,
  - acceptance policy and integrity modeling are incomplete.
- Hosted/shared-instance parity:
  - there is IPC/server functionality,
  - but not yet a clean `RNS.Reticulum` equivalent.
- LXMF router parity:
  - direct/opportunistic/propgation pieces exist,
  - but not the full upstream `LXMRouter` lifecycle contract.
- Stamp/ticket parity:
  - primitives exist,
  - policy integration does not.

### Conclusion on Interop

At the packet and transport level, the project is much closer to seamless Python interaction than the README suggests.

At the application model level, it is not yet seamless. The main gaps are not raw byte compatibility anymore; they are missing or under-modeled lifecycle APIs and hosted orchestration behavior.

That distinction is important. The current codebase is already beyond "can it interoperate?" and into "can it present an application contract that matches upstream expectations without each app reassembling the missing pieces itself?"

## Recommended Refactor Sequence

### Phase 1: Correctness and Boundary Cleanup

- Fix resource verification and acceptance semantics.
- Introduce typed resource/LXMF errors.
- Remove library `expect()` calls from public paths.
- Update README and crate docs so contributors stop working from stale assumptions.

### Phase 2: Storage and Core Abstractions

- Split transport logic from storage backend.
- Reduce hosted `NodeCore` footprint.
- Clean up destination/address/crypto modeling.

### Phase 3: Lifecycle APIs

- Add request receipt and pending request state.
- Add resource strategy and lifecycle callbacks/policies.
- Add stronger typed IDs/newtypes where it helps the refactor.

### Phase 4: LXMF Architecture

- Split portable LXMF core from router orchestration cleanly.
- Add queued outbound/inbound router behavior.
- Integrate stamps/tickets into real routing policy.

### Phase 5: Hosted Product Surface

- Extract a supported daemon/shared-instance layer from the Linux example.
- Keep examples thin.
- Align the hosted story with the upstream Reticulum mental model.

## Verification Performed

Commands run locally:

```bash
cargo test --workspace
cargo check -p rete-core -p rete-transport -p rete-stack -p rete-lxmf-core --target wasm32-unknown-unknown
cargo check -p rete-core -p rete-transport -p rete-stack -p rete-lxmf-core -p rete-embassy --target thumbv6m-none-eabi
cargo check -p rete-lxmf --no-default-features --target wasm32-unknown-unknown
cargo check -p rete-lxmf --no-default-features --target thumbv6m-none-eabi
```

Results:

- `cargo check` for the portable core crates passed on `wasm32-unknown-unknown`.
- `cargo check` for `rete-core`, `rete-transport`, `rete-stack`, `rete-lxmf-core`, and `rete-embassy` passed on `thumbv6m-none-eabi`.
- `cargo check -p rete-lxmf --no-default-features --target wasm32-unknown-unknown` passed.
- `cargo check -p rete-lxmf --no-default-features --target thumbv6m-none-eabi` failed because `rete-lxmf` still pulls in `std`.
- `cargo test --workspace` passed for the core, transport, stack, embassy, LXMF, example-linux, and interface crates.
- `cargo test --workspace` failed in `rete-tokio` local IPC and TCP server tests with `PermissionDenied` / `Operation not permitted` when creating local sockets or listeners in this sandbox. The failing tests were:
  - `local::tests::test_local_broadcast_to_clients`
  - `local::tests::test_local_client_connect_disconnect`
  - `local::tests::test_local_client_disconnect_cleanup`
  - `local::tests::test_local_client_to_client_relay`
  - `local::tests::test_local_packet_relay_to_node`
  - `local::tests::test_local_reteinterface_send_recv`
  - `tcp_server::tests::test_tcp_server_accept_and_relay`
  - `tcp_server::tests::test_tcp_server_broadcast_from_node`
  - `tcp_server::tests::test_tcp_server_disconnect_cleanup`
  - `tcp_server::tests::test_tcp_server_max_clients`

I do not read those failures as evidence of protocol bugs. They are consistent with sandbox restrictions around local socket operations.

## Bottom Line

The project already has enough implementation depth that the next round of work should optimize for architectural coherence, not just feature accumulation.

If I were sequencing actual engineering work, I would do it in this order:

1. Fix resource correctness and acceptance semantics.
2. Separate transport logic from storage sizing so hosted, embedded, and WASM can evolve cleanly.
3. Introduce real lifecycle APIs for requests/resources.
4. Rebuild the LXMF router around an explicit queue/receipt/retry model.
5. Extract a supported hosted/shared-instance product surface from the example.

That sequence gives the best chance of preserving current interop while making the codebase easier to extend in an idiomatic Rust direction.
