# EPIC-02: Unix Shared-Attach Compatibility

Status: `complete`
Depends on: `EPIC-00`, `EPIC-01`
Roadmap: [../ROADMAP.md](../ROADMAP.md)
Tracker: [../TRACKER.md](../TRACKER.md)

## Goal

Make stock Python shared-mode clients attach unchanged to the Rust daemon over the Unix local shared-attach path.

## Problem Statement

The repo already has a Unix local packet relay surface, but that is not the same as full shared-attach compatibility. The current implementation does not yet prove that:

- stock Python clients can attach unchanged,
- attach/detach behavior matches the upstream contract,
- or the shared attach path is anything more than a Rust-to-Rust packet socket.

## Why It Matters

Unix local shared attach is the default shared-instance path on Unix-like systems. If this epic is not complete, the daemon cannot credibly replace `rnsd` for the most important deployment path.

## Compatibility Target

This epic targets:

- Unix local shared attach
- instance naming behavior
- client attach / detach / reconnect semantics
- stock Python shared-mode client compatibility on Unix

It does not yet freeze the full control plane or canonical shared-state semantics; those are handled later.

## Public Interface Changes

Future supported runtime surfaces introduced or tightened by this epic:

- supported Unix shared listener behavior
- supported instance-name-driven attach path
- supported attach/detach/reconnect logging and diagnostics

## State Model Changes

At this stage, the daemon must track:

- connected shared-attach client sessions
- attach transport state
- listener ownership

Full canonical shared-state routing comes later in `EPIC-05`.

## Red Tests To Add First

Suggested first failing tests:

- stock Python shared-mode client cannot attach to the Rust daemon over Unix
- attach path/naming does not match the frozen contract
- reconnect behavior differs from the frozen contract
- multiple stock Python shared-mode clients cannot attach concurrently over Unix

Suggested future test files:

- `tests/interop/shared_mode/unix/attach_single_client.py`
- `tests/interop/shared_mode/unix/attach_multi_client.py`
- `crates/rete-tokio/tests/shared_unix_attach.rs`

## Implementation Plan

1. Match the Unix attach transport boundary exactly.
   - Use the frozen attach path, naming, and framing rules from `EPIC-00`.
   - Do not assume the current Rust local relay is already correct without fixture comparison.

2. Match client attach semantics.
   - Connection setup
   - initial attach expectations
   - disconnect handling
   - reconnect handling
   - listener-side cleanup

3. Remove Rust-only assumptions.
   - No Rust-native handshake shortcuts
   - No attach behavior that requires Rust-specific client code
   - No packet broadcast semantics that conflict with the frozen Unix attach contract

4. Validate stock Python shared-mode attach.
   - One Python client attach
   - Two Python clients attach
   - Attach while daemon already has active network interfaces

5. Freeze accepted behavior into tests.
   - Attach success
   - detach cleanup
   - reconnect
   - announce/data smoke flows through the attached client

## Green Gates

- Unix attach integration tests pass.
- Stock Python shared-mode Unix attach E2E passes.
- Multi-client Unix attach E2E passes.
- No accepted difference for Unix attach remains unrecorded.

## E2E Scenarios

Required shared-mode E2E:

- daemon starts in Unix shared mode
- first stock Python client attaches unchanged
- second stock Python client attaches unchanged
- one attached client disconnects without breaking the other
- reconnect after disconnect works
- attached Python client can announce through the daemon
- attached Python client can send and receive encrypted data through the daemon

## References

- [../contracts/GOLDEN_TRACES.md](../contracts/GOLDEN_TRACES.md)
- [../contracts/REFERENCE.md](../contracts/REFERENCE.md)
- [../../../crates/rete-tokio/src/local.rs](../../../crates/rete-tokio/src/local.rs)
- <https://reticulum.network/manual/using.html>
- <https://github.com/markqvist/Reticulum/blob/master/RNS/Interfaces/LocalInterface.py>
- <https://github.com/markqvist/Reticulum/blob/master/RNS/Reticulum.py>

## Open Questions

- None, assuming `EPIC-00` freezes the Unix attach contract before implementation starts.

## Done Definition

Mark this epic `complete` only when:

- stock Python shared-mode clients attach unchanged over Unix,
- attach/detach/reconnect behavior matches the frozen contract,
- and the Unix shared attach path is backed by green stock-Python E2E coverage.
