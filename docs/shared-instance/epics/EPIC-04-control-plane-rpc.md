# EPIC-04: Shared Control Plane And RPC Compatibility

Status: `planned`
Depends on: `EPIC-02`, `EPIC-03`
Roadmap: [../ROADMAP.md](../ROADMAP.md)
Tracker: [../TRACKER.md](../TRACKER.md)

## Goal

Implement the in-scope shared control/status compatibility surface that stock Python shared-mode clients and utilities depend on.

## Problem Statement

Packet attach alone is insufficient for a real shared-instance replacement. Shared-mode clients and utilities depend on control/status behavior as well. If the Rust daemon only provides attach and packet relay, then stock Python shared-mode clients may connect but still fail on status, session, or control interactions.

## Why It Matters

This epic is the boundary between “attachable daemon” and “real shared-instance host.” It makes the daemon usable by the Python-side ecosystem instead of only by raw packet clients.

## Compatibility Target

This epic targets:

- the in-scope shared control plane frozen in `EPIC-00`
- request/response behavior required by shared-mode clients
- status/control behavior needed by in-scope utilities
- any auth requirements tied to `rpc_key`

## Public Interface Changes

Future supported daemon surfaces introduced or tightened by this epic:

- shared control-plane service
- request/response handling for in-scope control operations
- auth behavior where the frozen contract requires it
- status/control compatibility surfaced to stock Python clients and utilities

## State Model Changes

The daemon must add:

- control-plane session tracking
- request correlation for control operations
- auth/permission state where the frozen contract requires it
- separation between packet plane and control plane

## Red Tests To Add First

Suggested first failing tests:

- in-scope control/status requests captured from the Python reference fail against the Rust daemon
- utility-style status queries cannot succeed unchanged
- `rpc_key`-guarded control requests are accepted/rejected incorrectly

Suggested future test files:

- `tests/interop/shared_mode/unix/control_status.py`
- `tests/interop/shared_mode/tcp/control_status.py`
- `crates/rete-tokio/tests/shared_control.rs`

## Implementation Plan

1. Freeze the in-scope control operation set from `EPIC-00`.
   - Only implement the operations required for shared-mode parity v1.
   - Record anything deferred in [../contracts/DIFFS.md](../contracts/DIFFS.md).

2. Separate packet plane from control plane.
   - Attach transport handling must not implicitly become the control implementation.
   - Control requests need explicit parsing, validation, handling, and response shaping.

3. Implement request/response compatibility.
   - Match the frozen request shape.
   - Match the frozen response shape.
   - Match error handling semantics closely enough for stock Python clients/utilities.

4. Implement auth behavior where applicable.
   - Honor `rpc_key` exactly where the frozen contract requires it.
   - Reject missing/invalid auth deterministically and observably.

5. Validate with stock Python-side consumers.
   - shared-mode clients in normal attach flows
   - status/control utilities in scope for v1

## Green Gates

- Control-plane integration tests pass.
- In-scope status/control Python E2E passes over Unix and TCP where applicable.
- Any accepted divergence is explicitly logged in [../contracts/DIFFS.md](../contracts/DIFFS.md).

## E2E Scenarios

Required shared-mode E2E:

- attached stock Python client completes required in-scope control interactions
- status query works against the Rust daemon in Unix mode
- status query works against the Rust daemon in TCP mode
- invalid auth fails predictably where `rpc_key` applies

## References

- [../contracts/REFERENCE.md](../contracts/REFERENCE.md)
- [../contracts/GOLDEN_TRACES.md](../contracts/GOLDEN_TRACES.md)
- [../contracts/DIFFS.md](../contracts/DIFFS.md)
- <https://reticulum.network/manual/using.html>
- <https://reticulum.network/manual/reference.html>
- <https://github.com/markqvist/Reticulum/blob/master/RNS/Reticulum.py>
- <https://github.com/markqvist/Reticulum/blob/master/RNS/Utilities/rnsd.py>
- <https://github.com/markqvist/Reticulum/blob/master/RNS/Utilities/rnstatus.py>
- <https://github.com/markqvist/Reticulum/blob/master/RNS/Utilities/rnpath.py>

## Open Questions

- Exact minimum v1 utility set must be frozen in `EPIC-00` and then treated as fixed for this epic.

## Done Definition

Mark this epic `complete` only when:

- the in-scope control/status surface is implemented,
- stock Python shared-mode clients and required utilities can use it unchanged,
- and control/status parity is backed by green shared-mode E2E coverage.
