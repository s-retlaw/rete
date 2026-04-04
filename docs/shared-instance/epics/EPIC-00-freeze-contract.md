# EPIC-00: Freeze Shared-Mode Compatibility Contract

Status: `planned`
Depends on: Architectural review complete
Roadmap: [../ROADMAP.md](../ROADMAP.md)
Tracker: [../TRACKER.md](../TRACKER.md)

## Goal

Freeze the exact shared-mode compatibility contract for the Rust daemon before any shared-instance implementation begins.

## Problem Statement

The repo already has useful pieces of local shared attach behavior, but not a frozen compatibility target. Without a contract freeze, later agents will implement against a mix of memory, partial repo behavior, and guessed Python behavior. That would create a Rust-native daemon, not a real shared-mode `rnsd` replacement.

## Why It Matters

This epic is the gate that prevents the rest of the roadmap from becoming ambiguous. It fixes:

- the reference version/date,
- the exact shared-mode boundary,
- the source-of-truth order,
- and the golden trace set used by later epics.

Every later epic depends on this.

## Compatibility Target

This epic freezes:

- Unix shared attach behavior
- TCP shared attach behavior
- in-scope control/status behavior used by shared-mode clients
- the shared-mode config surface in scope for this roadmap

## Public Interface Changes

Documentation-level commitments only:

- the supported shared-mode daemon contract
- the in-scope config keys
- the golden trace plan
- the accepted shared-mode test matrix

## State Model Changes

None in code. This epic only defines the intended state model boundaries that later epics must implement:

- daemon-owned canonical shared state
- client/session-scoped state
- allowed persistence surface

## Red Tests To Add First

Implementation for this epic starts with capture/probe tooling, so the red-first posture is:

- failing probe that shows stock Python client behavior is not yet frozen in fixtures
- failing contract test harness that expects the golden fixture set and finds it missing

Suggested future test/work files:

- `tests/shared_contract/test_fixture_index.py`
- `tests/shared_contract/test_reference_inventory.py`

## Implementation Plan

1. Pin the upstream compatibility target.
   - Record the exact reference date.
   - Record the exact upstream docs and Python modules in use.
   - Confirm the roadmap is shared-mode only.

2. Freeze the in-scope shared config surface.
   - `share_instance`
   - `instance_name`
   - `shared_instance_type`
   - `shared_instance_port`
   - `instance_control_port`
   - `rpc_key`
   - Any item not adopted must be explicitly recorded as out of scope.

3. Define the required golden trace scenarios.
   - daemon start
   - first client attach
   - second client attach
   - detach
   - reconnect
   - announce propagation
   - encrypted data path
   - control/status query
   - Unix attach
   - TCP attach

4. Create Python probe scripts for the trace scenarios.
   - One daemon launcher path using stock `rnsd`
   - One stock Python client path in shared mode
   - One mixed scenario path for multiple attached clients

5. Define fixture storage and metadata conventions.
   - Use the fixture structure defined in [../contracts/GOLDEN_TRACES.md](../contracts/GOLDEN_TRACES.md).
   - Every capture must include metadata, transcript, and notes.

6. Record unresolved compatibility questions.
   - If upstream docs and code disagree, record the issue and the source.
   - Do not let later epics silently decide around it.

## Green Gates

- Reference inventory doc is complete and cross-linked.
- Scope doc, trace plan, and difference ledger are all present and internally consistent.
- Golden trace scenario list is complete and approved for later capture.
- No unresolved question remains hidden outside `Open Questions` or the contract docs.

## E2E Scenarios

This epic does not implement runtime behavior. Its E2E deliverable is a complete scenario inventory for later capture and validation.

## References

- [../contracts/SCOPE.md](../contracts/SCOPE.md)
- [../contracts/REFERENCE.md](../contracts/REFERENCE.md)
- [../contracts/GOLDEN_TRACES.md](../contracts/GOLDEN_TRACES.md)
- [../contracts/DIFFS.md](../contracts/DIFFS.md)
- <https://reticulum.network/manual/using.html>
- <https://reticulum.network/manual/reference.html>
- <https://github.com/markqvist/Reticulum/blob/master/RNS/Reticulum.py>
- <https://github.com/markqvist/Reticulum/blob/master/RNS/Interfaces/LocalInterface.py>
- <https://github.com/markqvist/Reticulum/blob/master/RNS/Transport.py>
- <https://github.com/markqvist/Reticulum/blob/master/RNS/Utilities/rnsd.py>

## Open Questions

- Exact control-plane request/response set required for v1 parity must be frozen from upstream traces.
- Exact semantics of `instance_control_port` and `rpc_key` in the shared-mode path must be confirmed from the upstream implementation and traces.

## Done Definition

Mark this epic `complete` only when:

- the compatibility reference set is frozen,
- the in-scope shared-mode boundary is explicit,
- the golden trace plan is complete,
- and later epics can implement against named contracts instead of open-ended “match Python” instructions.
