# EPIC-08: Full Shared-Mode E2E Matrix

Status: `planned`
Depends on: `EPIC-07`
Roadmap: [../ROADMAP.md](../ROADMAP.md)
Tracker: [../TRACKER.md](../TRACKER.md)

## Goal

Prove shared-mode parity through a comprehensive stock-Python end-to-end matrix over both Unix and TCP shared attach.

The source of truth for required rows is [../PARITY_TEST_MATRIX.md](../PARITY_TEST_MATRIX.md).

## Problem Statement

Individual epic tests are necessary but not sufficient. Shared-mode replacement is a system-level claim, and it must be proven across the full protocol surface that the daemon exposes to attached Python clients.

Without this epic, parity claims would rest on partial or siloed evidence.

## Why It Matters

This epic is the proof step. It turns the roadmap from “we think the daemon is compatible” into “we have cross-language E2E evidence that it behaves like a shared Reticulum instance.”

## Compatibility Target

This epic covers the full shared-mode compatibility boundary, including:

- Unix shared attach
- TCP shared attach
- one or more stock Python clients
- mixed stock Python and Rust-native clients where useful

## Public Interface Changes

No new public interface is expected. This epic validates the interfaces created by earlier work.

## State Model Changes

No new state model is expected. This epic validates the completed shared-state and control behavior.

## Red Tests To Add First

Suggested first failing tests should be added per scenario category as each area is closed:

- one missing or broken scenario per protocol area
- one missing or broken scenario per attach transport
- one missing or broken scenario per multi-client case

Suggested test files:

- `tests/interop/shared_mode/unix/announce.py`
- `tests/interop/shared_mode/unix/data.py`
- `tests/interop/shared_mode/unix/link.py`
- `tests/interop/shared_mode/unix/request.py`
- `tests/interop/shared_mode/unix/resource_large.py`
- `tests/interop/shared_mode/unix/lxmf_direct.py`
- `tests/interop/shared_mode/tcp/announce.py`
- `tests/interop/shared_mode/tcp/data.py`
- `tests/interop/shared_mode/tcp/link.py`
- `tests/interop/shared_mode/tcp/request.py`
- `tests/interop/shared_mode/tcp/resource_large.py`
- `tests/interop/shared_mode/tcp/lxmf_direct.py`

Before implementation under this epic begins, the corresponding Stage 1 rows in [../PARITY_TEST_MATRIX.md](../PARITY_TEST_MATRIX.md) must exist and have concrete target files.

## Implementation Plan

1. Build the matrix axes.
   - Unix attach
   - TCP attach
   - one stock Python client
   - multiple stock Python clients
   - mixed stock Python + Rust-native client where useful

2. Build the required scenario categories.
   - attach / detach / reconnect
   - announce visibility / path learning
   - encrypted data and proofs
   - link establish / identify / teardown
   - request / response
   - resource transfer
   - LXMF in shared-mode flows in scope
   - daemon restart and reattach
   - concurrency and client churn

3. Ensure every in-scope category has:
   - at least one Unix shared-mode E2E
   - at least one TCP shared-mode E2E
   - at least one stock-Python-driven path

4. Group tests into CI suites from [../TEST_STRATEGY.md](../TEST_STRATEGY.md).

5. Record evidence for every scenario category in the tracker.
   - Record row-level evidence in [../PARITY_TEST_MATRIX.md](../PARITY_TEST_MATRIX.md), not only in the tracker.

## Green Gates

- The required scenario matrix is complete.
- Unix and TCP shared attach both have full in-scope E2E coverage.
- Every in-scope behavior has at least one stock-Python shared-mode E2E.
- CI suite definitions are aligned with the test strategy doc.

## E2E Scenarios

Required matrix:

1. attach / detach / reconnect
2. announce visibility and path learning
3. encrypted data send/receive
4. proof generation and receipt handling
5. link establish / identify / teardown
6. request / response round trip
7. resource transfer
   - small
   - large
   - interrupted
   - corrupted
8. LXMF shared-mode scenarios in scope
9. daemon restart and later client reattach
10. concurrent clients using the same shared instance

Run each scenario where applicable over:

- Unix shared attach
- TCP shared attach

## References

- [../TEST_STRATEGY.md](../TEST_STRATEGY.md)
- [../PARITY_TEST_MATRIX.md](../PARITY_TEST_MATRIX.md)
- [../contracts/GOLDEN_TRACES.md](../contracts/GOLDEN_TRACES.md)
- [../contracts/DIFFS.md](../contracts/DIFFS.md)

## Open Questions

- None. This epic validates the completed shared-mode scope; it should not be used to invent new scope.

## Done Definition

Mark this epic `complete` only when:

- the full required shared-mode E2E matrix exists,
- Unix and TCP shared attach are both covered,
- and the parity claim is backed by green stock-Python E2E evidence.
