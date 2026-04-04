# EPIC-09: Soak, Robustness, And Cutover Readiness

Status: `planned`
Depends on: `EPIC-08`
Roadmap: [../ROADMAP.md](../ROADMAP.md)
Tracker: [../TRACKER.md](../TRACKER.md)

## Goal

Validate that the shared-mode daemon is stable enough for real replacement use and provide a concrete cutover and rollback plan from Python `rnsd`.

The source of truth for required rows is [../PARITY_TEST_MATRIX.md](../PARITY_TEST_MATRIX.md).

## Problem Statement

Green E2E tests do not automatically prove operational readiness. A real shared-instance replacement also needs:

- long-run stability,
- resilience to malformed or disrupted attach/control traffic,
- and an operator-safe path to switch systems over and back if needed.

## Why It Matters

This epic is the final risk-reduction stage before claiming the Rust daemon can replace `rnsd` in shared mode on a real host.

## Compatibility Target

This epic validates the completed shared-mode replacement surface under realistic operational conditions.

## Public Interface Changes

No new protocol interface is required here. Expected outputs are:

- soak/robustness evidence
- cutover checklist
- rollback checklist
- known-limits documentation

## State Model Changes

No intentional state-model changes. Any state corruption found here is a bug against earlier epics.

## Red Tests To Add First

Suggested first failing tests:

- long-run attach/churn flow reveals instability
- malformed attach/control traffic is not handled safely
- daemon restart during client churn breaks recovery
- cutover checklist cannot be executed cleanly in a dry run

Suggested future test/work files:

- `tests/interop/shared_mode/unix/soak.py`
- `tests/interop/shared_mode/tcp/soak.py`
- `tests/interop/shared_mode/unix/robustness.py`
- `tests/interop/shared_mode/tcp/robustness.py`
- `docs/shared-instance/CUTOVER_CHECKLIST.md`
- `docs/shared-instance/ROLLBACK_CHECKLIST.md`

## Implementation Plan

1. Define soak workloads.
   - repeated attach/detach
   - repeated announce/data/link activity
   - repeated daemon restart with later reattach
   - concurrent multi-client churn

2. Define robustness workloads.
   - malformed shared attach traffic
   - malformed control requests
   - half-open/disrupted attach connections
   - listener backpressure
   - invalid auth attempts where applicable

3. Record resource and stability evidence.
   - error rates
   - crash-free duration
   - recovery behavior after disruption
   - update Stage 3 row evidence in [../PARITY_TEST_MATRIX.md](../PARITY_TEST_MATRIX.md)

4. Write cutover checklist.
   - how to stop using Python `rnsd`
   - how to start the Rust daemon
   - how to validate attach, announce, data, and utility behavior

5. Write rollback checklist.
   - how to stop the Rust daemon
   - how to re-enable Python `rnsd`
   - how to validate recovery after rollback

## Green Gates

- Soak suites are green for Unix and TCP shared attach.
- Robustness suites are green or any residual accepted limits are documented.
- Cutover and rollback checklists exist and have been dry-run.

## E2E Scenarios

Required final validation:

- long-run Unix shared attach soak
- long-run TCP shared attach soak
- multi-client churn under Unix
- multi-client churn under TCP
- malformed attach/control traffic under Unix
- malformed attach/control traffic under TCP
- cutover dry run from Python `rnsd` to Rust daemon
- rollback dry run from Rust daemon back to Python `rnsd`

## References

- [../TEST_STRATEGY.md](../TEST_STRATEGY.md)
- [../PARITY_TEST_MATRIX.md](../PARITY_TEST_MATRIX.md)
- [../contracts/DIFFS.md](../contracts/DIFFS.md)
- [../ROADMAP.md](../ROADMAP.md)

## Open Questions

- None. This epic should only validate and document readiness, not change scope.

## Done Definition

Mark this epic `complete` only when:

- soak and robustness evidence supports the shared-mode replacement claim,
- cutover and rollback checklists exist and are dry-run validated,
- and any remaining accepted limits are explicitly documented.
