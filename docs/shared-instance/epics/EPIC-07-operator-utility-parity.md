# EPIC-07: Utility And Operator Parity

Status: `planned`
Depends on: `EPIC-06`
Roadmap: [../ROADMAP.md](../ROADMAP.md)
Tracker: [../TRACKER.md](../TRACKER.md)

## Goal

Make the Rust daemon operationally usable as an `rnsd` replacement for shared-mode systems, including in-scope utility and operator workflows.

## Problem Statement

A technically compatible shared daemon is still hard to adopt if operators cannot:

- run it predictably as a service,
- diagnose bind/auth/config failures,
- or use the expected utility/status flows against it.

Shared-mode replacement needs operator parity, not just protocol parity.

## Why It Matters

This epic turns the daemon from “compatible in tests” into “usable in deployment.” It also closes the gap between daemon internals and the external operational workflows that existing Reticulum users depend on.

## Compatibility Target

This epic targets:

- in-scope utility compatibility
- operator-visible diagnostics
- service-style deployment flows
- failure-mode visibility for shared-mode operation

## Public Interface Changes

Future supported surfaces introduced or tightened by this epic:

- daemon logs and diagnostics
- in-scope utility/status interoperability
- deployment/service documentation
- failure-mode reporting for shared attach and control configuration

## State Model Changes

No new core state model is expected here. This epic consumes the earlier state/control work and makes it operable.

## Red Tests To Add First

Suggested first failing tests:

- required status/path utility interactions do not work unchanged
- daemon failure modes are not observable enough for operators
- invalid shared-mode startup conditions are not reported clearly

Suggested future test files:

- `tests/interop/shared_mode/unix/control_status.py`
- `tests/interop/shared_mode/tcp/control_status.py`
- `crates/rete-tokio/tests/shared_operator_errors.rs`

## Implementation Plan

1. Freeze the v1 utility set.
   - At minimum, support the shared-mode utility interactions required by the frozen contract.
   - Do not over-scope beyond the shared-mode target.

2. Define operator-visible diagnostics.
   - listener bind failure
   - duplicate instance conflict
   - invalid shared attach mode
   - invalid/missing auth where applicable
   - persistence load/save issues

3. Define deployment-facing daemon behavior.
   - startup readiness signal
   - shutdown completion signal
   - stable exit codes if in scope

4. Add utility compatibility tests.
   - status query
   - path/status query
   - any additional utility flow frozen as required in `EPIC-00`

5. Write operator runbook notes.
   - service start
   - expected logs
   - failure interpretation
   - rollback to Python `rnsd`

## Green Gates

- In-scope utility E2E tests are green.
- Operator-facing failures are deterministic and documented.
- Service/deployment notes exist and match actual daemon behavior.

## E2E Scenarios

Required shared-mode E2E:

- stock Python utility in scope can query the Rust daemon successfully
- invalid auth/config produces predictable failure behavior
- duplicate daemon conflict is visible and recoverable

## References

- [../contracts/REFERENCE.md](../contracts/REFERENCE.md)
- [../contracts/DIFFS.md](../contracts/DIFFS.md)
- <https://github.com/markqvist/Reticulum/blob/master/RNS/Utilities/rnsd.py>
- <https://github.com/markqvist/Reticulum/blob/master/RNS/Utilities/rnstatus.py>
- <https://github.com/markqvist/Reticulum/blob/master/RNS/Utilities/rnpath.py>

## Open Questions

- Exact v1 utility set must be frozen in `EPIC-00`; this epic should not expand it opportunistically.

## Done Definition

Mark this epic `complete` only when:

- the daemon is usable by operators as a shared-mode service,
- required utility flows work against it,
- and failure handling is sufficiently visible for real deployment.
