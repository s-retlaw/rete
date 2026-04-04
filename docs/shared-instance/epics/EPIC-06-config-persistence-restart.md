# EPIC-06: Config, Persistence, And Restart Compatibility

Status: `planned`
Depends on: `EPIC-05`
Roadmap: [../ROADMAP.md](../ROADMAP.md)
Tracker: [../TRACKER.md](../TRACKER.md)

## Goal

Make the shared-instance daemon stable across normal deployment flows: config parsing, persistence, restart, reattach, and multi-instance behavior.

## Problem Statement

Even if attach and shared-state semantics work, the daemon is not a real `rnsd` replacement unless it behaves predictably across:

- config-driven startup,
- persisted shared daemon state,
- restart and later client reattach,
- and multiple daemon instances identified by name or port.

## Why It Matters

Shared-instance replacement is an operational promise, not just a protocol promise. This epic makes the daemon viable as a real service instead of a lab-only process.

## Compatibility Target

This epic targets:

- the in-scope shared-mode config surface
- daemon-owned persistence behavior in scope
- restart behavior for shared-mode clients
- instance naming and multi-instance isolation

## Public Interface Changes

Future supported surfaces introduced or tightened by this epic:

- shared-mode config loading and validation
- shared-instance data-dir behavior
- daemon restart behavior
- multi-instance selection by name or port

## State Model Changes

This epic defines what the daemon must persist and restore for shared mode.

Planned persistence categories:

- daemon identity and configuration state in scope
- shared transport state that is meant to survive restart
- control/session-independent state that belongs to the shared instance

Not in scope:

- standalone Python local process state
- any persistence model that requires replacing Python in-process behavior

## Red Tests To Add First

Suggested first failing tests:

- daemon restart loses required shared state
- later client reattach after restart fails or behaves incorrectly
- multiple configured instances interfere with each other
- shared-mode config validation accepts invalid combinations or rejects valid ones

Suggested future test files:

- `crates/rete-tokio/tests/shared_restart.rs`
- `tests/interop/shared_mode/unix/restart.py`
- `tests/interop/shared_mode/tcp/restart.py`

## Implementation Plan

1. Freeze the in-scope shared-mode config contract.
   - Only implement config semantics frozen by `EPIC-00`.
   - Document any non-adopted settings as out of scope.

2. Define config precedence for the daemon.
   - Config file
   - CLI overrides if supported
   - data-dir defaults
   - invalid combinations must fail deterministically

3. Define persistence boundaries.
   - What daemon-owned state must survive restart
   - What session-scoped state must not
   - What is rebuilt on boot vs restored

4. Define restart behavior.
   - clean shutdown and restart
   - crash-recovery expectations if supported
   - later client reattach expectations

5. Define multi-instance behavior.
   - instance-name separation for Unix attach
   - port separation for TCP shared attach
   - data-dir separation and error reporting for conflicts

## Green Gates

- Shared config validation tests pass.
- Restart and reattach tests pass for Unix and TCP shared attach.
- Multi-instance isolation tests pass.
- Required persistence evidence exists and is linked in the tracker.

## E2E Scenarios

Required shared-mode E2E:

- daemon starts from config in Unix mode and survives client attach/detach
- daemon starts from config in TCP mode and survives client attach/detach
- daemon restarts and a stock Python shared-mode client reattaches successfully
- two shared instances configured separately do not interfere with each other

## References

- [../contracts/SCOPE.md](../contracts/SCOPE.md)
- [../contracts/REFERENCE.md](../contracts/REFERENCE.md)
- [../../ARCHITECTURAL_REVIEW_2026-04-01.md](../../ARCHITECTURAL_REVIEW_2026-04-01.md)
- [../../../examples/linux/src/main.rs](../../../examples/linux/src/main.rs)
- <https://reticulum.network/manual/using.html>
- <https://github.com/markqvist/Reticulum/blob/master/RNS/Reticulum.py>
- <https://github.com/markqvist/Reticulum/blob/master/RNS/Utilities/rnsd.py>

## Open Questions

- Exact restart semantics for any in-scope control-plane state must be frozen in `EPIC-00` if not explicit in the docs.

## Done Definition

Mark this epic `complete` only when:

- shared-mode config behavior is explicit and tested,
- restart and reattach flows are stable,
- required daemon-owned state survives restart,
- and multi-instance behavior is deterministic and isolated.
