# EPIC-01: Real Shared-Instance Daemon Surface

Status: `planned`
Depends on: `EPIC-00`
Roadmap: [../ROADMAP.md](../ROADMAP.md)
Tracker: [../TRACKER.md](../TRACKER.md)

## Goal

Create a supported Rust daemon surface that owns one canonical hosted node and can run as the system shared instance, instead of relying on example-only hosted logic.

## Problem Statement

The current hosted/shared behavior mostly lives in the Linux example and supporting runtime pieces. That is insufficient for a credible shared-instance replacement because:

- the example is not a supported daemon surface,
- daemon lifecycle and exclusivity rules are not defined,
- and the hosted node ownership model is not clearly separated from test/demo logic.

## Why It Matters

Every later shared-mode epic needs a stable daemon host surface. Without it, shared attach work would be layered onto example-specific behavior that is already identified as architectural debt in the prerequisite review.

## Compatibility Target

This epic targets the daemon host surface itself:

- one shared instance per configured instance identity/name
- daemon-first lifecycle
- listener ownership for shared attach
- daemon-owned canonical hosted node

It does not yet require stock Python clients to attach successfully. That comes in later epics.

## Public Interface Changes

Future supported daemon/runtime surfaces to introduce:

- a dedicated daemon entrypoint or supported daemon mode
- explicit shared-instance config parsing for:
  - `instance_name`
  - `shared_instance_type`
  - `shared_instance_port`
  - `instance_control_port`
  - `rpc_key`
- explicit daemon logging and shutdown behavior

## State Model Changes

The daemon must be the owner of:

- the canonical hosted node core
- the shared attach listeners
- persistent shared daemon state
- future session registry and control-plane state

The example application must stop being the only place where that ownership exists.

## Red Tests To Add First

Suggested first failing tests:

- daemon can start from config as a dedicated shared-instance process
- duplicate daemon start for the same instance fails cleanly
- daemon shutdown persists state and exits cleanly
- daemon host surface is invocable without example-specific CLI flows

Suggested future test files:

- `crates/rete-tokio/tests/shared_daemon_boot.rs`
- `crates/rete-tokio/tests/shared_daemon_exclusive_bind.rs`
- `crates/rete-tokio/tests/shared_daemon_shutdown.rs`

## Implementation Plan

1. Extract a dedicated daemon host surface.
   - Move shared-instance host logic out of example-only flow.
   - Keep the Linux example as a thin consumer later, not the host definition.

2. Define daemon ownership rules.
   - One canonical hosted node per shared instance.
   - Shared attach listeners are owned by the daemon.
   - The daemon is the authority for future shared-state persistence.

3. Define startup flow.
   - Parse config/data-dir first.
   - Load persistent daemon state.
   - Bind attach listeners.
   - Start hosted interfaces.
   - Publish readiness only after listeners and hosted node are live.

4. Define exclusivity rules.
   - Unix mode: duplicate bind for the same instance name must fail deterministically.
   - TCP mode: duplicate shared listener bind for the same port pair must fail deterministically.

5. Define shutdown flow.
   - Stop accepting new clients.
   - Drain or reject new control work cleanly.
   - Persist daemon-owned state.
   - Shut down listeners and hosted node in a stable order.

6. Define diagnostics and errors.
   - Listener bind failures
   - Invalid shared-mode config
   - Conflicting instance name / port ownership
   - Persistence load/save failures

## Green Gates

- Dedicated daemon surface exists in the planned location.
- Daemon startup and shutdown tests pass.
- Duplicate-bind/exclusivity tests pass.
- Hosted example is no longer the only authoritative daemon host path.

## E2E Scenarios

Required daemon-level E2E before closing the epic:

- start daemon with Unix shared mode configured and no attached clients
- start daemon with TCP shared mode configured and no attached clients
- duplicate daemon start fails in a controlled way
- daemon restart loads persisted state placeholder successfully

## References

- [../contracts/SCOPE.md](../contracts/SCOPE.md)
- [../contracts/REFERENCE.md](../contracts/REFERENCE.md)
- [../../ARCHITECTURAL_REVIEW_2026-04-01.md](../../ARCHITECTURAL_REVIEW_2026-04-01.md)
- [../../../examples/linux/src/main.rs](../../../examples/linux/src/main.rs)
- [../../../crates/rete-tokio/src/local.rs](../../../crates/rete-tokio/src/local.rs)
- <https://github.com/markqvist/Reticulum/blob/master/RNS/Utilities/rnsd.py>

## Open Questions

- Final crate/binary naming is a local project decision, not a compatibility contract issue.

## Done Definition

Mark this epic `complete` only when:

- a supported daemon surface exists,
- the daemon owns one canonical hosted node and its listeners,
- startup and shutdown behavior are explicit and tested,
- and later shared attach epics can target a real daemon instead of example-only flow.
