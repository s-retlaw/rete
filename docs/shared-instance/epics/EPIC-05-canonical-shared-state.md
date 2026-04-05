# EPIC-05: Canonical Shared State And Client Session Semantics

Status: `planned`
Depends on: `EPIC-04`
Roadmap: [../ROADMAP.md](../ROADMAP.md)
Tracker: [../TRACKER.md](../TRACKER.md)

## Goal

Replace packet-relay semantics with true daemon-owned canonical shared state and correct per-client session behavior.

## Problem Statement

A shared instance is not just a packet multiplexer. It is one canonical Reticulum instance serving multiple local programs. The current local server/client model in the repo is a useful starting point, but it does not yet prove correct shared-state behavior for:

- local client ownership
- daemon-owned shared transport state
- multi-client routing semantics
- session teardown cleanup

Without this epic, attached clients may appear to work while still sharing state incorrectly.

## Why It Matters

This is the core semantic difference between:

- a Rust daemon that forwards packets, and
- a Rust daemon that behaves like one shared Reticulum instance.

This epic is what makes “shared-mode replacement” true rather than superficial.

## Compatibility Target

This epic targets:

- daemon-owned canonical shared transport state
- client/session registration semantics
- correct delivery of network-visible behavior across multiple attached clients
- cleanup rules on client detach without corrupting shared daemon state

## Public Interface Changes

Future runtime surfaces introduced or tightened by this epic:

- explicit session registry behavior
- explicit client-owned registration semantics
- explicit shared-state routing behavior for attached clients

## State Model Changes

This epic defines and implements the central shared-state model:

- Daemon-owned canonical state:
  - interfaces
  - path table
  - known identities
  - transport-layer shared routing state
  - shared proof/request/resource state that belongs to the shared instance
  - shared LXMF state in scope for the daemon
- Client/session state:
  - attach session identity
  - client-owned registrations
  - session-scoped control state

Critical rule:

- incoming events must not be blindly broadcast to all local clients unless the frozen contract explicitly requires it

## Red Tests To Add First

Suggested first failing tests:

- current relay-style broadcast semantics deliver state/events incorrectly across multiple clients
- client disconnect removes too much or too little shared state
- client-owned registrations leak after detach
- daemon-owned shared state is not preserved correctly while clients churn

Suggested future test files:

- `tests/interop/shared_mode/unix/attach_multi_client.py`
- `tests/interop/shared_mode/tcp/attach_multi_client.py`
- `crates/rete-tokio/tests/shared_sessions.rs`

## Implementation Plan

1. Define the session registry.
   - Each attached client session must have stable identity in the daemon.
   - Session lifecycle must be explicit: attach, active, disconnect, cleanup.

2. Define ownership rules.
   - Which registrations are client-owned.
   - Which state is daemon-owned.
   - What happens when a client that created state disconnects.

3. Define event routing rules.
   - Which inbound network events are routed to one client.
   - Which are visible to multiple attached clients.
   - Which are handled entirely inside the daemon.

4. Implement cleanup semantics.
   - Client detach must clean up client-owned registrations.
   - Client detach must not destroy unrelated daemon-owned shared state.
   - Multi-client detach order must not corrupt the shared instance.

5. Validate multi-client behavior.
   - one client announces, another observes via the daemon
   - one client detaches, the rest remain healthy
   - shared transport state remains canonical during churn

## Green Gates

- Session-registry integration tests pass.
- Multi-client shared-state E2E passes for Unix and TCP.
- No relay-style broadcast shortcuts remain where canonical routing is required.

## E2E Scenarios

Required shared-mode E2E:

- two stock Python shared-mode clients attached to the same daemon
- client A announces and client B sees the shared-instance effects correctly
- client A disconnects and client B remains healthy
- client A reconnects and canonical shared state remains consistent
- mixed-client churn does not corrupt shared transport state

## References

- [../contracts/SCOPE.md](../contracts/SCOPE.md)
- [../contracts/REFERENCE.md](../contracts/REFERENCE.md)
- [../../../crates/rete-tokio/src/local.rs](../../../crates/rete-tokio/src/local.rs)
- [../../../crates/rete-tokio/src/hub.rs](../../../crates/rete-tokio/src/hub.rs)
- [../../../examples/daemon/src/main.rs](../../../examples/daemon/src/main.rs)
- <https://github.com/markqvist/Reticulum/blob/master/RNS/Reticulum.py>
- <https://github.com/markqvist/Reticulum/blob/master/RNS/Transport.py>

## Open Questions

- Exact client-owned vs daemon-owned registration boundaries must be frozen from the upstream contract and traces before implementation begins.

## Done Definition

Mark this epic `complete` only when:

- the daemon owns canonical shared state,
- client sessions are tracked explicitly,
- multi-client behavior matches one shared Reticulum instance,
- and relay-only semantics are no longer relied on for shared-mode behavior.
