# EPIC-03: TCP Shared-Attach Compatibility

Status: `complete`
Depends on: `EPIC-00`, `EPIC-01`
Roadmap: [../ROADMAP.md](../ROADMAP.md)
Tracker: [../TRACKER.md](../TRACKER.md)

## Goal

Make stock Python shared-mode clients attach unchanged to the Rust daemon when configured for `shared_instance_type = tcp`.

## Problem Statement

The repo already supports Reticulum traffic over TCP interfaces, but that is not the same as shared attach over TCP. Shared attach over TCP is a different compatibility boundary with its own listener, config keys, attach semantics, and control-path implications.

If this distinction is not preserved, implementation will accidentally reuse normal Reticulum TCP interface behavior and miss the shared-instance contract entirely.

## Why It Matters

The roadmap explicitly includes TCP shared attach. If the daemon only matches Unix shared attach, the compatibility story remains incomplete for systems or deployments that depend on `shared_instance_type = tcp`.

## Compatibility Target

This epic targets:

- `shared_instance_type = tcp`
- shared attach listener behavior over TCP
- `shared_instance_port`
- `instance_control_port`
- any `rpc_key` behavior tied to TCP shared attach/control

It explicitly does **not** target the normal Reticulum network TCP interface. That support already exists at a different layer.

## Public Interface Changes

Future supported runtime/config surfaces introduced or tightened by this epic:

- TCP shared attach listener
- shared attach config validation for TCP mode
- distinct operator diagnostics for TCP shared attach vs normal Reticulum TCP interfaces

## State Model Changes

The daemon must gain:

- a TCP shared attach listener distinct from normal Reticulum TCP interfaces
- per-client attach sessions over TCP
- any TCP-mode control listener state required by the frozen contract

## Red Tests To Add First

Suggested first failing tests:

- stock Python shared-mode client configured for TCP cannot attach unchanged
- current daemon TCP behavior is confused with normal Reticulum TCP interface behavior
- TCP attach/control port configuration does not match the frozen contract

Suggested future test files:

- `tests/interop/shared_mode/tcp/attach_single_client.py`
- `tests/interop/shared_mode/tcp/attach_multi_client.py`
- `crates/rete-tokio/tests/shared_tcp_attach.rs`

## Implementation Plan

1. Separate TCP shared attach from normal Reticulum TCP interfaces.
   - Shared attach TCP is a daemon/client compatibility boundary.
   - Normal Reticulum TCP is an external transport interface.
   - Their listeners, logs, and config validation must be distinct.

2. Implement the TCP shared attach listener from the frozen contract.
   - Bind the configured shared attach port(s).
   - Honor the expected attach/control split if the contract requires one.
   - Validate conflicting port configurations clearly.

3. Implement TCP attach session handling.
   - initial attach
   - disconnect
   - reconnect
   - multiple concurrent shared-mode clients

4. Apply auth/control semantics from the frozen contract.
   - especially around `rpc_key` and control operations if applicable

5. Validate with stock Python clients configured for TCP shared mode.

## Green Gates

- TCP shared attach integration tests pass.
- Stock Python TCP shared attach E2E passes.
- Multi-client TCP attach E2E passes.
- No confusion remains between shared attach TCP and normal Reticulum TCP interface behavior.

## E2E Scenarios

Required shared-mode E2E:

- daemon starts in TCP shared mode
- first stock Python client attaches unchanged via TCP
- second stock Python client attaches unchanged via TCP
- reconnect works after a dropped TCP attach connection
- attached Python client can announce through the daemon
- attached Python client can send and receive encrypted data through the daemon

## References

- [../contracts/SCOPE.md](../contracts/SCOPE.md)
- [../contracts/REFERENCE.md](../contracts/REFERENCE.md)
- [../contracts/GOLDEN_TRACES.md](../contracts/GOLDEN_TRACES.md)
- <https://reticulum.network/manual/using.html>
- <https://github.com/markqvist/Reticulum/blob/master/RNS/Reticulum.py>
- <https://github.com/markqvist/Reticulum/blob/master/RNS/Utilities/rnsd.py>
- [../../../crates/rete-iface-tcp/src/lib.rs](../../../crates/rete-iface-tcp/src/lib.rs)
- [../../../crates/rete-tokio/src/tcp_server.rs](../../../crates/rete-tokio/src/tcp_server.rs)

## Open Questions

- Exact control-port split and auth expectations must come from the frozen contract if the upstream behavior is not fully explicit in docs.

## Done Definition

Mark this epic `complete` only when:

- stock Python shared-mode clients attach unchanged over TCP,
- TCP shared attach is clearly distinct from normal Reticulum TCP transport interfaces,
- and the required TCP shared-mode E2E scenarios are green.
