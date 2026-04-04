# Shared-Mode Scope Contract

Created: 2026-04-02

## In-Scope Behaviors

The shared-instance replacement effort includes:

- A Rust daemon acting as the canonical shared Reticulum instance.
- Stock Python `RNS` clients using the normal shared-instance path unchanged.
- Unix local shared attach behavior.
- `shared_instance_type = tcp` behavior.
- Shared control/status behavior required by the frozen compatibility contract.
- Shared-state semantics across multiple attached local clients.
- Config, persistence, restart, operator, and E2E validation needed to credibly replace `rnsd` in shared mode.

## Supported Python App Mode

Supported mode:

- Shared-instance mode only.

Meaning:

- The Python app uses the normal shared-instance path and expects a shared Reticulum instance to exist.
- The Rust daemon is that shared instance.

## Supported Shared-Instance Transports

In scope from the beginning:

- Unix local shared attach
- TCP shared attach (`shared_instance_type = tcp`)

Unix remains the default compatibility path on Unix-like systems. TCP shared attach is also a first-class compatibility target for this roadmap.

## Out-Of-Scope Behaviors

Explicitly out of scope:

- Standalone Python operation with `share_instance = no`
- Any attempt to replace Python modules in-process
- `PyO3` bindings or Python compatibility shims
- Rust-native-only daemon/client compatibility as a substitute for stock Python compatibility
- Windows-native shared attach backend in the first roadmap

## Deferred Items

Deferred to later programs, if ever needed:

- Standalone Python replacement
- Python in-process Rust backend
- Windows named-pipe or platform-native local attach backend
- New Rust-native control protocols separate from the shared-instance compatibility surface

## Compatibility Boundary

The compatibility boundary for this effort is:

- the stock Python shared-mode client path,
- against a Rust daemon that behaves as the system shared instance,
- over Unix local attach and TCP shared attach.

Anything outside that boundary is not required for parity.
