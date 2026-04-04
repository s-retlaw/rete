# Shared-Mode Reference Contract

Created: 2026-04-02
Reference date: 2026-04-02

## Upstream Documentation

Primary shared-instance references:

- Reticulum system/shared-instance guide:
  - <https://reticulum.network/manual/using.html>
- Reticulum API reference:
  - <https://reticulum.network/manual/reference.html>

## Upstream Python Modules

These modules are the Python implementation references for shared-mode behavior:

- Reticulum core/shared-instance setup:
  - <https://github.com/markqvist/Reticulum/blob/master/RNS/Reticulum.py>
- Local shared attach behavior:
  - <https://github.com/markqvist/Reticulum/blob/master/RNS/Interfaces/LocalInterface.py>
- Transport/shared-state behavior:
  - <https://github.com/markqvist/Reticulum/blob/master/RNS/Transport.py>
- Shared daemon entrypoint:
  - <https://github.com/markqvist/Reticulum/blob/master/RNS/Utilities/rnsd.py>
- Shared status utility:
  - <https://github.com/markqvist/Reticulum/blob/master/RNS/Utilities/rnstatus.py>
- Path/status utility behavior:
  - <https://github.com/markqvist/Reticulum/blob/master/RNS/Utilities/rnpath.py>

## Compatibility Notes By Subsystem

### Shared Attach

Freeze:

- instance naming behavior
- local attach transport expectations
- attach/detach/reconnect behavior
- client session registration expectations

Primary references:

- `using.html`
- `LocalInterface.py`
- `Reticulum.py`

### Shared Control / Status

Freeze:

- in-scope status/control request shapes
- auth/permission expectations where `rpc_key` applies
- utility compatibility needed for v1

Primary references:

- `Reticulum.py`
- `rnsd.py`
- `rnstatus.py`
- `rnpath.py`

### Shared State

Freeze:

- what lives in the daemon as canonical state
- what is session-scoped
- what must survive client disconnect
- what must survive daemon restart

Primary references:

- `Reticulum.py`
- `Transport.py`

### Config

Freeze semantics for the in-scope shared-mode settings:

- `share_instance`
- `instance_name`
- `shared_instance_type`
- `shared_instance_port`
- `instance_control_port`
- `rpc_key`

Primary references:

- `using.html`
- `Reticulum.py`
- `rnsd.py`

## Local Starting Points In This Repo

Current relevant local code and docs:

- Shared attach starting point:
  - [../../../crates/rete-tokio/src/local.rs](../../../crates/rete-tokio/src/local.rs)
- Hosted example current surface:
  - [../../../examples/linux/src/main.rs](../../../examples/linux/src/main.rs)
- Architectural prerequisite:
  - [../../ARCHITECTURAL_REVIEW_2026-04-01.md](../../ARCHITECTURAL_REVIEW_2026-04-01.md)

These are starting points, not the compatibility contract.
