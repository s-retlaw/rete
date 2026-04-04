# Shared-Mode `rnsd` Replacement Test Strategy

Created: 2026-04-02
Scope source: [contracts/SCOPE.md](contracts/SCOPE.md)
Parity inventory: [PARITY_TEST_MATRIX.md](PARITY_TEST_MATRIX.md)

## TDD Rule

Every implementation task in this program follows this sequence:

1. Add or extend a failing test first.
2. Confirm the failure is for the intended compatibility gap.
3. Implement the smallest change that turns the test green.
4. Refactor without changing behavior.
5. Run the full local gate for the task.
6. Record evidence in [TRACKER.md](TRACKER.md).

No exceptions for “obvious” compatibility changes.

## Test Layers

Every epic must add coverage at the lowest useful layer plus at least one higher-level shared-mode test.

Required layers:

- Unit tests
  - parsing
  - state transitions
  - config interpretation
  - control-plane serialization/deserialization
- Rust integration tests
  - daemon lifecycle
  - attach listener behavior
  - shared state/session semantics
  - restart/persistence flows
- Python interoperability tests
  - stock Python shared-mode clients against the Rust daemon
  - Unix shared attach
  - TCP shared attach
- End-to-end scenario tests
  - multi-client shared-state flows
  - full protocol behavior through the Rust daemon

## Shared-Mode Harness Model

Shared-mode E2E tests should use a dedicated helper layer under `tests/interop/shared_mode/`.

Layout rules:

- use `tests/interop/shared_mode/unix/` for Unix shared attach cases
- use `tests/interop/shared_mode/tcp/` for TCP shared attach cases
- keep one file focused on one topology and one primary compatibility claim
- keep LXMF shared-mode cases in the shared-mode tree, not in a separate test program

The shared-mode helper should extend the existing line-oriented interop harness with a structured event layer.

Preferred event format:

```text
TEST_EVENT:{"source":"daemon","kind":"listener_ready","transport":"unix"}
```

Required helper capabilities:

- `checkpoint()`
- `emit_checkpoint(name, **fields)`
- `expect_event(...)`
- `expect_sequence(...)`
- `assert_no_event(...)`
- `count_events(...)`
- `dump_events()`

Required shared-mode event vocabulary:

- `listener_ready`
- `attached`
- `detached`
- `reconnected`
- `daemon_restarted`
- `control_query_ok`
- `control_query_failed`
- `rpc_auth_failed`
- `session_registered`
- `session_cleaned`
- `path_discovered`
- `announce_seen`
- `data_received`
- `link_established`
- `link_closed`
- `request_received`
- `resource_completed`
- `resource_corrupt`
- `lxmf_received`
- `attach_failed`
- `bind_failed`
- `timeout`
- `unexpected_disconnect`

## CI Suites

Define these suites for the shared-instance program:

- `shared-unit`
- `shared-integration`
- `shared-e2e-unix`
- `shared-e2e-tcp`
- `shared-soak`

Expected use:

- `shared-unit` and `shared-integration` on every relevant implementation task.
- `shared-e2e-unix` whenever Unix shared attach behavior changes.
- `shared-e2e-tcp` whenever TCP shared attach or control behavior changes.
- `shared-soak` on milestone validation, not on every small task.

## Red/Green Policy

- A task cannot move to `green` unless the new failing test passes.
- A task cannot move to `done` unless all relevant regression tests also pass.
- An epic cannot close on Rust-only tests.
- If behavior differs from Python and the difference is accepted by the user, it must be recorded in [contracts/DIFFS.md](contracts/DIFFS.md) and linked in the tracker evidence.

## Required Evidence Per Task

Every task must provide:

- the exact test added first
- the failing output or failure condition
- the passing output after implementation
- the relevant shared-mode E2E result
- any recorded deviation, if applicable

## Required Shared-Mode E2E Matrix

The full shared-service parity inventory is tracked in [PARITY_TEST_MATRIX.md](PARITY_TEST_MATRIX.md).

Required stage gates:

- `S1`: core shared-service parity, including LXMF
- `S2`: operational readiness
- `S3`: robustness, soak, and cutover

Every in-scope compatibility claim must exist as its own matrix row before the implementation that satisfies it is merged.

## Golden Trace Rule

Golden traces captured under `EPIC-00` are mandatory reference fixtures for:

- attach behavior
- control-plane behavior
- status/control requests in scope
- selected end-to-end packet/control flows

Do not replace trace-backed compatibility with hand-wavy “equivalent enough” checks.

## Completion Standard

The shared-instance program is not complete until:

- every `S1`, `S2`, and `S3` row in [PARITY_TEST_MATRIX.md](PARITY_TEST_MATRIX.md) is `covered`,
- all in-scope behavior has at least one stock-Python shared-mode E2E,
- Unix and TCP shared attach both pass the required E2E matrix,
- soak and robustness evidence exists for the shared daemon,
- and all known accepted differences are explicitly tracked.
