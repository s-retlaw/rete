# Shared-Mode `rnsd` Replacement Roadmap

Created: 2026-04-02
Status: `planned`
Prerequisite: [ARCHITECTURAL_REVIEW_2026-04-01.md](../ARCHITECTURAL_REVIEW_2026-04-01.md) complete

## Goal

Build a Rust shared instance that can replace Python `rnsd` for **shared-mode** use. When the Rust daemon is running as the system shared instance, stock Python applications that use the normal Reticulum shared-instance path should continue to work unchanged.

This roadmap is documentation-first. It defines the staged work, test gates, and compatibility contracts for later implementation.

## Scope

In scope:

- Shared-instance replacement only.
- Unix local shared attach.
- `shared_instance_type = tcp`.
- Stock Python `RNS` clients using the shared-instance path.
- Daemon-first deployment model.
- Full red/green TDD and cross-language E2E coverage for shared-mode behavior.

Out of scope:

- Standalone Python replacement (`share_instance = no`).
- `PyO3`, Python in-process bindings, or any attempt to replace Python modules.
- Windows-native shared attach backend in the first roadmap.
- New Rust-native client APIs as a substitute for compatibility.

## Compatibility Target

The compatibility target for this roadmap is:

- Official Reticulum shared-instance behavior as documented on 2026-04-02:
  - <https://reticulum.network/manual/using.html>
  - <https://reticulum.network/manual/reference.html>
- Observed behavior in the upstream Python implementation:
  - <https://github.com/markqvist/Reticulum/blob/master/RNS/Reticulum.py>
  - <https://github.com/markqvist/Reticulum/blob/master/RNS/Interfaces/LocalInterface.py>
  - <https://github.com/markqvist/Reticulum/blob/master/RNS/Transport.py>
  - <https://github.com/markqvist/Reticulum/blob/master/RNS/Utilities/rnsd.py>
  - <https://github.com/markqvist/Reticulum/blob/master/RNS/Utilities/rnstatus.py>
  - <https://github.com/markqvist/Reticulum/blob/master/RNS/Utilities/rnpath.py>

Source-of-truth order is fixed in [contracts/README.md](contracts/README.md).

## Milestones

### M1: Freeze and Stand Up

- `EPIC-00` Freeze compatibility contract
- `EPIC-01` Real daemon surface

Milestone exit:

- The compatibility contract is frozen.
- There is a supported Rust daemon surface separate from example-only hosted logic.

### M2: Shared Attach Compatibility

- `EPIC-02` Unix shared-attach compatibility
- `EPIC-03` TCP shared-attach compatibility
- `EPIC-04` Shared control plane / RPC compatibility

Milestone exit:

- Stock Python shared-mode clients can attach over both Unix and TCP.
- In-scope control/status interactions match the captured contract.

### M3: True Shared State

- `EPIC-05` Canonical shared state and client session semantics
- `EPIC-06` Config / persistence / restart compatibility
- `EPIC-07` Utility / operator parity

Milestone exit:

- The daemon behaves like one canonical shared instance, not just a packet relay.
- Shared-state persistence and operator workflows are stable.

### M4: Prove And Cut Over

- `EPIC-08` Full shared-mode E2E matrix
- `EPIC-09` Soak / robustness / cutover readiness

Milestone exit:

- Shared-mode replacement is backed by green stock-Python E2E coverage.
- There is a defined cutover and rollback process.

## Epic Dependency Graph

| Epic | Title | Depends On | Implementation Intent | Completion Criteria |
|---|---|---|---|---|
| `EPIC-00` | Freeze compatibility contract | Architectural review complete | Capture exact shared-mode contract, references, and golden traces before compatibility work begins | Shared-mode scope, references, and trace plan are frozen and documented |
| `EPIC-01` | Real daemon surface | `EPIC-00` | Extract and define a supported shared-instance daemon surface | Dedicated daemon surface exists and owns canonical hosted node lifecycle |
| `EPIC-02` | Unix shared-attach compatibility | `EPIC-00`, `EPIC-01` | Match stock Python shared attach on Unix/domain sockets | Python shared-mode client attaches and exchanges traffic over Unix |
| `EPIC-03` | TCP shared-attach compatibility | `EPIC-00`, `EPIC-01` | Match `shared_instance_type = tcp` attach behavior | Python shared-mode client attaches and exchanges traffic over TCP |
| `EPIC-04` | Shared control plane / RPC compatibility | `EPIC-02`, `EPIC-03` | Match in-scope shared control/status interactions | Control/status flows in scope behave like the frozen reference contract |
| `EPIC-05` | Canonical shared state and client session semantics | `EPIC-04` | Replace packet-relay semantics with true daemon-owned shared state | Multi-client shared-mode semantics match one canonical shared instance |
| `EPIC-06` | Config / persistence / restart compatibility | `EPIC-05` | Match shared-mode config, persistence, and restart behavior | Restart, reattach, and multi-instance behavior are stable and tested |
| `EPIC-07` | Utility / operator parity | `EPIC-06` | Make the daemon operationally usable as an `rnsd` replacement | In-scope utility and operator workflows work against the daemon |
| `EPIC-08` | Full shared-mode E2E matrix | `EPIC-07` | Prove parity across all shared-mode protocol scenarios | All required shared-mode E2E scenarios are green for Unix and TCP |
| `EPIC-09` | Soak / robustness / cutover readiness | `EPIC-08` | Validate long-run stability and cutover readiness | Soak, robustness, and cutover checklists are complete and green |

## Required Test Posture

Every epic must follow the rules in [TEST_STRATEGY.md](TEST_STRATEGY.md).
The complete shared-service parity inventory lives in [PARITY_TEST_MATRIX.md](PARITY_TEST_MATRIX.md).

Minimum required posture by epic:

- A failing test must be added before implementation work begins.
- Rust-only tests are insufficient once shared-mode compatibility is involved.
- Every behavior in scope must end up with at least one stock-Python shared-mode E2E.

## Exit Criteria For Shared-Mode Parity

The roadmap is complete only when all of the following are true:

- Every `S1` row in [PARITY_TEST_MATRIX.md](PARITY_TEST_MATRIX.md) is `covered`.
- The Rust daemon is a supported shared-instance host surface.
- Stock Python shared-mode clients attach unchanged over Unix and TCP.
- In-scope control/status behaviors match the frozen contract or are recorded in [contracts/DIFFS.md](contracts/DIFFS.md).
- Shared-state behavior is canonical and deterministic across multiple attached clients.
- Config, persistence, restart, and operator workflows are validated.
- The required shared-mode E2E matrix is green.
- Soak and robustness gates are green or have explicitly documented accepted limits.

## Decision Log

Current fixed decisions:

- Shared-mode replacement only.
- Standalone Python replacement deferred.
- Unix and TCP shared attach both in scope from the beginning.
- Stage 1 parity includes LXMF shared-mode flows.
- Windows-native shared attach backend deferred.
- Documentation pack is the current deliverable; code implementation happens later.

Track later decisions in [TRACKER.md](TRACKER.md) and [contracts/DIFFS.md](contracts/DIFFS.md).

## Epic Links

- [EPIC-00](epics/EPIC-00-freeze-contract.md)
- [EPIC-01](epics/EPIC-01-daemon-surface.md)
- [EPIC-02](epics/EPIC-02-unix-shared-attach.md)
- [EPIC-03](epics/EPIC-03-tcp-shared-attach.md)
- [EPIC-04](epics/EPIC-04-control-plane-rpc.md)
- [EPIC-05](epics/EPIC-05-canonical-shared-state.md)
- [EPIC-06](epics/EPIC-06-config-persistence-restart.md)
- [EPIC-07](epics/EPIC-07-operator-utility-parity.md)
- [EPIC-08](epics/EPIC-08-e2e-matrix.md)
- [EPIC-09](epics/EPIC-09-soak-cutover.md)
