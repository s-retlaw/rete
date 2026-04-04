# Shared-Mode `rnsd` Replacement Tracker

Created: 2026-04-02
Source roadmap: [ROADMAP.md](ROADMAP.md)
Parity matrix: [PARITY_TEST_MATRIX.md](PARITY_TEST_MATRIX.md)
Prerequisite review: [../ARCHITECTURAL_REVIEW_2026-04-01.md](../ARCHITECTURAL_REVIEW_2026-04-01.md)

## Tracking Rules

- Epic IDs are stable and must match [ROADMAP.md](ROADMAP.md) and all epic specs.
- Every implementation task must start with a failing test.
- Every task must carry its own evidence before moving to `done`.
- Any behavior difference from the frozen Python contract must be recorded in [contracts/DIFFS.md](contracts/DIFFS.md) before merge.
- A task can be owned by one agent at a time.
- Parity completion is measured against [PARITY_TEST_MATRIX.md](PARITY_TEST_MATRIX.md), not against prose milestone summaries.

## Epic Status Values

Use only these statuses:

- `planned`
- `ready`
- `in_progress`
- `blocked`
- `validating`
- `complete`

## Task Status Values

Use only these statuses:

- `todo`
- `red`
- `green`
- `refactor`
- `blocked`
- `done`

## Evidence Requirements

Every completed task must link evidence for:

- the failing test added first
- the passing local gate after implementation
- the relevant shared-mode E2E result
- any accepted deviations logged in [contracts/DIFFS.md](contracts/DIFFS.md)

Every completed parity row must also carry its row-level evidence in [PARITY_TEST_MATRIX.md](PARITY_TEST_MATRIX.md).

No task is complete with prose-only confirmation.

## Epic Status Board

| ID | Title | Status | Depends On | Owner | Exit Criteria | Evidence |
|---|---|---|---|---|---|---|
| `EPIC-00` | Freeze compatibility contract | `complete` | Architectural review complete | claude | Shared-mode scope, references, and trace plan are frozen. 12 golden traces captured and validated. | `test_fixture_index.py` GREEN (4/4), `test_reference_inventory.py` GREEN (8/8), `test_golden_traces.py` GREEN (12/12). Pickle opcodes + wire format documented in REFERENCE.md. |
| `EPIC-01` | Real daemon surface | `planned` | `EPIC-00` | `TBD` | Dedicated daemon surface exists and owns canonical hosted node lifecycle | `TBD` |
| `EPIC-02` | Unix shared-attach compatibility | `planned` | `EPIC-00`, `EPIC-01` | `TBD` | Stock Python shared attach works over Unix | `TBD` |
| `EPIC-03` | TCP shared-attach compatibility | `planned` | `EPIC-00`, `EPIC-01` | `TBD` | Stock Python shared attach works over TCP | `TBD` |
| `EPIC-04` | Shared control plane / RPC compatibility | `planned` | `EPIC-02`, `EPIC-03` | `TBD` | In-scope control/status interactions match contract | `TBD` |
| `EPIC-05` | Canonical shared state and client session semantics | `planned` | `EPIC-04` | `TBD` | Shared daemon semantics are canonical, not relay-only | `TBD` |
| `EPIC-06` | Config / persistence / restart compatibility | `planned` | `EPIC-05` | `TBD` | Restart and reattach flows are stable and tested | `TBD` |
| `EPIC-07` | Utility / operator parity | `planned` | `EPIC-06` | `TBD` | In-scope utility and operator workflows work | `TBD` |
| `EPIC-08` | Full shared-mode E2E matrix | `planned` | `EPIC-07` | `TBD` | Shared-mode E2E matrix is green for Unix and TCP | `TBD` |
| `EPIC-09` | Soak / robustness / cutover readiness | `planned` | `EPIC-08` | `TBD` | Soak and cutover evidence supports replacement claim | `TBD` |

## Active Task Board

| Task ID | Epic | Status | Owner | Red Test | Green Evidence |
|---|---|---|---|---|---|
| `EPIC-00a-01` | `EPIC-00` | `done` | claude | `test_fixture_index.py`, `test_reference_inventory.py` | Contract docs frozen, probe scripts written, 4/12 traces captured |
| `EPIC-00b-01` | `EPIC-00` | `done` | claude | `test_golden_traces.py` | Remaining 8 traces captured, pickle opcodes documented, wire format documented |

## Blocker Log

| Date | Blocked Item | Reason | Unblock Condition |
|---|---|---|---|
| `2026-04-02` | None yet | N/A | N/A |

## Decision Log

| Date | Decision | Notes |
|---|---|---|
| `2026-04-02` | Shared-mode replacement only | Standalone Python replacement is out of scope |
| `2026-04-02` | Unix and TCP shared attach both in scope | Both modes planned from the beginning |
| `2026-04-02` | Stock Python apps in shared mode must work unchanged | Rust-native-only daemon is not the target |
| `2026-04-02` | Stage 1 parity includes LXMF | Core shared-service parity is not complete without LXMF shared-mode flows |
| `2026-04-02` | TDD is mandatory | Failing test first for every task |
| `2026-04-04` | Response pickle uses protocol 4; Rust decoder must handle both protocol 2 and 4 | Observed in golden traces: request=proto2, response=proto4 |
| `2026-04-04` | Auth handshake is 3 messages (one-way) in observed traces | CHALLENGE, DIGEST, WELCOME. Mutual auth (6 messages) may occur in other flows |
| `2026-04-04` | `Transport.has_path()` returns False in shared-mode clients | Shared-mode clients defer transport to daemon; path resolution is daemon-side only |
| `2026-04-04` | rnsd writes logs to file, not stderr | Daemon stderr is empty; control.log from probes only has content when probe writes its own output |

## Next-Up Queue

1. `EPIC-00` contract freeze and golden trace capture.
2. `EPIC-01` daemon surface extraction from example-only hosted logic.
3. `EPIC-02` Unix shared attach with stock Python shared-mode E2E.
4. `EPIC-03` TCP shared attach with stock Python shared-mode E2E.
5. Seed row ownership and status fields in [PARITY_TEST_MATRIX.md](PARITY_TEST_MATRIX.md) before implementation starts.

## Task Template Reference

Every task created under an epic must include:

- `Goal`
- `Dependency`
- `Red tests to add first`
- `Implementation steps`
- `Green checks`
- `E2E scenarios`
- `Reference docs/code`
- `Evidence required to mark done`
