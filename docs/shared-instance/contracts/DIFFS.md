# Shared-Mode Compatibility Differences

Created: 2026-04-02

## Purpose

This file is the only accepted place to record behavior differences between:

- the frozen Python shared-mode reference contract, and
- the Rust shared-instance implementation.

If a difference is not recorded here, it is treated as a bug.

## Rules For Recording A Difference

Every difference entry must include:

- a stable ID
- the affected subsystem
- the source reference or trace
- the observed Rust behavior
- the desired or accepted behavior
- the reason it is accepted or still open
- the epic/task that owns it
- the validation evidence

## Allowed Difference Types

Allowed only if explicitly approved and recorded:

- operational/logging wording differences that do not alter protocol or control semantics
- internal implementation differences with identical externally observable behavior
- documented temporary gaps during active implementation, marked as open and blocked from parity claims

## Disallowed Difference Types

Do not accept without explicit written approval:

- shared attach transport incompatibility
- control-plane request/response incompatibility in scope
- behavior changes that break stock Python shared-mode clients
- state-model differences that change multi-client semantics
- silent omission of config keys in scope

## Open Differences

| ID | Subsystem | Reference | Rust Behavior | Owner | Status | Evidence |
|---|---|---|---|---|---|---|
| `None yet` | N/A | N/A | N/A | N/A | N/A | N/A |

Replace the placeholder row when the first open difference is accepted into the tracker.

## Rejected Differences

| ID | Subsystem | Reference | Rejected Proposal | Reason |
|---|---|---|---|---|
| `None yet` | N/A | N/A | N/A | N/A |

## Resolved Differences

| ID | Subsystem | Reference | Resolution | Evidence |
|---|---|---|---|---|
| `None yet` | N/A | N/A | N/A | N/A |
