# Shared-Instance Compatibility Contracts

Created: 2026-04-02
Roadmap source: [../ROADMAP.md](../ROADMAP.md)

## Purpose

This directory defines the compatibility contract for the shared-mode `rnsd` replacement effort.

Its job is to prevent later implementation work from drifting into:

- a Rust-native daemon that stock Python clients cannot use,
- compatibility claims without trace-backed evidence,
- or ad hoc decisions that are not recorded anywhere.

These docs are the fixed reference set that all shared-instance implementation work must follow.

## Source-Of-Truth Order

When sources disagree, use this order:

1. Official Reticulum documentation
2. Observed behavior from upstream Python code
3. Captured golden traces
4. Project-local compatibility decisions

If item 4 is used to accept a divergence, that divergence must be recorded in [DIFFS.md](DIFFS.md).

## Golden Trace Capture

Golden traces are mandatory for the shared-instance program. They are used to freeze the behavior of:

- shared attach
- detach / reconnect
- in-scope control plane
- in-scope status and utility flows
- selected packet/control interactions

The trace plan is defined in [GOLDEN_TRACES.md](GOLDEN_TRACES.md).

## Acceptable Divergence

There is no silent divergence.

A behavior difference is acceptable only if:

- it is explicitly recorded in [DIFFS.md](DIFFS.md),
- it is tied to a specific contract item,
- it is validated against stock Python shared-mode behavior where possible,
- and it is linked from the relevant epic/task evidence.

## Contract Documents

- [SCOPE.md](SCOPE.md)
- [REFERENCE.md](REFERENCE.md)
- [GOLDEN_TRACES.md](GOLDEN_TRACES.md)
- [DIFFS.md](DIFFS.md)
