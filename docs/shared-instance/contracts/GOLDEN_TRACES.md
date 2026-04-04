# Shared-Mode Golden Trace Plan

Created: 2026-04-02

## Trace Capture Goals

Golden traces exist to freeze the behavior of the stock Python shared-instance path before implementation begins.

They are not optional debugging aids. They are compatibility fixtures used to:

- eliminate guesswork,
- validate control-plane behavior,
- and prove later that the Rust daemon matches the intended shared-mode boundary.

## Required Scenarios

Capture traces for all of these scenarios:

- daemon start
- first client attach
- second client attach
- client detach
- client reconnect
- announce propagation through the shared instance
- encrypted data send/receive through the shared instance
- in-scope control/status query
- Unix shared attach
- TCP shared attach

## Trace Format

Each scenario capture must include:

- scenario metadata
  - date
  - Reticulum version
  - transport mode (`unix` or `tcp`)
  - participants
- raw attach/control transcript
- packet transcript where relevant
- human-readable notes on the observed behavior
- any environmental assumptions

Preferred file set per scenario:

- `README.md`
- `metadata.json`
- `control.log`
- `packets.bin` or `packets.log`
- `notes.md`

## Storage Convention

Planned fixture location:

- `tests/fixtures/shared-instance/<mode>/<scenario>/...`

Where:

- `<mode>` is `unix` or `tcp`
- `<scenario>` is a stable, descriptive name such as:
  - `daemon-start`
  - `first-attach`
  - `multi-client-announce`
  - `control-status-query`

This doc defines the convention only. It does not require fixture generation in the current documentation step.

## Validation Usage

Golden traces are used for:

- contract-freeze review in `EPIC-00`
- attach/control compatibility tests in `EPIC-02` to `EPIC-04`
- later regression checks when shared-mode behavior changes

If implementation behavior differs from a trace, one of two things must happen:

- fix the implementation to match, or
- record and justify the difference in [DIFFS.md](DIFFS.md)

## Capture Rules

- Do not capture ad hoc traces without recording the exact scenario.
- Do not overwrite an accepted trace fixture without updating the contract docs and decision log.
- Do not call a behavior “compatible enough” without either a matching trace or an accepted difference entry.
