# EPIC-XX: Title

Status: `planned`
Depends on: `TBD`
Roadmap: [../ROADMAP.md](../ROADMAP.md)
Tracker: [../TRACKER.md](../TRACKER.md)

## Goal

State the single outcome this epic must deliver.

## Problem Statement

State the compatibility or architectural gap this epic closes.

## Why It Matters

Explain why the gap blocks shared-mode `rnsd` replacement.

## Compatibility Target

Name the exact shared-mode boundary this epic affects:

- Unix shared attach
- TCP shared attach
- control plane
- canonical shared state
- operator parity
- or another explicit shared-mode subsystem

## Public Interface Changes

List the supported daemon/config/runtime surfaces this epic is expected to change.

## State Model Changes

List any daemon-owned state, session state, persistence, or routing changes introduced by this epic.

## Red Tests To Add First

List the failing tests that must exist before implementation starts.

## Implementation Plan

Break the work into decision-complete steps. Keep each step implementable by one agent.

## Green Gates

List the exact local gates and regression checks required before this epic can move to `validating`.

## E2E Scenarios

List the stock-Python shared-mode scenarios that must pass for this epic.

## References

Link the relevant upstream docs/code and local contract docs.

## Open Questions

List only unresolved items that cannot be decided from the frozen contract.

If there are none, say `None`.

## Done Definition

State the conditions required to mark the epic `complete`.
