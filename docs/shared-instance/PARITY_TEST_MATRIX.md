# Shared-Service Parity Test Matrix

Created: 2026-04-02  
Source roadmap: [ROADMAP.md](ROADMAP.md)  
Execution rules: [TEST_STRATEGY.md](TEST_STRATEGY.md)  
Status tracker: [TRACKER.md](TRACKER.md)

## Purpose

This document is the source of truth for the shared-service parity test inventory.

Rules:

- One row equals one required compatibility claim.
- Every row must eventually map to one concrete test implementation.
- Stage completion is based on rows being `covered`, not on prose summaries.
- Stock-Python shared-mode E2E coverage is mandatory for every in-scope behavior.

## Stage Summary

| Stage | Name | Meaning | Completion Rule |
|---|---|---|---|
| `S1` | Core Shared-Service Parity | First formal parity gate for the shared daemon | Every `S1` row is `covered` |
| `S2` | Operational Readiness | Service-grade restart, config, utility, and operator behavior | Every `S2` row is `covered` |
| `S3` | Robustness, Soak, And Cutover | Production-readiness and migration confidence | Every `S3` row is `covered` |

## Case ID Scheme

Format:

- `S1-UNX-ATTACH-001`
- `S1-TCP-CTRL-002`
- `S2-GEN-STATE-001`

Segments:

- Stage: `S1`, `S2`, `S3`
- Transport:
  - `UNX` = Unix shared attach
  - `TCP` = TCP shared attach
  - `GEN` = transport-agnostic integration gate
- Domain:
  - `ATTACH`
  - `CTRL`
  - `STATE`
  - `ANNC`
  - `DATA`
  - `LINK`
  - `REQ`
  - `RSRC`
  - `LXMF`
  - `RESTART`
  - `OPER`
  - `ROBUST`
  - `SOAK`
  - `CUTOVER`

## Case Status Values

Use only these values at the matrix-row level:

- `unplanned`
- `planned`
- `red`
- `green`
- `covered`
- `blocked`

## Evidence Rules

Each row must eventually link evidence for:

- the failing test added first
- the passing local gate
- the required shared-mode E2E result where applicable
- any accepted deviation in [contracts/DIFFS.md](contracts/DIFFS.md)

## Shared-Mode Test Layout

This matrix assumes the shared-mode test program will use:

- Rust integration:
  - `crates/rete-tokio/tests/shared_attach_unix.rs`
  - `crates/rete-tokio/tests/shared_attach_tcp.rs`
  - `crates/rete-tokio/tests/shared_control.rs`
  - `crates/rete-tokio/tests/shared_sessions.rs`
  - `crates/rete-tokio/tests/shared_restart.rs`
- Python E2E:
  - `tests/interop/shared_mode/shared_mode_helpers.py`
  - `tests/interop/shared_mode/unix/*.py`
  - `tests/interop/shared_mode/tcp/*.py`

Shared-mode E2E files should follow these rules:

- one file = one topology + one primary compatibility claim
- Unix and TCP cases are mirrored as separate files
- LXMF cases stay inside the shared-mode tree

## Shared-Mode Event Contract

Shared-mode tests should use a structured event layer on top of the existing interop harness.

Preferred event format:

```text
TEST_EVENT:{"source":"daemon","kind":"listener_ready","transport":"unix"}
```

Expected helper API:

- `checkpoint()`
- `emit_checkpoint(name, **fields)`
- `expect_event(...)`
- `expect_sequence(...)`
- `assert_no_event(...)`
- `count_events(...)`
- `dump_events()`

Shared-mode event vocabulary:

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

---

## Stage 1: Core Shared-Service Parity

Stage 1 is the first formal parity gate. Shared-service parity is not achieved until every row in this section is `covered`.

### Stage 1 Rust Integration Gates

| Case ID | Transport | Layer | Scenario | Topology | Claim Proven | Required Events / Assertions | Suggested Test File | CI Suite | Blocks | Status | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `S1-GEN-ATTACH-001` | `GEN` | Rust integration | Unix listener bind and accept | daemon only | daemon binds the Unix shared listener and accepts attach sessions | `listener_ready`; attach accepted; no `bind_failed` | `crates/rete-tokio/tests/shared_attach_unix.rs` | `shared-integration` | `EPIC-02` | `planned` | `TBD` |
| `S1-GEN-ATTACH-002` | `GEN` | Rust integration | TCP shared listener bind and accept | daemon only | shared TCP attach listener is distinct from the normal Reticulum TCP interface | `listener_ready`; attach accepted; no cross-wiring with interface TCP | `crates/rete-tokio/tests/shared_attach_tcp.rs` | `shared-integration` | `EPIC-03` | `planned` | `TBD` |
| `S1-GEN-CTRL-001` | `GEN` | Rust integration | Control request routing and auth | daemon only | in-scope control/status requests route correctly and honor auth requirements | `control_query_ok`; `control_query_failed`; `rpc_auth_failed` where applicable | `crates/rete-tokio/tests/shared_control.rs` | `shared-integration` | `EPIC-04` | `planned` | `TBD` |
| `S1-GEN-STATE-001` | `GEN` | Rust integration | Session registry lifecycle | daemon + synthetic clients | attach, detach, and reconnect produce correct session registry transitions | `session_registered`; `session_cleaned`; `reconnected` | `crates/rete-tokio/tests/shared_sessions.rs` | `shared-integration` | `EPIC-05` | `planned` | `TBD` |
| `S1-GEN-STATE-002` | `GEN` | Rust integration | Ownership-aware cleanup | daemon + synthetic clients | disconnect cleanup removes only client-owned state and leaves daemon-owned shared state intact | `session_cleaned`; no loss of canonical state | `crates/rete-tokio/tests/shared_sessions.rs` | `shared-integration` | `EPIC-05` | `planned` | `TBD` |
| `S1-GEN-STATE-003` | `GEN` | Rust integration | Canonical routing vs broadcast | daemon + synthetic clients | inbound shared-state routing is canonical and not a blind packet broadcast shortcut | targeted delivery assertions; no broadcast leak | `crates/rete-tokio/tests/shared_sessions.rs` | `shared-integration` | `EPIC-05` | `planned` | `TBD` |

### Stage 1 Stock-Python E2E Cases

| Case ID | Transport | Layer | Scenario | Topology | Claim Proven | Required Events / Assertions | Suggested Test File | CI Suite | Blocks | Status | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `S1-UNX-ATTACH-001` | `UNX` | Python E2E | Single-client attach | Rust daemon + 1 stock Python client | stock Python client attaches unchanged over Unix shared attach | `listener_ready`; `attached`; no `attach_failed` | `tests/interop/shared_mode/unix/attach_single_client.py` | `shared-e2e-unix` | `EPIC-02` | `planned` | `TBD` |
| `S1-TCP-ATTACH-001` | `TCP` | Python E2E | Single-client attach | Rust daemon + 1 stock Python client | stock Python client attaches unchanged over TCP shared attach | `listener_ready`; `attached`; no `attach_failed` | `tests/interop/shared_mode/tcp/attach_single_client.py` | `shared-e2e-tcp` | `EPIC-03` | `planned` | `TBD` |
| `S1-UNX-ATTACH-002` | `UNX` | Python E2E | Multi-client attach | Rust daemon + 2 stock Python clients | two stock Python clients share the same daemon over Unix | 2x `attached`; 2x `session_registered` | `tests/interop/shared_mode/unix/attach_multi_client.py` | `shared-e2e-unix` | `EPIC-02` | `planned` | `TBD` |
| `S1-TCP-ATTACH-002` | `TCP` | Python E2E | Multi-client attach | Rust daemon + 2 stock Python clients | two stock Python clients share the same daemon over TCP | 2x `attached`; 2x `session_registered` | `tests/interop/shared_mode/tcp/attach_multi_client.py` | `shared-e2e-tcp` | `EPIC-03` | `planned` | `TBD` |
| `S1-UNX-ATTACH-003` | `UNX` | Python E2E | Reconnect after client drop | Rust daemon + 1 stock Python client | client reconnect re-establishes a healthy Unix shared session | `detached`; `reconnected`; `session_registered` | `tests/interop/shared_mode/unix/reconnect.py` | `shared-e2e-unix` | `EPIC-05` | `planned` | `TBD` |
| `S1-TCP-ATTACH-003` | `TCP` | Python E2E | Reconnect after client drop | Rust daemon + 1 stock Python client | client reconnect re-establishes a healthy TCP shared session | `detached`; `reconnected`; `session_registered` | `tests/interop/shared_mode/tcp/reconnect.py` | `shared-e2e-tcp` | `EPIC-05` | `planned` | `TBD` |
| `S1-UNX-CTRL-001` | `UNX` | Python E2E | Status query | Rust daemon + 1 stock Python client | in-scope status query works against the daemon over Unix shared attach | `control_query_ok` | `tests/interop/shared_mode/unix/control_status.py` | `shared-e2e-unix` | `EPIC-04` | `planned` | `TBD` |
| `S1-TCP-CTRL-001` | `TCP` | Python E2E | Status query | Rust daemon + 1 stock Python client | in-scope status query works against the daemon over TCP shared attach | `control_query_ok` | `tests/interop/shared_mode/tcp/control_status.py` | `shared-e2e-tcp` | `EPIC-04` | `planned` | `TBD` |
| `S1-UNX-CTRL-002` | `UNX` | Python E2E | Path/control query | Rust daemon + 1 stock Python client | in-scope path/control query behavior matches the frozen Unix contract | `control_query_ok`; expected response shape | `tests/interop/shared_mode/unix/control_status.py` | `shared-e2e-unix` | `EPIC-04` | `planned` | `TBD` |
| `S1-TCP-CTRL-002` | `TCP` | Python E2E | Path/control query | Rust daemon + 1 stock Python client | in-scope path/control query behavior matches the frozen TCP contract | `control_query_ok`; expected response shape | `tests/interop/shared_mode/tcp/control_status.py` | `shared-e2e-tcp` | `EPIC-04` | `planned` | `TBD` |
| `S1-TCP-CTRL-003` | `TCP` | Python E2E | Auth failure | Rust daemon + 1 stock Python client | invalid auth is rejected predictably where `rpc_key` applies | `rpc_auth_failed`; no daemon destabilization | `tests/interop/shared_mode/tcp/control_status.py` | `shared-e2e-tcp` | `EPIC-04` | `planned` | `TBD` |
| `S1-UNX-STATE-001` | `UNX` | Python E2E | Announce visible across clients | Rust daemon + 2 stock Python clients | client A announce becomes visible through the shared instance to client B | `announce_seen`; `path_discovered` | `tests/interop/shared_mode/unix/announce.py` | `shared-e2e-unix` | `EPIC-05` | `planned` | `TBD` |
| `S1-TCP-STATE-001` | `TCP` | Python E2E | Announce visible across clients | Rust daemon + 2 stock Python clients | client A announce becomes visible through the shared instance to client B | `announce_seen`; `path_discovered` | `tests/interop/shared_mode/tcp/announce.py` | `shared-e2e-tcp` | `EPIC-05` | `planned` | `TBD` |
| `S1-UNX-STATE-002` | `UNX` | Python E2E | Client detach cleanup | Rust daemon + 2 stock Python clients | client detach cleans only client-owned registrations under Unix shared attach | `detached`; `session_cleaned`; surviving client remains healthy | `tests/interop/shared_mode/unix/attach_multi_client.py` | `shared-e2e-unix` | `EPIC-05` | `planned` | `TBD` |
| `S1-TCP-STATE-002` | `TCP` | Python E2E | Client detach cleanup | Rust daemon + 2 stock Python clients | client detach cleans only client-owned registrations under TCP shared attach | `detached`; `session_cleaned`; surviving client remains healthy | `tests/interop/shared_mode/tcp/attach_multi_client.py` | `shared-e2e-tcp` | `EPIC-05` | `planned` | `TBD` |
| `S1-UNX-ANNC-001` | `UNX` | Python E2E | Announce propagation | Rust daemon + 1 stock Python client + peer | announce propagation through the Unix shared daemon matches the contract | `announce_seen`; peer path learned | `tests/interop/shared_mode/unix/announce.py` | `shared-e2e-unix` | `EPIC-08` | `planned` | `TBD` |
| `S1-TCP-ANNC-001` | `TCP` | Python E2E | Announce propagation | Rust daemon + 1 stock Python client + peer | announce propagation through the TCP shared daemon matches the contract | `announce_seen`; peer path learned | `tests/interop/shared_mode/tcp/announce.py` | `shared-e2e-tcp` | `EPIC-08` | `planned` | `TBD` |
| `S1-UNX-DATA-001` | `UNX` | Python E2E | Encrypted data send/receive | Rust daemon + 1 stock Python client + peer | encrypted single-packet data crosses the Unix shared daemon unchanged | `data_received`; proof/receipt expectation satisfied | `tests/interop/shared_mode/unix/data.py` | `shared-e2e-unix` | `EPIC-08` | `planned` | `TBD` |
| `S1-TCP-DATA-001` | `TCP` | Python E2E | Encrypted data send/receive | Rust daemon + 1 stock Python client + peer | encrypted single-packet data crosses the TCP shared daemon unchanged | `data_received`; proof/receipt expectation satisfied | `tests/interop/shared_mode/tcp/data.py` | `shared-e2e-tcp` | `EPIC-08` | `planned` | `TBD` |
| `S1-UNX-LINK-001` | `UNX` | Python E2E | Link establish / data / teardown | Rust daemon + 1 stock Python client + peer | link lifecycle works through Unix shared attach | `link_established`; `data_received`; `link_closed` | `tests/interop/shared_mode/unix/link.py` | `shared-e2e-unix` | `EPIC-08` | `planned` | `TBD` |
| `S1-TCP-LINK-001` | `TCP` | Python E2E | Link establish / data / teardown | Rust daemon + 1 stock Python client + peer | link lifecycle works through TCP shared attach | `link_established`; `data_received`; `link_closed` | `tests/interop/shared_mode/tcp/link.py` | `shared-e2e-tcp` | `EPIC-08` | `planned` | `TBD` |
| `S1-UNX-REQ-001` | `UNX` | Python E2E | Request/response round trip | Rust daemon + 1 stock Python client + peer | request lifecycle works through Unix shared attach | `request_received`; expected response returned | `tests/interop/shared_mode/unix/request.py` | `shared-e2e-unix` | `EPIC-08` | `planned` | `TBD` |
| `S1-TCP-REQ-001` | `TCP` | Python E2E | Request/response round trip | Rust daemon + 1 stock Python client + peer | request lifecycle works through TCP shared attach | `request_received`; expected response returned | `tests/interop/shared_mode/tcp/request.py` | `shared-e2e-tcp` | `EPIC-08` | `planned` | `TBD` |
| `S1-UNX-RSRC-001` | `UNX` | Python E2E | Small resource transfer | Rust daemon + 1 stock Python client + peer | small resource completes correctly over Unix shared attach | `resource_completed` | `tests/interop/shared_mode/unix/resource_small.py` | `shared-e2e-unix` | `EPIC-08` | `planned` | `TBD` |
| `S1-TCP-RSRC-001` | `TCP` | Python E2E | Small resource transfer | Rust daemon + 1 stock Python client + peer | small resource completes correctly over TCP shared attach | `resource_completed` | `tests/interop/shared_mode/tcp/resource_small.py` | `shared-e2e-tcp` | `EPIC-08` | `planned` | `TBD` |
| `S1-UNX-RSRC-002` | `UNX` | Python E2E | Large resource transfer | Rust daemon + 1 stock Python client + peer | large resource completes correctly over Unix shared attach | `resource_completed` | `tests/interop/shared_mode/unix/resource_large.py` | `shared-e2e-unix` | `EPIC-08` | `planned` | `TBD` |
| `S1-TCP-RSRC-002` | `TCP` | Python E2E | Large resource transfer | Rust daemon + 1 stock Python client + peer | large resource completes correctly over TCP shared attach | `resource_completed` | `tests/interop/shared_mode/tcp/resource_large.py` | `shared-e2e-tcp` | `EPIC-08` | `planned` | `TBD` |
| `S1-UNX-RSRC-003` | `UNX` | Python E2E | Corrupt resource handling | Rust daemon + 1 stock Python client + peer | corrupt resource is detected and not falsely completed over Unix shared attach | `resource_corrupt`; no false `resource_completed` | `tests/interop/shared_mode/unix/resource_corrupt.py` | `shared-e2e-unix` | `EPIC-08` | `planned` | `TBD` |
| `S1-TCP-RSRC-003` | `TCP` | Python E2E | Corrupt resource handling | Rust daemon + 1 stock Python client + peer | corrupt resource is detected and not falsely completed over TCP shared attach | `resource_corrupt`; no false `resource_completed` | `tests/interop/shared_mode/tcp/resource_corrupt.py` | `shared-e2e-tcp` | `EPIC-08` | `planned` | `TBD` |
| `S1-UNX-LXMF-001` | `UNX` | Python E2E | LXMF direct delivery | Rust daemon + 1 stock Python LXMF client + peer | direct LXMF delivery works through Unix shared attach | `lxmf_received` | `tests/interop/shared_mode/unix/lxmf_direct.py` | `shared-e2e-unix` | `EPIC-08` | `planned` | `TBD` |
| `S1-TCP-LXMF-001` | `TCP` | Python E2E | LXMF direct delivery | Rust daemon + 1 stock Python LXMF client + peer | direct LXMF delivery works through TCP shared attach | `lxmf_received` | `tests/interop/shared_mode/tcp/lxmf_direct.py` | `shared-e2e-tcp` | `EPIC-08` | `planned` | `TBD` |
| `S1-UNX-LXMF-002` | `UNX` | Python E2E | LXMF opportunistic delivery | Rust daemon + 1 stock Python LXMF client + peer | opportunistic LXMF delivery works through Unix shared attach | `lxmf_received` | `tests/interop/shared_mode/unix/lxmf_opportunistic.py` | `shared-e2e-unix` | `EPIC-08` | `planned` | `TBD` |
| `S1-TCP-LXMF-002` | `TCP` | Python E2E | LXMF opportunistic delivery | Rust daemon + 1 stock Python LXMF client + peer | opportunistic LXMF delivery works through TCP shared attach | `lxmf_received` | `tests/interop/shared_mode/tcp/lxmf_opportunistic.py` | `shared-e2e-tcp` | `EPIC-08` | `planned` | `TBD` |
| `S1-UNX-LXMF-003` | `UNX` | Python E2E | LXMF propagation flow | Rust daemon + propagation peer + stock Python LXMF client | propagation-mode LXMF works through Unix shared attach | `lxmf_received`; propagation path confirmed | `tests/interop/shared_mode/unix/lxmf_propagation.py` | `shared-e2e-unix` | `EPIC-08` | `planned` | `TBD` |
| `S1-TCP-LXMF-003` | `TCP` | Python E2E | LXMF propagation flow | Rust daemon + propagation peer + stock Python LXMF client | propagation-mode LXMF works through TCP shared attach | `lxmf_received`; propagation path confirmed | `tests/interop/shared_mode/tcp/lxmf_propagation.py` | `shared-e2e-tcp` | `EPIC-08` | `planned` | `TBD` |

### Stage 1 Completion Rule

Stage 1 is complete only when:

- every Stage 1 integration row is `covered`
- every Stage 1 stock-Python E2E row is `covered`
- no accepted Stage 1 deviation is missing from [contracts/DIFFS.md](contracts/DIFFS.md)

---

## Stage 2: Operational Readiness

Stage 2 is required before recommending the Rust daemon as the normal shared-instance service for real operator use.

### Stage 2 Rust Integration Gates

| Case ID | Transport | Layer | Scenario | Topology | Claim Proven | Required Events / Assertions | Suggested Test File | CI Suite | Blocks | Status | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `S2-GEN-RESTART-001` | `GEN` | Rust integration | Restart state restore | daemon only | daemon restores required persisted state on restart | `daemon_restarted`; required state restored | `crates/rete-tokio/tests/shared_restart.rs` | `shared-integration` | `EPIC-06` | `planned` | `TBD` |
| `S2-GEN-RESTART-002` | `GEN` | Rust integration | Multi-instance isolation | 2 daemon instances | separately configured instances do not interfere | isolated listeners and isolated state | `crates/rete-tokio/tests/shared_restart.rs` | `shared-integration` | `EPIC-06` | `planned` | `TBD` |
| `S2-GEN-OPER-001` | `GEN` | Rust integration | Config validation | daemon only | invalid shared-mode configs fail predictably before service start | `bind_failed` or config validation failure | `crates/rete-tokio/tests/shared_restart.rs` | `shared-integration` | `EPIC-06` | `planned` | `TBD` |

### Stage 2 Stock-Python E2E Cases

| Case ID | Transport | Layer | Scenario | Topology | Claim Proven | Required Events / Assertions | Suggested Test File | CI Suite | Blocks | Status | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `S2-UNX-RESTART-001` | `UNX` | Python E2E | Restart and later reattach | Rust daemon + 1 stock Python client | stock Python client reattaches successfully after daemon restart over Unix | `daemon_restarted`; `reconnected`; healthy attach and traffic | `tests/interop/shared_mode/unix/restart.py` | `shared-e2e-unix` | `EPIC-06` | `planned` | `TBD` |
| `S2-TCP-RESTART-001` | `TCP` | Python E2E | Restart and later reattach | Rust daemon + 1 stock Python client | stock Python client reattaches successfully after daemon restart over TCP | `daemon_restarted`; `reconnected`; healthy attach and traffic | `tests/interop/shared_mode/tcp/restart.py` | `shared-e2e-tcp` | `EPIC-06` | `planned` | `TBD` |
| `S2-UNX-RESTART-002` | `UNX` | Python E2E | Required state survives restart | Rust daemon + client + peer | daemon-owned Unix shared state needed for normal reattach/use survives restart | post-restart attach works; expected state remains visible | `tests/interop/shared_mode/unix/restart.py` | `shared-e2e-unix` | `EPIC-06` | `planned` | `TBD` |
| `S2-TCP-RESTART-002` | `TCP` | Python E2E | Required state survives restart | Rust daemon + client + peer | daemon-owned TCP shared state needed for normal reattach/use survives restart | post-restart attach works; expected state remains visible | `tests/interop/shared_mode/tcp/restart.py` | `shared-e2e-tcp` | `EPIC-06` | `planned` | `TBD` |
| `S2-UNX-OPER-001` | `UNX` | Python E2E | Instance-name exclusivity | 2 daemon start attempts + stock Python client | duplicate Unix shared instance naming fails visibly and safely | first listener succeeds; second fails; original stays healthy | `tests/interop/shared_mode/unix/restart.py` | `shared-e2e-unix` | `EPIC-06` | `planned` | `TBD` |
| `S2-TCP-OPER-001` | `TCP` | Python E2E | Shared/control port exclusivity | 2 daemon start attempts + stock Python client | conflicting TCP shared/control ports fail visibly and safely | first listener succeeds; second fails; original stays healthy | `tests/interop/shared_mode/tcp/restart.py` | `shared-e2e-tcp` | `EPIC-06` | `planned` | `TBD` |
| `S2-UNX-OPER-002` | `UNX` | Python E2E | Status utility compatibility | Rust daemon + stock Python utility | required status utility works unchanged against Unix shared attach | `control_query_ok`; expected utility output | `tests/interop/shared_mode/unix/control_status.py` | `shared-e2e-unix` | `EPIC-07` | `planned` | `TBD` |
| `S2-TCP-OPER-002` | `TCP` | Python E2E | Status utility compatibility | Rust daemon + stock Python utility | required status utility works unchanged against TCP shared attach | `control_query_ok`; expected utility output | `tests/interop/shared_mode/tcp/control_status.py` | `shared-e2e-tcp` | `EPIC-07` | `planned` | `TBD` |
| `S2-UNX-OPER-003` | `UNX` | Python E2E | Path utility compatibility | Rust daemon + stock Python utility | required path utility works unchanged against Unix shared attach | `control_query_ok`; expected path result | `tests/interop/shared_mode/unix/control_status.py` | `shared-e2e-unix` | `EPIC-07` | `planned` | `TBD` |
| `S2-TCP-OPER-003` | `TCP` | Python E2E | Path utility compatibility | Rust daemon + stock Python utility | required path utility works unchanged against TCP shared attach | `control_query_ok`; expected path result | `tests/interop/shared_mode/tcp/control_status.py` | `shared-e2e-tcp` | `EPIC-07` | `planned` | `TBD` |
| `S2-GEN-OPER-004` | `GEN` | Python E2E | Bind/config error visibility | daemon start attempt | operator-facing bind/config errors are diagnosable and stable | expected failure message shape; no silent failure | `tests/interop/shared_mode/unix/restart.py` | `shared-e2e-unix` | `EPIC-07` | `planned` | `TBD` |

### Stage 2 Completion Rule

Stage 2 is complete only when:

- every Stage 2 row is `covered`
- restart, config, and operator evidence is linked in [TRACKER.md](TRACKER.md)

---

## Stage 3: Robustness, Soak, And Cutover

Stage 3 is the production-readiness gate.

### Stage 3 Rust Integration Gates

| Case ID | Transport | Layer | Scenario | Topology | Claim Proven | Required Events / Assertions | Suggested Test File | CI Suite | Blocks | Status | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `S3-GEN-ROBUST-001` | `GEN` | Rust integration | Malformed control rejection | daemon only | malformed control traffic is rejected safely without corrupting daemon state | `control_query_failed`; no crash; no leaked session state | `crates/rete-tokio/tests/shared_control.rs` | `shared-integration` | `EPIC-09` | `planned` | `TBD` |
| `S3-GEN-ROBUST-002` | `GEN` | Rust integration | Half-open session handling | daemon + synthetic clients | half-open/disrupted sessions are cleaned up without shared-state corruption | `unexpected_disconnect`; `session_cleaned` | `crates/rete-tokio/tests/shared_sessions.rs` | `shared-integration` | `EPIC-09` | `planned` | `TBD` |

### Stage 3 Stock-Python E2E Cases

| Case ID | Transport | Layer | Scenario | Topology | Claim Proven | Required Events / Assertions | Suggested Test File | CI Suite | Blocks | Status | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `S3-UNX-ROBUST-001` | `UNX` | Python E2E | Malformed attach traffic | Rust daemon + malformed Unix client | malformed Unix attach traffic is rejected safely | `attach_failed`; no daemon crash | `tests/interop/shared_mode/unix/robustness.py` | `shared-soak` | `EPIC-09` | `planned` | `TBD` |
| `S3-TCP-ROBUST-001` | `TCP` | Python E2E | Malformed attach traffic | Rust daemon + malformed TCP client | malformed TCP attach traffic is rejected safely | `attach_failed`; no daemon crash | `tests/interop/shared_mode/tcp/robustness.py` | `shared-soak` | `EPIC-09` | `planned` | `TBD` |
| `S3-UNX-ROBUST-002` | `UNX` | Python E2E | Half-open client session | Rust daemon + stock Python client | half-open Unix shared session is recovered or cleaned up safely | `unexpected_disconnect`; `session_cleaned`; later attach still healthy | `tests/interop/shared_mode/unix/robustness.py` | `shared-soak` | `EPIC-09` | `planned` | `TBD` |
| `S3-TCP-ROBUST-002` | `TCP` | Python E2E | Half-open client session | Rust daemon + stock Python client | half-open TCP shared session is recovered or cleaned up safely | `unexpected_disconnect`; `session_cleaned`; later attach still healthy | `tests/interop/shared_mode/tcp/robustness.py` | `shared-soak` | `EPIC-09` | `planned` | `TBD` |
| `S3-TCP-ROBUST-003` | `TCP` | Python E2E | Invalid auth attempts | Rust daemon + stock Python client | repeated invalid auth attempts do not destabilize the daemon | `rpc_auth_failed`; no degraded healthy attach path | `tests/interop/shared_mode/tcp/robustness.py` | `shared-soak` | `EPIC-09` | `planned` | `TBD` |
| `S3-UNX-SOAK-001` | `UNX` | Python E2E | Attach/detach churn | Rust daemon + stock Python clients | repeated Unix attach/detach churn remains stable | repeated `attached`/`detached`; no leaked sessions | `tests/interop/shared_mode/unix/soak.py` | `shared-soak` | `EPIC-09` | `planned` | `TBD` |
| `S3-TCP-SOAK-001` | `TCP` | Python E2E | Attach/detach churn | Rust daemon + stock Python clients | repeated TCP attach/detach churn remains stable | repeated `attached`/`detached`; no leaked sessions | `tests/interop/shared_mode/tcp/soak.py` | `shared-soak` | `EPIC-09` | `planned` | `TBD` |
| `S3-UNX-SOAK-002` | `UNX` | Python E2E | Mixed protocol workload | Rust daemon + stock Python clients + peers | repeated announce/data/link workload remains stable over Unix shared attach | repeated `announce_seen`; `data_received`; `link_established` without instability | `tests/interop/shared_mode/unix/soak.py` | `shared-soak` | `EPIC-09` | `planned` | `TBD` |
| `S3-TCP-SOAK-002` | `TCP` | Python E2E | Mixed protocol workload | Rust daemon + stock Python clients + peers | repeated announce/data/link workload remains stable over TCP shared attach | repeated `announce_seen`; `data_received`; `link_established` without instability | `tests/interop/shared_mode/tcp/soak.py` | `shared-soak` | `EPIC-09` | `planned` | `TBD` |
| `S3-UNX-SOAK-003` | `UNX` | Python E2E | Restart during churn | Rust daemon + stock Python clients | restart during active Unix client churn recovers cleanly | `daemon_restarted`; `reconnected`; no stuck sessions | `tests/interop/shared_mode/unix/soak.py` | `shared-soak` | `EPIC-09` | `planned` | `TBD` |
| `S3-TCP-SOAK-003` | `TCP` | Python E2E | Restart during churn | Rust daemon + stock Python clients | restart during active TCP client churn recovers cleanly | `daemon_restarted`; `reconnected`; no stuck sessions | `tests/interop/shared_mode/tcp/soak.py` | `shared-soak` | `EPIC-09` | `planned` | `TBD` |
| `S3-UNX-CUTOVER-001` | `UNX` | Python E2E | Cutover dry run | Python `rnsd` host replaced by Rust daemon | dry-run cutover to the Rust daemon succeeds for Unix shared attach systems | cutover checklist completed; attach/status/traffic all healthy | `tests/interop/shared_mode/unix/cutover.py` | `shared-soak` | `EPIC-09` | `planned` | `TBD` |
| `S3-TCP-CUTOVER-001` | `TCP` | Python E2E | Cutover dry run | Python `rnsd` host replaced by Rust daemon | dry-run cutover to the Rust daemon succeeds for TCP shared attach systems | cutover checklist completed; attach/status/traffic all healthy | `tests/interop/shared_mode/tcp/cutover.py` | `shared-soak` | `EPIC-09` | `planned` | `TBD` |
| `S3-UNX-CUTOVER-002` | `UNX` | Python E2E | Rollback dry run | Rust daemon replaced by Python `rnsd` | dry-run rollback from the Rust daemon succeeds for Unix shared attach systems | rollback checklist completed; recovery healthy | `tests/interop/shared_mode/unix/cutover.py` | `shared-soak` | `EPIC-09` | `planned` | `TBD` |
| `S3-TCP-CUTOVER-002` | `TCP` | Python E2E | Rollback dry run | Rust daemon replaced by Python `rnsd` | dry-run rollback from the Rust daemon succeeds for TCP shared attach systems | rollback checklist completed; recovery healthy | `tests/interop/shared_mode/tcp/cutover.py` | `shared-soak` | `EPIC-09` | `planned` | `TBD` |

### Stage 3 Completion Rule

Stage 3 is complete only when:

- every Stage 3 row is `covered`
- soak, robustness, cutover, and rollback evidence is linked in [TRACKER.md](TRACKER.md)

## Usage Notes

- Agents should claim work by row ID, not by broad scenario family.
- When one file covers multiple matrix rows, each row still needs separate evidence notes.
- If a new compatibility requirement is discovered, add a new row before implementation merges.
