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
| `EPIC-01` | Real daemon surface | `complete` | `EPIC-00` | claude | Dedicated daemon surface exists and owns canonical hosted node lifecycle | `shared_daemon_boot.rs` GREEN (4/4): boot, Unix exclusivity, TCP exclusivity, clean shutdown. `rete-shared` binary builds. Config: `SharedInstanceConfig` with 6 frozen keys. |
| `EPIC-02` | Unix shared-attach compatibility | `complete` | `EPIC-00`, `EPIC-01` | claude | Stock Python shared attach works over Unix | `shared_daemon_attach.rs` GREEN (3/3): relay, disconnect, packet ingest. Python E2E: `attach_single_client.py` (7/7), `attach_multi_client.py` (9/9), `reconnect.py` (8/8). Workspace tests pass. E2E interop (53/53) no regressions. |
| `EPIC-03` | TCP shared-attach compatibility | `complete` | `EPIC-00`, `EPIC-01` | claude | Stock Python shared attach works over TCP | `shared_daemon_attach_tcp.rs` GREEN (3/3): relay, disconnect, packet ingest. Python E2E: `attach_single_client.py` (7/7), `attach_multi_client.py` (9/9), `reconnect.py` (8/8). Workspace tests pass. E2E interop (53/53) no regressions. |
| `EPIC-04` | Shared control plane / RPC compatibility | `complete` | `EPIC-02`, `EPIC-03` | claude | In-scope control/status interactions match contract | `shared_daemon_control.rs` GREEN (4/4): Unix/TCP auth+query, auth failure, multiple queries. Python E2E: `unix/control_status.py` (11/11), `tcp/control_status.py` (12/12). Pickle codec validates against golden traces. Workspace tests pass (771). E2E interop (53/53) no regressions. |
| `EPIC-05` | Canonical shared state and client session semantics | `complete` | `EPIC-04` | claude | Shared daemon semantics are canonical, not relay-only | Fixed Hub dispatch (AllExceptSource/SourceInterface per-client routing), removed client_read_task broadcast bypass, added SessionRegistry with ClientEvent lifecycle tracking. Rust: `shared_daemon_attach.rs` GREEN (3/3): canonical announce routing, disconnect no crash, packet ingest. `shared_daemon_attach_tcp.rs` GREEN (3/3). `session::tests` GREEN (3/3). Python E2E: `unix/announce_visible.py` (7/7), `unix/detach_cleanup.py` (10/10), `tcp/announce_visible.py` (7/7), `tcp/detach_cleanup.py` (10/10). Workspace tests pass (~780). E2E interop (53/53) no regressions. |
| `EPIC-06` | Config / persistence / restart compatibility | `complete` | `EPIC-05` | claude | Restart and reattach flows are stable and tested | Config validation: `SharedInstanceConfig::validate()` with 5 rules, 7 unit tests + 4 integration tests GREEN. Periodic snapshot: tick-based save every ~5 min. Restart: `shared_daemon_restart.rs` GREEN (3/3): state restore, Unix isolation, TCP isolation. Python E2E: `unix/restart.py` (11/11), `tcp/restart.py` (11/11). Workspace tests pass (789). E2E interop (53/53) no regressions. |
| `EPIC-07` | Utility / operator parity | `complete` | `EPIC-06` | claude | In-scope utility and operator workflows work | Channel-based RPC query bridge (control→node event loop via mpsc+oneshot). Live handlers for all GET/DROP commands: interface_stats (with live counters + client count), path_table (from transport snapshot), next_hop, next_hop_if_name, first_hop_timeout, link_count, drop path/all_via/announce_queues. Pickle decoder extended with GLOBAL/TUPLE2/REDUCE for proto 2 bytes. Operator diagnostics: identity hash + transport mode logged at startup, auth failures logged. Rust: `shared_daemon_control.rs` GREEN (7/7) including 3 new EPIC-07 tests (path_table, next_hop, drop_path). Python E2E: `unix/rnstatus_full.py` (11/11), `tcp/rnstatus_full.py` (10/10), `unix/rnpath_query.py` (8/8), `tcp/rnpath_query.py` (7/7). Workspace tests pass. E2E interop no regressions. |
| `EPIC-08` | Full shared-mode E2E matrix | `complete` | `EPIC-07` | claude | Shared-mode E2E matrix is green for Unix and TCP | 20/20 containerized E2E tests GREEN: announce(2), data(2), link(2), request(2), resource_small(2), resource_large(2), resource_corrupt(2), lxmf_direct(2), lxmf_opportunistic(2), lxmf_propagation(2). 8 daemon bugs fixed: RPC authkey (SHA-256 + mutual auth + HMAC nonce), HDLC buffer (LOCAL_MTU=300KB), ingest limit (300KB), dedup skip for link traffic, BoundedVecDeque, announce context_flag, cached announce replay, has_path RPC. Workspace tests pass. Stage 1 complete. |
| `EPIC-09` | Soak / robustness / cutover readiness | `planned` | `EPIC-08` | `TBD` | Soak and cutover evidence supports replacement claim | `TBD` |

## Active Task Board

| Task ID | Epic | Status | Owner | Red Test | Green Evidence |
|---|---|---|---|---|---|
| `EPIC-00a-01` | `EPIC-00` | `done` | claude | `test_fixture_index.py`, `test_reference_inventory.py` | Contract docs frozen, probe scripts written, 4/12 traces captured |
| `EPIC-00b-01` | `EPIC-00` | `done` | claude | `test_golden_traces.py` | Remaining 8 traces captured, pickle opcodes documented, wire format documented |
| `EPIC-01-01` | `EPIC-01` | `done` | claude | `shared_daemon_boot.rs` (4 tests) | `SharedInstanceConfig` + `SharedDaemon` + `rete-shared` binary. All 4 integration tests green. Full workspace tests pass. E2E interop (53/53) no regressions. |
| `EPIC-02-01` | `EPIC-02` | `done` | claude | `shared_daemon_attach.rs` (3 tests), `attach_single_client.py`, `attach_multi_client.py`, `reconnect.py` | Rust: 3/3 integration tests (relay, disconnect, packet ingest). Python E2E: single attach 7/7, multi-client 9/9, reconnect 8/8. Zero compat issues — HDLC framing works unchanged. Workspace tests pass. E2E interop (53/53) no regressions. |
| `EPIC-03-01` | `EPIC-03` | `done` | claude | `shared_daemon_attach_tcp.rs` (3 tests), `tcp/attach_single_client.py`, `tcp/attach_multi_client.py`, `tcp/reconnect.py` | Rust: 3/3 integration tests (relay, disconnect, packet ingest over TCP). Python E2E: single attach 7/7, multi-client 9/9, reconnect 8/8. Required `shared_instance_type = tcp` in Python client config for TCP detection. Workspace tests pass. E2E interop (53/53) no regressions. |
| `EPIC-04-01` | `EPIC-04` | `done` | claude | `pickle::tests` (7 tests), `control::tests` (6 tests), `shared_daemon_control.rs` (4 tests), `unix/control_status.py` (11/11), `tcp/control_status.py` (12/12) | Pickle codec (proto 2+4, 20 opcodes) validates against golden traces. HMAC-SHA256 auth handshake. Control listener (Unix+TCP). interface_stats + path_table + rate_table + link_count + blackholed_identities handlers. Auth failure correctly rejected. Workspace tests pass (771). E2E interop (53/53) no regressions. |
| `EPIC-05-01` | `EPIC-05` | `done` | claude | `session::tests` (3 tests), `shared_daemon_attach.rs` (3 tests), `shared_daemon_attach_tcp.rs` (3 tests), `unix/announce_visible.py` (7/7), `unix/detach_cleanup.py` (10/10), `tcp/announce_visible.py` (7/7), `tcp/detach_cleanup.py` (10/10) | Fixed Hub dispatch semantics: AllExceptSource now broadcasts to Hub clients except source (was: skip entire slot), SourceInterface sends to source client only (was: broadcast all). Removed client_read_task broadcast bypass in LocalServer and TcpServer. Added SessionRegistry with ClientEvent lifecycle tracking. Replaced relay tests with canonical announce routing tests. Workspace tests pass (~780). E2E interop (53/53) no regressions. |
| `EPIC-06-01` | `EPIC-06` | `done` | claude | `config::tests::validate_*` (7 tests), `shared_daemon_config.rs` (4 tests), `shared_daemon_restart.rs` (3 tests), `unix/restart.py` (11/11), `tcp/restart.py` (11/11) | Config validation: `SharedInstanceConfig::validate()` with 5 rules. Periodic snapshot on `NodeEvent::Tick` (every ~5 min). Restart: announce → shutdown → snapshot.json has paths → restart → client reattaches. Multi-instance: Unix (different names) and TCP (different ports) coexist with independent identities. Workspace tests pass (789). E2E interop (53/53) no regressions. |
| `EPIC-07-01` | `EPIC-07` | `done` | claude | `shared_daemon_control.rs` (7 tests including 3 new: path_table, next_hop, drop_path), `unix/rnstatus_full.py` (11/11), `tcp/rnstatus_full.py` (10/10), `unix/rnpath_query.py` (8/8), `tcp/rnpath_query.py` (7/7) | Channel-based RPC bridge: mpsc+oneshot from control listener to node event loop, drained via `try_recv()` in `on_event`. Live GET handlers: interface_stats (counters + client count via AtomicUsize), path_table (snapshot), next_hop, next_hop_if_name, first_hop_timeout, link_count, packet_rssi/snr/q (None), rate_table (empty), blackholed_identities (empty). Live DROP handlers: path, all_via, announce_queues. Pickle decoder extended with GLOBAL/TUPLE2/REDUCE for proto 2 bytes. Operator diagnostics: identity hash + transport mode at startup, auth failure logging. Workspace tests pass. E2E interop no regressions. |
| `EPIC-08-01` | `EPIC-08` | `done` | claude | 20 containerized E2E tests: `unix/announce.py` (7/7), `tcp/announce.py` (7/7), `unix/data.py` (11/11), `tcp/data.py` (11/11), `unix/link.py` (11/11), `tcp/link.py` (11/11), `unix/request.py` (12/12), `tcp/request.py` (12/12), `unix/resource_small.py` (13/13), `tcp/resource_small.py` (13/13), `unix/resource_large.py` (11/11), `tcp/resource_large.py` (11/11), `unix/resource_corrupt.py` (10/10), `tcp/resource_corrupt.py` (10/10), `unix/lxmf_direct.py` (11/11), `tcp/lxmf_direct.py` (11/11), `unix/lxmf_opportunistic.py` (10/10), `tcp/lxmf_opportunistic.py` (10/10), `unix/lxmf_propagation.py` (10/10), `tcp/lxmf_propagation.py` (10/10) | Containerized E2E infrastructure (Dockerfile, container_runner.py). 8 daemon bugs fixed: (1) RPC authkey SHA-256 + mutual auth + HMAC nonce-only, (2) HDLC LOCAL_MTU=300KB for shared-instance, (3) ingest MAX_INGEST_PKT=300KB, (4) dedup skip for relayed link traffic, (5) BoundedVecDeque for hosted dedup window, (6) announce context_flag preservation in rebuild, (7) cached announce replay for new clients, (8) has_path RPC handler. Side-by-side wire comparison (lxmf_compare_runner.py) confirmed parity with Python rnsd. Workspace tests pass. Stage 1 complete. |

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
| `2026-04-04` | Unix data-plane framing is fully compatible without changes | Stock Python RNS 1.1.4 clients attach to rete-shared in 7ms. HDLC framing, client relay, disconnect cleanup, and reconnect all work identically. No DIFFS.md entries needed for EPIC-02. |
| `2026-04-04` | DaemonFuture must be actively polled for server accept/relay to work | Tests using `tokio::select!` to drive daemon future concurrently with test logic. Boot tests only needed `connect()` (kernel-buffered), but relay/ingest tests require the accept loop. |
| `2026-04-04` | TCP data-plane framing is fully compatible without changes | Stock Python RNS 1.1.4 clients attach to rete-shared TCP in <10ms. HDLC framing, client relay, disconnect cleanup, and reconnect all work identically to Unix. No DIFFS.md entries needed for EPIC-03. |
| `2026-04-04` | Python RNS requires `shared_instance_type = tcp` in client config for TCP mode | On Linux, Python RNS defaults to AF_UNIX. The `shared_instance_type = tcp` config key forces TCP mode. Without it, clients start standalone instead of attaching to the TCP daemon. |
| `2026-04-04` | S1-TCP-ATTACH-003 reassigned from EPIC-05 to EPIC-03 | TCP reconnect is structurally identical to Unix reconnect (ClientHub disconnect cleanup is transport-agnostic). No reason to defer to EPIC-05. |
| `2026-04-04` | Control plane does not route through NodeCommand for read-only queries | interface_stats, path_table, etc. are built from static config data at daemon startup. No command channel needed. Write operations (drop, blackhole) can be added later via NodeCommand when dynamic state tracking is implemented. |
| `2026-04-04` | Pickle codec is in rete-daemon, not a separate crate | Control-plane-only, never needed by no_std targets, tightly coupled to RPC response shapes. No benefit to a separate crate. |
| `2026-04-04` | Python RNS uses "LocalServerInterface" type name for both Unix and TCP shared attach interfaces | Golden traces confirm identical type string regardless of transport. |
| `2026-04-05` | Hub dispatch fixed: AllExceptSource sends to other Hub clients, SourceInterface sends to source only | Previous behavior was wrong for multi-client Hubs: AllExceptSource skipped the Hub slot entirely, SourceInterface broadcast to all. client_read_task broadcast bypass removed — all routing now goes through the node's canonical dispatch. |
| `2026-04-05` | SessionRegistry is std::sync::Mutex, not tokio::sync::Mutex | All operations are fast HashMap lookups (never held across .await). std::sync::Mutex is more efficient for this use case. |
| `2026-04-05` | ClientEvent channel added to ClientHub, opt-in via new_with_events | Backward-compatible: existing `new()` sets event_tx=None. Daemon opts in via `enable_client_events()` on LocalServer/TcpServer. |
| `2026-04-05` | Config validation uses `SharedInstanceConfig::validate()` called before any I/O | Subsumes the old `share_instance` check. 5 rules: share_instance, empty name, TCP same-port, TCP port-0 (data and control). |
| `2026-04-05` | Periodic snapshot uses tick_count in daemon closure, not event.rs handler | event.rs carries LXMF dependencies not needed by rete-shared. Lightweight tick-based save in the daemon's own on_event closure keeps the shared daemon lean. RefCell<JsonFileStore> shared between periodic and shutdown saves. |
| `2026-04-05` | Multi-instance isolation proven via bind mechanics and separate data_dirs | Different instance names → different Unix abstract sockets. Different TCP ports → separate listeners. Different data_dirs → separate identities and snapshots. No cross-contamination observed. |
| `2026-04-05` | HDLC buffer for local shared-instance connections is 300KB (not radio MTU 500) | Resource transfers and LXMF messages can produce frames up to 262KB (negotiated link MTU). TcpServer also uses 300KB. |
| `2026-04-05` | RPC control socket uses mutual auth (bidirectional challenge-response) | Python's `multiprocessing.connection.Client` does `answer_challenge` then `deliver_challenge`. Server must respond to both. Without mutual auth, `get_packet_rssi` RPC calls from `Link.__update_phy_stats` cause `EOFError` that kills frame processing. |
| `2026-04-05` | RPC authkey = SHA-256(transport_identity_private_key) | Matches Python RNS's `RNS.Identity.full_hash(Transport.identity.get_private_key())`. Clients must share daemon's `transport_identity` file. |
| `2026-04-05` | Daemon caches and replays announces to newly-connected clients | Python RNS clients that connect after an announce would otherwise miss it. Implemented via inbound channel intercept that tracks announce packets and new client_ids. |
| `2026-04-05` | Dedup skips link traffic where daemon doesn't own the link | Identical keepalive packets would otherwise be permanently flagged as duplicates, causing link timeout. |
| `2026-04-05` | Announce rebuild preserves context_flag for ratchet announces | LXMF destinations use ratchets (context_flag=1). Without preserving this in the H2 rebuild, the announce signature validation fails on the receiving client. |
| `2026-04-05` | E2E tests run in isolated Docker containers | Each test gets its own network namespace — no port conflicts. Container runner at `tests/interop/shared_mode/container_runner.py`. |

## Next-Up Queue

1. ~~`EPIC-00` contract freeze and golden trace capture.~~ COMPLETE
2. ~~`EPIC-01` daemon surface extraction from example-only hosted logic.~~ COMPLETE
3. ~~`EPIC-02` Unix shared attach with stock Python shared-mode E2E.~~ COMPLETE
4. ~~`EPIC-03` TCP shared attach with stock Python shared-mode E2E.~~ COMPLETE
5. ~~`EPIC-04` Shared control plane / RPC compatibility.~~ COMPLETE
6. ~~`EPIC-05` Canonical shared state and client session semantics.~~ COMPLETE
7. ~~`EPIC-06` Config, persistence, and restart compatibility.~~ COMPLETE
8. ~~`EPIC-07` Utility / operator parity.~~ COMPLETE
9. ~~`EPIC-08` Full shared-mode E2E matrix.~~ COMPLETE — **Stage 1 complete.**
10. `EPIC-09` Soak / robustness / cutover readiness.

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
