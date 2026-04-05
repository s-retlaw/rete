# Shared-Mode `rnsd` Replacement — Multi-Session Implementation Plan

**Created:** 2026-04-04
**Status:** Approved for implementation

## Context

**Problem:** The rete project needs a Rust daemon that can replace Python `rnsd` as the system shared instance. Stock Python shared-mode clients (`RNS.Reticulum(shared_instance=True)`) must attach unchanged over Unix sockets and TCP. No Python code changes allowed on the client side.

**What exists today:**
- `crates/rete-tokio/src/local.rs` — `LocalServer` already binds `\0rns/{name}`, HDLC-frames packets, relays via `ClientHub`. **Data plane works.**
- `crates/rete-tokio/src/tcp_server.rs` — `TcpServer` with HDLC + IFAC + multi-client. **Works.**
- `crates/rete-tokio/src/lib.rs` — `TokioNode` event loop, multi-interface dispatch. **Works.**
- `crates/rete-daemon/` — Building blocks (config, command, identity, monitoring, event, file_store, compression). **Library only, no binary.**
- `examples/daemon/src/main.rs` — Full hosted node (402 lines). **Example-only, not a supported daemon surface.**
- `tests/interop/local_ipc_interop.py` — Rust-to-Rust Unix IPC test. **Proves data plane relay works between Rust nodes.**

**What is missing:**
1. No dedicated daemon binary or `SharedDaemon` abstraction
2. No shared-instance config keys (`instance_name`, `shared_instance_type`, `shared_instance_port`, `instance_control_port`, `rpc_key`)
3. No control plane RPC (Python uses `multiprocessing.connection` with pickle + HMAC auth)
4. No session registry or canonical shared-state management
5. No exclusive bind enforcement
6. No golden traces captured from Python `rnsd`
7. No `tests/interop/shared_mode/` directory or Python-vs-Rust shared-mode E2E tests
8. No `tests/fixtures/shared-instance/` directory

**Python protocol (must match):**
- **Data plane:** HDLC-framed packets on Unix `\0rns/{instance_name}` or TCP `127.0.0.1:37428`. No handshake, no control messages on the data socket.
- **Control plane:** Separate socket (`\0rns/{instance_name}/rpc` or TCP `127.0.0.1:37429`). Uses Python `multiprocessing.connection` protocol: 4-byte length-prefixed messages, HMAC challenge-response auth, pickle-serialized dicts for requests/responses.
- **Default ports:** data=37428, control=37429 (TCP mode). Unix mode uses abstract-namespace sockets.

**Controlling docs:** `docs/shared-instance/` — TRACKER.md, ROADMAP.md, PARITY_TEST_MATRIX.md, TEST_STRATEGY.md, contracts/*, epics/EPIC-00 through EPIC-09.

---

## Critical Architecture Decision: Pickle / multiprocessing.connection

The Python RPC uses `multiprocessing.connection.Listener/Client` (HMAC auth + pickle serialization). For `rnstatus` and `rnpath` to work unchanged against the Rust daemon, we must implement this protocol.

**Decision: Implement a minimal pickle protocol 2 codec + multiprocessing.connection framing in Rust.**

Rationale:
- The `multiprocessing.connection` wire format is simple: HMAC challenge-response (3 messages), then length-prefixed pickle blobs
- The pickle subset needed is narrow (~15 opcodes for dicts of strings/ints/floats/lists/None/bool)
- HMAC auth uses SHA-256 on Python 3.12+ (with `{sha256}` prefix), MD5 on legacy Python — `hmac` + `sha2` crates handle modern, `md-5` for legacy fallback
- Alternative (JSON/msgpack) would break `rnstatus`/`rnpath` compatibility, defeating the purpose
- Risk mitigated by implementing against golden trace byte sequences, not spec guesses

Record in DIFFS.md: Any pickle opcode encountered in the wild that Rust doesn't handle is an accepted temporary gap.

---

## Session Plan (13 Sessions)

Each session is self-contained: clear context between sessions, TDD red-green, full E2E.

---

### Session 1: EPIC-00a — Contract Freeze and Probe Scripts

**Goal:** Freeze the compatibility contract. Write Python probe scripts to capture golden traces from stock `rnsd`.

**Dependencies:** None.

**Red tests:**
- `tests/shared_contract/test_fixture_index.py` — fails because fixture index doesn't exist
- `tests/shared_contract/test_reference_inventory.py` — fails because reference inventory is incomplete

**Steps:**
1. Pin exact Python Reticulum version/commit in `contracts/REFERENCE.md`
2. Install `rns` at that version in the devcontainer
3. Freeze in-scope config surface in `contracts/SCOPE.md` (6 keys)
4. Write probe scripts under `tests/shared_contract/probes/`:
   - `probe_daemon_start.py` — starts `rnsd`, captures socket names, readiness
   - `probe_attach.py` — starts `rnsd`, attaches one Python client, captures raw HDLC bytes
   - `probe_control.py` — connects to RPC socket, captures HMAC auth exchange + `get interface_stats` request/response in raw bytes
   - `probe_multi_client.py` — two clients attach, captures announce relay
   - `probe_tcp.py` — `shared_instance_type = tcp`, captures TCP attach + control port
5. Create fixture storage structure: `tests/fixtures/shared-instance/{unix,tcp}/{scenario}/`
6. Create `tests/fixtures/shared-instance/index.json` manifest

**Green checks:** Probe scripts run against stock `rnsd` without error. Fixture index test passes.

**Evidence:** Frozen contract docs, working probe scripts.

**Files modified:**
- `contracts/REFERENCE.md`, `contracts/SCOPE.md`
- New: `tests/shared_contract/probes/*.py`
- New: `tests/shared_contract/test_fixture_index.py`, `test_reference_inventory.py`
- New: `tests/fixtures/shared-instance/index.json`

---

### Session 2: EPIC-00b — Golden Trace Capture

**Goal:** Execute probes, capture golden traces for all 10 required scenarios. Analyze and document the `multiprocessing.connection` wire format from actual traces.

**Dependencies:** Session 1.

**Red tests:**
- `tests/shared_contract/test_golden_traces.py` — fails because golden trace fixtures not populated

**Steps:**
1. Run each probe against Python `rnsd`, save outputs to fixture files:
   - `tests/fixtures/shared-instance/unix/{daemon-start,first-attach,multi-client-announce,control-status-query}/`
   - `tests/fixtures/shared-instance/tcp/{daemon-start,first-attach,control-status-query}/`
2. Capture raw bytes of HMAC auth exchange (CHALLENGE, DIGEST, WELCOME) and one complete RPC request/response cycle
3. Document exact pickle opcodes observed in `contracts/REFERENCE.md` (supplemental section)
4. Document exact `multiprocessing.connection` framing (length prefix, auth sequence)
5. Populate `notes.md` for each scenario
6. Update `contracts/GOLDEN_TRACES.md` with completion status

**Green checks:** `test_golden_traces.py` passes. Control-plane byte traces documented.

**Evidence:** Populated fixture directory, annotated control plane byte traces. EPIC-00 marked complete.

**Files modified:**
- New: `tests/fixtures/shared-instance/` tree (all scenarios)
- `contracts/GOLDEN_TRACES.md`, `contracts/REFERENCE.md`
- New: `tests/shared_contract/test_golden_traces.py`
- `docs/shared-instance/TRACKER.md` — EPIC-00 → `complete`

---

### Session 3: EPIC-01 — Daemon Surface

**Goal:** Create a dedicated `SharedDaemon` abstraction and binary entry point, separate from the example. Shared-instance config keys. Exclusive bind enforcement.

**Dependencies:** Session 2 (EPIC-00 complete).

**Red tests:**
- `crates/rete-daemon/tests/shared_daemon_boot.rs`:
  - `test_daemon_starts_from_shared_config` — `SharedInstanceConfig` doesn't exist
  - `test_duplicate_daemon_bind_fails` — no exclusivity check
  - `test_daemon_shutdown_clean` — no structured shutdown

**Steps:**
1. Add `SharedInstanceConfig` to `crates/rete-daemon/src/config.rs`:
   - `instance_name: String` (default "default")
   - `shared_instance_type: SharedInstanceType` (Unix | Tcp)
   - `shared_instance_port: Option<u16>` (default 37428)
   - `instance_control_port: Option<u16>` (default 37429)
   - `rpc_key: Option<String>`
2. Add `[shared_instance]` section to TOML config struct
3. Create `crates/rete-daemon/src/daemon.rs` — `SharedDaemon` struct:
   - Owns `TokioNode`, `InterfaceSlot` vec, listener handles
   - `start(config) -> Result<()>` — parse config, load identity, bind listeners, run node loop
   - `shutdown()` — drain, persist, exit
   - Exclusivity: bind failure on duplicate instance name (Unix) or port (TCP)
4. Create `crates/rete-daemon/src/bin/rete-shared.rs` — the supported daemon binary
5. Emit `DAEMON_READY` on stdout after listeners bound, `DAEMON_SHUTDOWN` on clean exit
6. Wire TOML + CLI arg parsing for the new config keys

**Green checks:** All three Rust integration tests pass. `cargo build -p rete-daemon --bin rete-shared` produces binary.

**E2E:**
- Start daemon in Unix mode, verify `DAEMON_READY`
- Start daemon in TCP mode, verify `DAEMON_READY`
- Start two daemons same instance name, verify second fails

**Evidence:** Passing tests, binary artifact. EPIC-01 marked complete.

**Files modified:**
- `crates/rete-daemon/src/config.rs` — add `SharedInstanceConfig`, `[shared_instance]` TOML section
- New: `crates/rete-daemon/src/daemon.rs`
- New: `crates/rete-daemon/src/bin/rete-shared.rs`
- `crates/rete-daemon/src/lib.rs` — add `pub mod daemon;`
- `crates/rete-daemon/Cargo.toml` — add `[[bin]]`
- New: `crates/rete-daemon/tests/shared_daemon_boot.rs`
- `docs/shared-instance/TRACKER.md` — EPIC-01 → `complete`

---

### Session 4: EPIC-02 — Unix Shared-Attach Compatibility

**Goal:** Stock Python shared-mode clients attach unchanged to the Rust daemon over Unix.

**Dependencies:** Session 3.

**Red tests:**
- `tests/interop/shared_mode/unix/attach_single.py` — Python `RNS.Reticulum(shared_instance=True)` fails to attach
- `tests/interop/shared_mode/unix/attach_multi.py` — two Python clients fail
- `tests/interop/shared_mode/unix/reconnect.py` — reconnect after drop fails

**Steps:**
1. Create `tests/interop/shared_mode/shared_mode_helpers.py`:
   - `start_rete_daemon(mode, instance_name, ...)` — starts `rete-shared` binary
   - `start_python_shared_client(config_dir, ...)` — creates Python RNS client in shared mode
   - Structured event emission per TEST_STRATEGY.md (`TEST_EVENT:{...}`)
2. Verify Rust daemon's Unix socket path matches Python's `\0rns/{instance_name}` — already confirmed in `local.rs:68`
3. Verify no handshake needed — data socket is HDLC-only, confirm against golden traces
4. Write single-client test: start Rust daemon, Python client attaches, sends announce, daemon relays
5. Write multi-client test: two Python clients, announces visible to each other
6. Write reconnect test: client drops, reconnects, still works
7. Fix any framing/naming differences. Record unfixable diffs in DIFFS.md

**Green checks:** All three Python E2E tests pass.

**Parity rows covered:** S1-GEN-ATTACH-001, S1-UNX-ATTACH-001, S1-UNX-ATTACH-002, S1-UNX-ATTACH-003.

**Files modified:**
- New: `tests/interop/shared_mode/shared_mode_helpers.py`
- New: `tests/interop/shared_mode/unix/attach_single.py`
- New: `tests/interop/shared_mode/unix/attach_multi.py`
- New: `tests/interop/shared_mode/unix/reconnect.py`
- `docs/shared-instance/PARITY_TEST_MATRIX.md` — mark rows `covered`

---

### Session 5: EPIC-03 — TCP Shared-Attach Compatibility

**Goal:** Stock Python shared-mode clients attach unchanged over TCP (`shared_instance_type = tcp`).

**Dependencies:** Session 4.

**Red tests:**
- `tests/interop/shared_mode/tcp/attach_single.py`
- `tests/interop/shared_mode/tcp/attach_multi.py`
- `tests/interop/shared_mode/tcp/reconnect.py`

**Steps:**
1. Analyze golden traces for TCP shared attach — verify no IFAC on shared port (shared attach is local-trust)
2. Implement TCP shared-attach listener in daemon — **separate** from the Reticulum `TcpServer`:
   - Binds `shared_instance_port` (default 37428) on `127.0.0.1`
   - HDLC framing, no IFAC
   - Uses `ClientHub` for multi-client relay
3. Add TCP shared-attach listener to `SharedDaemon::start()` when `shared_instance_type = Tcp`
4. Mirror Unix test topology with TCP config:
   ```ini
   [reticulum]
     shared_instance_type = tcp
     shared_instance_port = 37428
   ```
5. Debug and fix any TCP-specific issues

**Green checks:** All three TCP E2E tests pass.

**Parity rows covered:** S1-GEN-ATTACH-002, S1-TCP-ATTACH-001, S1-TCP-ATTACH-002, S1-TCP-ATTACH-003.

**Files modified:**
- `crates/rete-daemon/src/daemon.rs` — add TCP shared-attach listener
- New: `tests/interop/shared_mode/tcp/attach_single.py`
- New: `tests/interop/shared_mode/tcp/attach_multi.py`
- New: `tests/interop/shared_mode/tcp/reconnect.py`

---

### Session 6: EPIC-04a — Control Plane Wire Format and Auth

**Goal:** Implement `multiprocessing.connection` wire protocol, HMAC auth, and minimal pickle codec in Rust.

**Dependencies:** Session 5. Golden traces from Session 2 provide exact byte sequences.

**Red tests:**
- `crates/rete-daemon/tests/pickle_test.rs`:
  - `test_decode_golden_rpc_request` — fails, no pickle module
  - `test_encode_rpc_response` — encode response, decode with Python, verify match
- `crates/rete-daemon/tests/rpc_auth_test.rs`:
  - `test_hmac_challenge_response` — simulated auth, fails, no rpc module

**Steps:**
1. Create `crates/rete-daemon/src/pickle.rs`:
   - `enum PickleValue { None, Bool, Int, Float, Bytes, String, List, Dict }`
   - `fn decode(data: &[u8]) -> Result<PickleValue>` — protocol 2 stack-machine decoder (~15 opcodes)
   - `fn encode(value: &PickleValue) -> Vec<u8>` — protocol 2 encoder
   - Validate against golden trace pickle bytes
2. Create `crates/rete-daemon/src/rpc.rs`:
   - `multiprocessing.connection` framing: 4-byte big-endian length prefix for messages
   - HMAC auth handshake: CHALLENGE (20-byte nonce), DIGEST (HMAC-MD5), WELCOME/FAILURE
   - Authkey derivation from transport identity or explicit `rpc_key`
3. Unit test against exact golden trace byte sequences

**Green checks:** Pickle decode/encode passes against golden traces. Auth handshake passes against golden auth bytes.

**Parity rows touched:** Foundation for S1-GEN-CTRL-001.

**Files modified:**
- New: `crates/rete-daemon/src/pickle.rs`
- New: `crates/rete-daemon/src/rpc.rs`
- `crates/rete-daemon/src/lib.rs` — add modules
- `crates/rete-daemon/Cargo.toml` — add `md-5` dependency
- New: `crates/rete-daemon/tests/pickle_test.rs`
- New: `crates/rete-daemon/tests/rpc_auth_test.rs`

---

### Session 7: EPIC-04b — RPC Command Handlers

**Goal:** Implement in-scope RPC command handlers. Validate with stock `rnstatus` and `rnpath`.

**Dependencies:** Session 6.

**Red tests:**
- `tests/interop/shared_mode/unix/control_status.py` — `rnstatus` against Rust daemon fails
- `tests/interop/shared_mode/tcp/control_status.py` — TCP fails
- `tests/interop/shared_mode/unix/control_auth_fail.py` — wrong key not rejected
- `tests/interop/shared_mode/tcp/control_auth_fail.py`

**Steps:**
1. Define v1 RPC command set (frozen from golden traces):
   - `get interface_stats`, `get path_table`, `get rate_table`, `get next_hop`, `get link_count`
   - `get packet_rssi/snr/q`, `get blackholed_identities`
   - `drop path`, `drop all_via`, `drop announce_queues`
2. Create `crates/rete-daemon/src/rpc_handler.rs`:
   - Match pickle dict `{"get": "command_name"}` to handlers
   - Each handler reads from `HostedNodeCore` state, returns pickle dict
3. Create `crates/rete-daemon/src/rpc_listener.rs`:
   - `RpcListener` binds `\0rns/{name}/rpc` (Unix) or `instance_control_port` (TCP)
   - Accept loop: auth handshake, then pickle request/response
4. Wire into `SharedDaemon` — start RPC listener alongside data listeners
5. Wire `rpc_key` config
6. Test with actual `rnstatus` against Rust daemon (Unix and TCP)
7. Test auth failure with wrong key

**Green checks:** `rnstatus` produces output against Rust daemon. Auth failure correctly rejects.

**Parity rows covered:** S1-GEN-CTRL-001, S1-UNX-CTRL-001, S1-TCP-CTRL-001, S1-UNX-CTRL-002, S1-TCP-CTRL-002, S1-TCP-CTRL-003.

**Files modified:**
- New: `crates/rete-daemon/src/rpc_handler.rs`
- New: `crates/rete-daemon/src/rpc_listener.rs`
- `crates/rete-daemon/src/daemon.rs` — wire RPC listener
- New: `tests/interop/shared_mode/{unix,tcp}/control_*.py`

---

### Session 8: EPIC-05 — Canonical Shared State and Session Semantics

**Goal:** Replace relay-only semantics with daemon-owned canonical shared state. Multi-client routing.

**Dependencies:** Session 7.

**Red tests:**
- `crates/rete-daemon/tests/shared_sessions.rs`:
  - `test_session_registry_lifecycle`
  - `test_ownership_cleanup`
  - `test_canonical_routing`
- `tests/interop/shared_mode/unix/announce_visible.py` — client A announces, client B sees via daemon
- `tests/interop/shared_mode/unix/detach_cleanup.py` — detach removes only client-owned state

**Steps:**
1. Create `crates/rete-daemon/src/session.rs` — `SessionRegistry`:
   - Track client sessions with stable IDs
   - Track client-owned registrations (destinations, links)
   - Daemon-owned state: path table, known identities, transport routing
   - Cleanup on client detach: remove client registrations, preserve daemon state
2. Implement `shared_connection_disappeared()` equivalent:
   - Tear down client's links
   - Remove client's destination registrations from transport table
3. Implement routing rules:
   - Announces: broadcast to all local clients
   - DATA for local destination: route to owning client only
   - Link traffic: route to link endpoint owner
4. Integrate into `SharedDaemon`
5. Test multi-client announce visibility (Unix + TCP)
6. Test detach doesn't corrupt other clients

**Green checks:** Session tests pass. Announce + detach E2E tests pass.

**Parity rows covered:** S1-GEN-STATE-001 through S1-GEN-STATE-003, S1-UNX-STATE-001, S1-TCP-STATE-001, S1-UNX-STATE-002, S1-TCP-STATE-002.

**Files modified:**
- New: `crates/rete-daemon/src/session.rs`
- `crates/rete-daemon/src/daemon.rs` — integrate session registry
- New: `crates/rete-daemon/tests/shared_sessions.rs`
- New: `tests/interop/shared_mode/unix/announce_visible.py`
- New: `tests/interop/shared_mode/unix/detach_cleanup.py`
- New: TCP mirrors

---

### Session 9: EPIC-06 — Config, Persistence, and Restart

**Goal:** Daemon survives restart with state intact. Config validation. Multi-instance isolation.

**Dependencies:** Session 8.

**Red tests:**
- `crates/rete-daemon/tests/shared_restart.rs`:
  - `test_restart_state_restore`
  - `test_multi_instance_isolation`
  - `test_config_validation`
- `tests/interop/shared_mode/unix/restart.py` — Python client reattach after Rust daemon restart

**Steps:**
1. Integrate `JsonFileStore` snapshot into `SharedDaemon` for periodic + shutdown persistence
2. Implement startup restore: load snapshot, rebuild path table + known identities
3. Multi-instance isolation: separate sockets + data dirs per instance
4. Config validation: reject invalid combos, conflicting ports
5. Test restart cycle: Python client discovers paths -> stop daemon -> restart -> paths survive
6. Test two daemons with different names don't interfere

**Green checks:** Restart + isolation + config tests pass.

**Parity rows covered:** S2-GEN-RESTART-001, S2-GEN-RESTART-002, S2-GEN-OPER-001, S2-UNX-RESTART-001/002, S2-TCP-RESTART-001/002.

---

### Session 10: EPIC-07 — Operator Utility Parity

**Goal:** `rnstatus` and `rnpath` fully work. Operator diagnostics.

**Dependencies:** Session 9.

**Red tests:**
- `tests/interop/shared_mode/unix/rnstatus_full.py`
- `tests/interop/shared_mode/unix/rnpath_query.py`
- TCP mirrors

**Steps:**
1. Verify `rnstatus` output against Rust daemon matches Python `rnsd` (use golden traces)
2. Verify `rnpath` query/resolve work
3. Add structured log messages for bind failures, auth failures, config errors
4. Test E2E over Unix and TCP
5. Test error visibility

**Green checks:** `rnstatus`/`rnpath` produce correct output. Error diagnostics visible.

**Parity rows covered:** S2-UNX-OPER-002/003, S2-TCP-OPER-002/003, S2-UNX-OPER-001, S2-TCP-OPER-001.

---

### Session 11: EPIC-08a — Full E2E Matrix: Unix Protocol Scenarios

**Goal:** Prove full protocol parity for Unix: announce, data, link, request, resource, LXMF.

**Dependencies:** Session 10.

**Red tests (all Unix):**
- `tests/interop/shared_mode/unix/announce.py`
- `tests/interop/shared_mode/unix/data.py`
- `tests/interop/shared_mode/unix/link.py`
- `tests/interop/shared_mode/unix/request.py`
- `tests/interop/shared_mode/unix/resource_small.py`
- `tests/interop/shared_mode/unix/resource_large.py`
- `tests/interop/shared_mode/unix/resource_corrupt.py`
- `tests/interop/shared_mode/unix/lxmf_direct.py`
- `tests/interop/shared_mode/unix/lxmf_opportunistic.py`
- `tests/interop/shared_mode/unix/lxmf_propagation.py`

**Steps:**
1. Each test: Rust daemon + Python shared-mode client + peer
2. Daemon acts as transparent shared instance — if data relay is correct, tests should pass without new daemon code
3. Debug failures (likely: link traffic routing, resource segmentation, LXMF delivery)
4. Emit structured events per TEST_STRATEGY.md

**Green checks:** All Unix protocol E2E tests pass.

**Parity rows covered:** All remaining S1-UNX-* rows (ANNC, DATA, LINK, REQ, RSRC, LXMF).

---

### Session 12: EPIC-08b — Full E2E Matrix: TCP Protocol Scenarios

**Goal:** Mirror Session 11 for TCP shared attach.

**Dependencies:** Session 11.

**Red tests:** TCP mirrors of all Session 11 tests.

**Steps:** Same topology with TCP config. Fix any TCP-specific issues.

**Green checks:** All TCP protocol E2E tests pass. **Stage 1 complete.**

**Parity rows covered:** All remaining S1-TCP-* rows.

---

### Session 13: EPIC-09 — Soak, Robustness, and Cutover — COMPLETE (2026-04-05)

**Goal:** Validate stability under stress. Cutover/rollback documentation.

**Dependencies:** Session 12.

**Red tests:**
- `tests/interop/shared_mode/unix/soak.py` — attach/detach churn (100 cycles)
- `tests/interop/shared_mode/tcp/soak.py`
- `tests/interop/shared_mode/unix/robustness.py` — malformed traffic, half-open connections
- `tests/interop/shared_mode/tcp/robustness.py`

**Steps:**
1. Soak workloads: 100 attach/detach cycles, sustained traffic for 5 min, restart during churn
2. Robustness: garbage bytes to data socket, garbage to control socket, half-open connections, invalid auth
3. Monitor for crashes, leaked sessions, memory growth
4. Write `docs/shared-instance/CUTOVER_CHECKLIST.md` and `ROLLBACK_CHECKLIST.md`
5. Dry-run cutover and rollback

**Green checks:** Soak + robustness pass. Cutover/rollback dry-run green.

**Parity rows covered:** All S3-* rows. **All 76 parity rows covered. Program complete.**

---

## Session-to-EPIC Coverage Summary

| Session | EPIC | New Parity Rows | Cumulative |
|---------|------|----------------|------------|
| 1 | EPIC-00a | 0 (foundation) | 0 |
| 2 | EPIC-00b | 0 (traces) | 0 |
| 3 | EPIC-01 | 0 (daemon surface) | 0 |
| 4 | EPIC-02 | 4 | 4 |
| 5 | EPIC-03 | 4 | 8 |
| 6 | EPIC-04a | 0 (wire format) | 8 |
| 7 | EPIC-04b | 6 | 14 |
| 8 | EPIC-05 | 7 | 21 |
| 9 | EPIC-06 | 9 | 30 |
| 10 | EPIC-07 | 6 | 36 |
| 11 | EPIC-08a | ~12 | 48 |
| 12 | EPIC-08b | ~12 | 60 |
| 13 | EPIC-09 | 16 | 76 |

---

## Blockers and Risks

### Blockers (must resolve before implementation)
1. **Python RNS not installed** in devcontainer — need `pip install rns` or `uv pip install rns` for probes and E2E tests
2. **HMAC auth uses SHA-256** on Python 3.12+ with `{sha256}` prefix in challenges; legacy Python uses MD5 without prefix. Rust must handle both. Verified via golden traces 2026-04-04
3. **Pickle protocol version** — verify which protocol version `multiprocessing.connection` uses (likely 2 or 4) from golden traces

### Risks
1. **Pickle complexity creep** — if real RPC payloads use more opcodes than expected, the decoder grows. Mitigated by golden trace capture first.
2. **Session routing correctness** — current `ClientHub::broadcast` sends to all clients. Python routes DATA to specific clients. Session 8 must fix this or LXMF will break silently.
3. **TCP shared-attach vs normal TCP interface confusion** — daemon must maintain TWO separate TCP listeners (shared-attach on 37428, normal transport on 4242). Session 5 must enforce this.
4. **`rnstatus` response shape** — if the Rust daemon's response dicts have slightly different keys/types than Python, `rnstatus` may crash. Golden traces are the safety net.

### Assumptions
1. The devcontainer has network access to install Python packages
2. Python `rnsd` can run inside the devcontainer for golden trace capture
3. Abstract-namespace Unix sockets work in the devcontainer (Linux kernel required)
4. The `multiprocessing.connection` protocol hasn't changed between the pinned Python version and the one used to capture traces

---

## Verification — Per Session

Every session must end with:
1. `cargo test --workspace` — all unit tests pass (no regressions)
2. The session's specific red tests turned green
3. The existing E2E interop suite still passes (no regressions):
   ```bash
   cd tests/interop && for test in live_interop link_interop channel_interop resource_interop relay_interop transport_relay_interop path_request_interop proof_routing_interop ifac_interop robustness_interop; do
     uv run python ${test}.py --rust-binary ../../target/debug/rete --timeout 45
   done
   ```
4. Any new shared-mode E2E tests pass
5. PARITY_TEST_MATRIX.md rows updated
6. TRACKER.md task evidence recorded
7. Any behavior deltas recorded in DIFFS.md
