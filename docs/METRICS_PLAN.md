# Rete Metrics & Observability Plan

## Goal

Add comprehensive metrics tracking to rete, matching Python RNS's observability
layer. These metrics will feed a future web dashboard (see WEB_CLIENT_PLAN.md)
and an `rnstatus`-equivalent CLI tool.

## Design Principles

- **no_std compatible**: Core counters must work on ESP32 (no `std::time::Instant`,
  use caller-provided timestamps)
- **Zero-cost when unused**: Counters are simple integer fields, no allocations
- **Pull-based**: The caller queries stats when needed, no background threads
- **Incrementally adoptable**: Each phase is independently useful

---

## Phase 1: Interface-Level Byte/Packet Counters

**Crate**: `rete-stack` (on the `ReteInterface` trait or a wrapper)

Add an `InterfaceStats` struct that wraps any `ReteInterface` and counts traffic:

```rust
pub struct InterfaceStats {
    pub rxb: u64,           // total bytes received
    pub txb: u64,           // total bytes transmitted
    pub rx_packets: u64,    // total packets received
    pub tx_packets: u64,    // total packets transmitted
    pub rx_errors: u64,     // recv errors
    pub tx_errors: u64,     // send errors
}
```

**Where to increment**: In the `ReteInterface` wrapper — every `recv()` increments
`rxb` + `rx_packets`, every `send()` increments `txb` + `tx_packets`.

**Implementation approach**: Create a `CountedInterface<I: ReteInterface>` wrapper
in `rete-stack` that delegates to the inner interface and bumps counters. This
avoids modifying every interface implementation. The wrapper exposes `stats()`
to read current values.

**Python equivalent**: `Interface.rxb`, `Interface.txb` (base class attributes
incremented in `processIncoming()` / `processOutgoing()`)

---

## Phase 2: Transport-Level Counters

**Crate**: `rete-transport`

Add a `TransportStats` struct as a field on `Transport`:

```rust
pub struct TransportStats {
    // Global traffic
    pub total_rxb: u64,
    pub total_txb: u64,

    // Packet disposition counters
    pub packets_received: u64,
    pub packets_sent: u64,
    pub packets_forwarded: u64,     // relayed for other nodes
    pub packets_dropped_dedup: u64, // dropped as duplicate
    pub packets_dropped_invalid: u64,
    pub packets_dropped_ifac: u64,  // IFAC verification failed

    // Announce counters
    pub announces_received: u64,
    pub announces_sent: u64,
    pub announces_retransmitted: u64,
    pub announces_rate_limited: u64,

    // Link counters
    pub links_established: u64,
    pub links_closed: u64,
    pub links_failed: u64,         // handshake failures
    pub link_requests_received: u64,

    // Path counters
    pub paths_learned: u64,
    pub paths_expired: u64,

    // Crypto error counters
    pub crypto_failures: u64,      // decrypt/verify failures

    // Uptime
    pub started_at: u64,           // caller-provided timestamp (secs)
}
```

**Where to increment**: Inside `Transport::ingest()`, `Transport::handle_tick()`,
`Transport::flush_announces()`, and the various `handle_*` methods. Each code
path that drops, forwards, or processes a packet bumps the corresponding counter.

**Expose via**: `Transport::stats() -> &TransportStats`

**Python equivalent**: `Transport.traffic_rxb`, `Transport.traffic_txb`,
table sizes via `len()`, announce rate table.

---

## Phase 3: Table Snapshots

**Crate**: `rete-transport`

Add methods to expose current table state for dashboard rendering:

```rust
impl Transport {
    /// Summary of path table contents
    pub fn path_summary(&self) -> PathSummary {
        PathSummary {
            total: self.path_count(),
            by_hops: [count_1hop, count_2hop, ...],  // histogram
            oldest_secs: oldest_path_age,
            newest_secs: newest_path_age,
        }
    }

    /// All paths with metadata (for topology view)
    pub fn path_entries(&self) -> Vec<PathInfo> { ... }

    /// Active links with metrics
    pub fn link_entries(&self) -> Vec<LinkInfo> { ... }

    /// Announce rate table (rate limits, violations)
    pub fn announce_rate_entries(&self) -> Vec<AnnounceRateInfo> { ... }
}
```

**PathInfo** includes: dest_hash, hops, via (next-hop), learned_at, last_accessed,
snr, interface_idx.

**LinkInfo** includes: link_id, state, rtt, last_inbound, last_outbound,
activated_at, peer_identity_hash.

**Python equivalent**: `Transport.path_table`, `Transport.link_table`,
`Transport.announce_rate_table` (accessed directly as dicts).

---

## Phase 4: Live Throughput Computation

**Crate**: `rete-transport` or `rete-stack`

Python computes `current_rx_speed` / `current_tx_speed` in a background thread
(`count_traffic_loop`) that samples `rxb`/`txb` every second and computes deltas.

For rete, do this in `handle_tick()` (already called periodically):

```rust
pub struct ThroughputTracker {
    last_rxb: u64,
    last_txb: u64,
    last_sample_time: u64,  // seconds
    pub rx_bps: u64,        // current receive bits/sec
    pub tx_bps: u64,        // current transmit bits/sec
}
```

Update on each tick: `rx_bps = (current_rxb - last_rxb) * 8 / elapsed_secs`.

---

## Phase 5: Announce Frequency Tracking

**Crate**: `rete-transport`

Per-interface announce rate, matching Python's `ia_freq_deque` / `oa_freq_deque`:

Store timestamps of last N announces (N=6) per interface. Compute frequency as
`N / (newest - oldest)` announces per second.

Add to the interface stats or as a separate tracker passed through the event system.

---

## Phase 6: Link Quality Metrics (RSSI/SNR/Q)

**Crate**: `rete-core` or `rete-stack`

When the underlying interface provides signal quality (RNode via KISS, or
AutoInterface in the future), attach it to inbound packets:

```rust
pub struct PacketMeta {
    pub rssi: Option<f32>,  // dBm
    pub snr: Option<f32>,   // dB
    pub q: Option<f32>,     // 0.0-1.0 quality
}
```

Thread this through `ingest()` so Transport can store per-link RSSI/SNR/Q
(last received values) and per-path SNR (already partially implemented as
`last_snr` on PathEntry).

**Python equivalent**: `interface.r_stat_rssi`, `interface.r_stat_snr`,
`Link.rssi`, `Link.snr`, `Link.q`.

---

## Phase 7: Stats Export API

**Crate**: `rete-stack` (on `NodeCore`)

Aggregate all stats into a single `NodeStats` struct:

```rust
pub struct NodeStats {
    pub transport: TransportStats,
    pub interfaces: Vec<(u8, String, InterfaceStats)>,  // idx, name, stats
    pub paths: PathSummary,
    pub links: Vec<LinkInfo>,
    pub uptime_secs: u64,
    pub identity_hash: [u8; 16],
}

impl NodeCore {
    pub fn stats(&self, now: u64) -> NodeStats { ... }
}
```

This is the single entry point a web dashboard or CLI tool calls to get
everything. Serializable to JSON via serde (behind a feature flag to keep
no_std clean).

**Python equivalent**: `Reticulum.get_interface_stats()` (lines 1090-1269 in
Reticulum.py), used by `rnstatus`.

---

## Implementation Order

1. **Phase 2 first** (TransportStats) — most value, self-contained in one crate
2. **Phase 1 next** (InterfaceStats wrapper) — enables per-interface breakdown
3. **Phase 7** (Stats export API) — aggregation layer for consumers
4. **Phase 3** (Table snapshots) — needed for topology views
5. **Phase 4** (Throughput) — nice-to-have, trivial once counters exist
6. **Phase 5** (Announce frequency) — nice-to-have
7. **Phase 6** (Link quality) — depends on interface support (RNode)

---

## Testing Strategy

- Unit tests: Verify counters increment correctly by ingesting known packets
  and checking `stats()` values
- Interop tests: Run existing E2E tests, verify stats are non-zero and sensible
  (e.g., `packets_received > 0`, `rxb > 0` after an announce exchange)
- Snapshot tests: Serialize `NodeStats` to JSON, verify structure matches
  expected schema (important for the web dashboard contract)

---

## Compatibility Notes

- All stats types should be `#[derive(Clone, Debug, Default)]`
- Add `#[derive(serde::Serialize)]` behind a `serde` feature flag
- Keep `no_std` compatible — use `u64` timestamps, not `std::time::Instant`
- ESP32 has limited RAM — keep per-entry overhead small (no String allocations
  in hot paths, use fixed-size arrays where possible)
