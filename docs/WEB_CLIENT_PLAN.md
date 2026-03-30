# Rete Web Client — Zero-Install Reticulum in the Browser

## Vision

A progressive web app (PWA) that runs a full Reticulum node in the browser
via WASM. No installation, no Python, no terminal — click a link and you're
on the mesh. Identity keys stay local (IndexedDB). Messages are end-to-end
encrypted. The gateway server can't read your content.

The gateway binary (`rete-web-server`) is simultaneously a full Reticulum
transport node, a web server, and a WebSocket gateway. One binary, one
process — anyone who runs it is hosting a Reticulum node AND a web UI for
others to join through.

---

## Value Proposition

**For users**: Zero-friction onramp to Reticulum. Someone sends you a URL,
you open it, you have a Reticulum identity and can message anyone on the
mesh. No Python, no pip, no config files. The "just send them a link"
onboarding that Reticulum currently lacks.

**For node operators**: One binary gives you a transport node with a built-in
web dashboard (topology, metrics, map) AND a gateway for browser clients.
Replace rnsd + NomadNet + manual monitoring with a single deployment.

**For the ecosystem**: Dramatically lowers the barrier to trying Reticulum.
A community mesh where onboarding is "open this URL" instead of a 10-step
install guide is a fundamentally different adoption curve.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Browser (PWA)                                               │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐    │
│  │  Svelte UI Layer                                      │    │
│  │                                                       │    │
│  │  ┌────────────┐  ┌────────────┐  ┌───────────────┐   │    │
│  │  │ Messaging  │  │ Network    │  │ Settings      │   │    │
│  │  │ (LXMF)    │  │ Dashboard  │  │               │   │    │
│  │  │           │  │            │  │ Identity mgmt │   │    │
│  │  │ Contacts  │  │ Topology   │  │ Gateway config│   │    │
│  │  │ Groups    │  │ map        │  │ Key export    │   │    │
│  │  │ Files     │  │ Live stats │  │               │   │    │
│  │  └────────────┘  └────────────┘  └───────────────┘   │    │
│  └──────────────────────┬───────────────────────────────┘    │
│                         │ wasm-bindgen FFI                    │
│  ┌──────────────────────┴───────────────────────────────┐    │
│  │  WASM Module (Rust)                                   │    │
│  │                                                       │    │
│  │  rete-core      — packet parsing, crypto              │    │
│  │  rete-transport — routing, path tables, announces     │    │
│  │  rete-stack     — NodeCore state machine              │    │
│  │  rete-web-wasm  — JS bindings, WS transport, storage  │    │
│  └──────────────────────┬───────────────────────────────┘    │
│                         │ WebSocket (binary frames)          │
└─────────────────────────┼───────────────────────────────────┘
                          │
                          │ wss://mesh.example.com/rns
                          │
┌─────────────────────────┼───────────────────────────────────┐
│  Gateway Server          │                                    │
│  (single rete-web-server binary)                              │
│                          │                                    │
│  ┌───────────────────────┴──────────────────────────────┐    │
│  │  axum                                                 │    │
│  │                                                       │    │
│  │  GET /           → static files (HTML/JS/WASM)        │    │
│  │  WS  /rns        → bidirectional RNS packet relay     │    │
│  │  GET /api/stats  → gateway node stats (JSON)          │    │
│  │                                                       │    │
│  │  rete transport node (full routing, announce relay)    │    │
│  └───────────────────────┬──────────────────────────────┘    │
│                          │                                    │
│  Configured interfaces:                                       │
│    TCP ↔ rnsd (e.g., amsterdam:4965, btb:4242)               │
│    Serial ↔ RNode/LoRa                                       │
│    AutoInterface (LAN peers)                                  │
│    Any standard RNS interface                                 │
└──────────────────────────────────────────────────────────────┘
```

---

## Gateway Models

### Model 1: Personal gateway (primary use case)

You run `rete-web-server` on your own machine/VPS/Pi. You configure it with
YOUR interfaces — your LoRa radio, your TCP connection to specific rnsd nodes,
AutoInterface on your LAN. You access the web UI from your phone when away
from home. One user, one gateway, your networks.

This is the simple, honest model. Like using a Nomad Network node as a
personal transport node, but with a web UI built in.

### Model 2: Community gateway (demo / public access)

Run `rete-web-server` on a VPS with TCP connections to well-known public
networks (Amsterdam testnet, BetweenTheBorders, etc.). Point a domain at it.
Anyone with a browser can open the URL and see the mesh, discover nodes,
send LXMF messages. Great for demos and lowering the adoption barrier.

The gateway is a standard Reticulum transport node — browser users inherit
its network reach through the WebSocket.

### Model 3: Embedded gateway (ESP32-S3 + LoRa)

Run the full rete stack on an ESP32-S3 with an SX1262 LoRa radio. The device
creates a WiFi AP and serves the WASM client directly, or exposes a BLE GATT
service for Web Bluetooth connections. No host computer, no internet required.

```
Phone browser ──WiFi AP──→ ESP32-S3 ──LoRa──→ mesh
Phone browser ──BLE────────→ ESP32-S3 ──LoRa──→ mesh
```

The WASM + HTML assets are embedded in firmware via `include_bytes!()` (~80KB
gzipped). The embedded HTTP server (picoserve) serves them over WiFi. For the
BLE path, the web client is hosted externally (GitHub Pages, CDN) and connects
to the device via the Web Bluetooth API — no WiFi needed on the device.

This is the "zero infrastructure" play: drop the device somewhere with power
and an antenna, and anyone in WiFi/BLE range can open a browser and join the
mesh. See [RNODE_VISION.md](RNODE_VISION.md) for full details.

### Model 4: Dial-out proxy (future, needs security review)

The gateway doesn't pre-connect to networks. Instead, browser users provide
an rnsd address and the gateway opens a TCP connection on their behalf. Each
WebSocket gets its own dedicated backend TCP connection:

```
User A browser ──WS──→ gateway ──TCP──→ amsterdam-rnsd:4965
User B browser ──WS──→ gateway ──TCP──→ btb-rnsd:4242
User C browser ──WS──→ gateway ──TCP──→ private.vpn:4242
```

The gateway is a dumb WebSocket-to-TCP proxy — ~100 lines of axum code.
Security concern: this is essentially an open TCP proxy, so it needs an
allowlist of permitted target addresses or restriction to known Reticulum
ports. Defer this until Model 1 and 2 are proven.

---

## Known Public Reticulum Networks

There is no central registry — Reticulum is intentionally decentralized.
Known entry points as of early 2026:

- `amsterdam.connect.reticulum.network:4965` — main public testnet (Mark Qvist)
- `betweentheborders.com:4242` — BetweenTheBorders community network
- Others shared informally on Matrix (#reticulum:matrix.org) and Discord

For the web client, ship a small hardcoded list of known public entry points
as defaults the user can pick from, plus a text field for custom `host:port`.
Optionally fetch a community-maintained JSON list from GitHub for updates.

---

## What the Browser Node Can and Cannot Do

### Can do:
- **Send/receive LXMF messages** — the killer feature, encrypted messaging
- **Announce and be discovered** — full Reticulum identity with crypto
- **Establish links** — bidirectional encrypted sessions
- **Receive files** — LXMF attachments, browser downloads them
- **Browse the network** — path table, topology, metrics dashboard
- **Act as a destination** — Sideband/NomadNet users can message the browser node
- **Queue messages offline** — compose while disconnected, send on reconnect

### Cannot do:
- Share local files proactively (no filesystem access without user picker)
- Run as a background service (tab must be open, PWA helps somewhat)
- Access local hardware (no serial, no radio, no Bluetooth)
- Act as a useful transport relay (the gateway already does this)

### Bottom line:
A zero-install Reticulum messenger with a network dashboard. That's the
product. It won't replace Sideband for power users, but it's the easiest
possible way to get someone onto the mesh.

---

## Tech Stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| **Server** | axum + tokio | Already used by rete-linux, mature, async WS support via `axum::extract::ws` |
| **Frontend framework** | SvelteKit | Best ecosystem for maps/charts/3D, fast, small bundles, easy WASM interop |
| **WASM protocol engine** | rete-core + rete-transport + rete-stack compiled to `wasm32-unknown-unknown` | Already `no_std`, crypto crates have WASM support |
| **WASM bindings** | wasm-bindgen + wasm-pack | Standard Rust→JS bridge |
| **Maps** | MapLibre GL JS | Open source, no API key, vector tiles, overlay support |
| **Network topology** | Cytoscape.js | Purpose-built for graph visualization, force-directed layouts |
| **Charts** | Apache ECharts or Chart.js | Real-time time series, gauges, histograms |
| **3D (optional)** | Three.js | Globe view for wide-area mesh visualization |
| **Storage** | IndexedDB (via idb) | Identity keys, message history, path cache, settings |
| **Notifications** | Web Push API | Message notifications when tab is backgrounded |
| **Install** | PWA manifest + service worker | Installable on desktop/mobile, offline message queue |

### Why Svelte over Leptos (pure Rust)?

Leptos would keep everything in Rust, which is appealing. But the marquee
features (network topology graph, geographic map, real-time charts) all
depend on JS visualization libraries (Cytoscape, MapLibre, ECharts). Fighting
JS interop from Rust for the primary UI features creates more pain than the
language consistency saves. Let Svelte own rendering, let Rust own protocol
and crypto. The boundary is clean: `sendPacket(bytes)` / `onPacketReceived(bytes)`.

---

## Crate Structure

All within the existing rete monorepo — this is another target platform,
not a separate project.

```
rete/
├── crates/
│   ├── rete-core/              # unchanged — shared with all targets
│   ├── rete-transport/         # unchanged — shared with all targets
│   ├── rete-stack/             # unchanged — shared with all targets
│   ├── rete-web-common/        # shared types: WS frame format, stats schema
│   ├── rete-web-wasm/          # WASM bindings: JS API, WS transport, IndexedDB
│   └── rete-web-server/        # axum: static files + WS endpoint + stats API
├── web/
│   └── frontend/               # SvelteKit app
│       ├── src/
│       │   ├── lib/
│       │   │   ├── wasm/       # wasm-bindgen imports, typed wrappers
│       │   │   ├── stores/     # Svelte stores fed by WASM events
│       │   │   └── components/
│       │   │       ├── messaging/   # chat, contacts, LXMF
│       │   │       ├── dashboard/   # stats, charts, throughput
│       │   │       ├── topology/    # network graph (Cytoscape)
│       │   │       └── map/         # geographic overlay (MapLibre)
│       │   └── routes/         # SvelteKit pages
│       └── static/             # built WASM pkg
├── examples/
│   ├── linux/                  # existing CLI node
│   ├── esp32c6/                # existing embedded
│   └── esp32s3/                # existing embedded
```

---

## WebSocket Protocol

Binary WebSocket frames carrying raw RNS packets. Minimal framing:

```
Frame format:
  [0:2]  payload_length (u16 big-endian)
  [2:]   raw RNS packet (same bytes as TCP/serial interface)
```

This is intentionally simple — the same framing as the TCP interface but
with WebSocket as the transport. No custom protocol negotiation, no JSON
wrapping. The browser's WASM rete node treats the WebSocket exactly like
a TCP interface.

The gateway server treats each WebSocket connection as an interface instance,
feeding packets into its transport layer like any other interface.

---

## WASM Module API (wasm-bindgen exports)

```rust
// rete-web-wasm/src/lib.rs

#[wasm_bindgen]
pub struct ReteNode { /* NodeCore + Transport */ }

#[wasm_bindgen]
impl ReteNode {
    /// Create a new node, loading identity from provided bytes or generating fresh
    pub fn new(identity_bytes: Option<Vec<u8>>) -> ReteNode;

    /// Export identity for storage in IndexedDB
    pub fn export_identity(&self) -> Vec<u8>;

    /// Feed an inbound packet (from WebSocket)
    pub fn ingest(&mut self, raw: &[u8], now_secs: f64) -> JsValue; // returns outbound packets

    /// Periodic tick (call from setInterval)
    pub fn tick(&mut self, now_secs: f64) -> JsValue;

    /// Create and return an announce packet
    pub fn announce(&mut self, app_data: Option<Vec<u8>>) -> Vec<u8>;

    /// Get current stats as JSON
    pub fn stats(&self, now_secs: f64) -> JsValue;

    /// Get path table as JSON (for topology view)
    pub fn paths(&self) -> JsValue;

    /// Get active links as JSON
    pub fn links(&self) -> JsValue;

    /// Destination hash for this node
    pub fn dest_hash(&self) -> Vec<u8>;

    /// Identity hash for this node
    pub fn identity_hash(&self) -> Vec<u8>;
}
```

The Svelte frontend calls these methods, feeding WebSocket data in and
rendering the results. The `ingest()` method returns any outbound packets
that should be sent over the WebSocket.

---

## Dashboard Features

### Real-Time Stats (fed by METRICS_PLAN.md counters)

- **Traffic gauges**: Current RX/TX throughput (bits/sec)
- **Packet counters**: Received, sent, forwarded, dropped — with sparkline history
- **Announce activity**: Announces/minute, rate limit violations
- **Table sizes**: Paths known, active links, pending announces
- **Uptime**: Node uptime, WebSocket connection duration

### Network Topology View (Cytoscape.js)

- Nodes = known destinations (from path table)
- Edges = paths, weighted by hop count
- Color = freshness (green=recently heard, yellow=stale, red=expired)
- Click node → show dest hash, identity, last announce time, hop count
- Real-time: nodes appear/disappear as paths are learned/expire
- Layout: force-directed, or hierarchical showing hop distance from self

### Geographic Map (MapLibre GL)

- Plot nodes with GPS coordinates on a real map
- Lines between nodes showing links/paths
- Heat map overlay for signal quality (SNR/RSSI from RNode interfaces)
- Coverage area visualization based on known node positions
- Useful for: LoRa mesh planning, coverage assessment, finding dead zones

### Message Interface (LXMF)

- Contact list with online/offline status (based on announce recency)
- Chat thread view with message history (stored in IndexedDB)
- File attachments via LXMF
- Message delivery receipts (LXMF delivery proofs)
- Offline queue: messages composed offline, sent when WebSocket reconnects

---

## Security Model

- **Identity keys**: Generated in WASM, stored in IndexedDB, never leave browser
- **End-to-end encryption**: All RNS crypto happens in WASM — gateway sees
  only encrypted packets (same trust model as any transport node)
- **Gateway trust**: Equivalent to connecting to rnsd over TCP — the gateway
  routes packets but can't read content. Metadata (announce hashes, timing,
  packet sizes) is visible to the gateway, same as any RNS transport node
- **Key backup**: Export identity as downloadable file for backup/migration
- **Multiple gateways**: Connect to multiple gateway nodes for redundancy
- **IFAC support**: Interface Access Codes can segment traffic on shared
  gateways — two browser users with different IFACs on the same gateway
  won't see each other's traffic (private network on shared infrastructure)

---

## Development Phases

### Phase A: Dumb Pipe (days, not weeks)
- `rete-web-server`: axum serving a static HTML page + WebSocket endpoint
- WebSocket endpoint relays bytes bidirectionally to a configured TCP rnsd
- The HTML page is dead simple — connect button, hex log of packets flowing
- No WASM yet. Just prove the plumbing: browser → WS → axum → TCP → rnsd
- Success: see packets from the Reticulum network in the browser console

### Phase B: WASM Protocol Engine
- `rete-web-wasm`: Compile rete-core + rete-transport to WASM
- wasm-bindgen API: `new()`, `ingest()`, `tick()`, `announce()`
- Static page loads WASM, creates identity, announces, shows discovered
  destinations in a list
- Success: browser node announces, Python RNS on the mesh discovers it

### Phase C: Minimal Chat (the demo moment)
- SvelteKit project scaffolding
- WebSocket connection management (reconnect, status indicator)
- Identity creation/loading from IndexedDB
- Destination list (who's announcing)
- Send LXMF message to a destination, receive and display LXMF messages
- **This is where it becomes usable** — send a friend with Sideband a link,
  they message each other: one from a phone app, one from a browser tab

### Phase D: Dashboard
- Integrate metrics from METRICS_PLAN.md
- Real-time stats charts (ECharts)
- Network topology graph (Cytoscape.js)
- Path table browser

### Phase E: Full LXMF Client
- Contact management with names/notes
- Message history with IndexedDB persistence
- File attachments
- Delivery receipts
- PWA manifest + service worker for installability
- Push notifications for background message delivery

### Phase F: Geographic Map
- MapLibre integration
- Node position plotting (from GPS-tagged announces)
- Coverage visualization
- Link quality overlays (SNR/RSSI heatmaps)

---

## Deployment Models

### Personal (Raspberry Pi / home server)
```bash
rete-web-server --tcp rnsd.example.com:4242 --serial /dev/ttyUSB0 --auto
# Serves web UI on :8080, connects to rnsd + local LoRa radio + LAN peers
# Access from phone: http://mypi.local:8080
```

### Public demo (VPS)
```bash
rete-web-server \
  --tcp amsterdam.connect.reticulum.network:4965 \
  --tcp betweentheborders.com:4242 \
  --bind 0.0.0.0:443 --tls cert.pem key.pem
# Anyone can open https://mesh.example.com and join the mesh
```

### Private team (VPN / tailscale)
```bash
rete-web-server --auto --bind 100.x.y.z:8080
# Only accessible to tailnet members, AutoInterface for LAN mesh
```

In all cases: one binary, one command, zero configuration files required
(though a config file can be used for complex setups).

### Embedded (ESP32-S3 + LoRa — see RNODE_VISION.md)
```
# Device creates WiFi AP, serves WASM client, bridges to LoRa mesh
# No host computer, no internet, no configuration needed
# Phone connects to WiFi, browser auto-opens via captive portal
```

---

## BLE Transport (Web Bluetooth)

An alternative to WebSocket: the browser connects to the gateway device
directly over BLE using the Web Bluetooth API. This is most relevant for the
embedded gateway model (Model 3) but could also apply to a Pi/desktop gateway
with Bluetooth.

```
Browser (Chrome)
  |
  | Web Bluetooth API
  | BLE GATT characteristic (binary RNS packets)
  |
Gateway device (ESP32-S3 / Pi / desktop)
  |
  | LoRa / TCP / AutoInterface
  |
Reticulum mesh
```

Advantages over WebSocket:
- No WiFi AP needed on the device (lower power, simpler firmware)
- Web client hosted externally (GitHub Pages) — updates independently
- BLE pairing provides device authentication

Limitations:
- Chromium-only (Chrome, Edge). No Firefox. Limited Safari support.
- BLE MTU is 512 bytes — most RNS packets (MTU 500) fit in one write,
  but announces with large app_data may need fragmentation.
- Lower throughput than WiFi, but LoRa is the bottleneck anyway.
- Requires internet for initial page load (PWA caches for offline after).

The WASM client is the same regardless of transport — WebSocket or BLE.
Only the `ReteInterface` implementation in the browser differs.

---

## Open Questions

1. **Multiple browser tabs**: Should each tab be its own node, or share identity
   via SharedWorker / BroadcastChannel?
2. **Gateway discovery**: Hardcoded gateway URL, or some discovery mechanism?
   Could use DNS SRV records or a well-known URL convention.
3. **Mobile considerations**: Battery impact of persistent WebSocket? Service
   worker with periodic sync might be better for mobile.
4. **Gateway scaling**: One WebSocket per browser client. How many concurrent
   clients can a single gateway handle? Probably thousands (just packet relay),
   but needs benchmarking.
5. **LXMF propagation nodes**: Should the web client be able to act as a
   propagation node, or always rely on network propagation nodes for
   store-and-forward?
6. **Dial-out proxy security**: If Model 4 (user-specified rnsd targets) is
   implemented, what restrictions prevent abuse as an open TCP proxy?
   Allowlist of known ports (4242, 4965)? Rate limiting? Authentication?
7. **Identity portability**: Can a user export their browser identity and
   import it into Sideband (or vice versa)? The key format is the same
   (X25519 + Ed25519), so this should be possible.
8. **BLE fragmentation**: If Web Bluetooth is used, how to handle RNS packets
   that exceed the BLE MTU? Simple length-prefix fragmentation, or rely on
   BLE 5.0 extended MTU negotiation?
9. **Embedded gateway OTA**: How to update WASM/HTML assets on an ESP32
   without reflashing firmware? Separate flash partition? Or just reflash
   (assets are small, OTA update of full firmware is reasonable)?
