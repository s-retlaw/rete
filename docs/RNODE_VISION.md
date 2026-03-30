# Rete RNode — Full-Stack Reticulum on a Single Chip

## Vision

A standard RNode is a dumb KISS TNC — the radio is just a modem, all protocol
logic runs on the connected host (Python RNS). If we put the full rete stack
on an ESP32-S3 with a LoRa radio (SX1262/SX1276), we get something
fundamentally new: a **standalone Reticulum node that IS the radio AND the
protocol stack**, with WiFi and BLE for client access.

Any phone becomes a mesh terminal — open a browser, connect to the device,
message anyone on the LoRa mesh. No internet, no app install, no Python.

---

## Architecture

```
 Phone browser         Phone browser
      |                     |
      | WiFi AP / BLE
      |                     |
 +----+---------------------+----+
 |    ESP32-S3 + SX1262          |
 |                               |
 |  HTTP server --> WASM+HTML    |   <-- serves the browser client (WiFi path)
 |  WebSocket /rns <-> NodeCore  |   <-- bridges browser to mesh (WiFi path)
 |  BLE GATT <-> NodeCore        |   <-- bridges browser to mesh (BLE path)
 |  LoRa interface <-> NodeCore  |   <-- radio to mesh
 |                               |
 |  Full rete stack:             |
 |    routing, crypto, LXMF      |
 +---------------+---------------+
                 | LoRa RF
                 |
    +------------+------------+
    |   Reticulum mesh        |
    |   (other RNodes, rnsd   |
    |    nodes, Sideband...)  |
    +-------------------------+
```

---

## How Interop Works

### The Short Version

RNode adds **zero framing on the air**. The LoRa radio's built-in PHY layer
handles preamble, sync word, header, and CRC. What goes over RF is a standard
LoRa packet containing raw RNS packet bytes. Interop is entirely about
matching LoRa radio parameters.

A standard RNode + Python RNS:
```
[Python RNS] --KISS serial--> [RNode firmware] --LoRa RF--> air
```

Our device:
```
[rete NodeCore] --SPI--> [SX1262] --LoRa RF--> air
```

Same packets on the air. If the LoRa parameters match (frequency, spreading
factor, bandwidth, coding rate), packets are fully interoperable regardless
of implementation.

### Data Flow: Standard RNode TX

```
1. Python RNS has a raw RNS packet (up to 500 bytes)
2. Wraps in KISS: FEND(0xC0) + CMD_DATA(0x00) + escaped_data + FEND(0xC0)
3. Sends over serial/USB/BLE to RNode firmware
4. Firmware un-KISSes -> raw RNS packet bytes
5. If >255 bytes: split into two LoRa frames (see Split Packets below)
6. CSMA/CA channel access check
7. Radio transmits: LoRa PHY adds preamble + sync word + header + CRC
8. On the air: a standard LoRa packet. Nothing RNode-specific.
```

### Data Flow: Standard RNode RX

```
1. LoRa radio receives packet (PHY validates sync word + CRC)
2. Firmware reads raw bytes from radio FIFO
3. If split: reassembles from sequence numbers
4. Wraps in KISS: FEND + CMD_DATA + escaped_data + FEND
5. Sends over serial/USB/BLE to host
6. Python RNS un-KISSes -> raw RNS packet
```

### Data Flow: Our Rete RNode (no KISS needed)

```
TX: NodeCore has outbound packet -> raw bytes -> SPI -> SX1262 transmits
RX: SX1262 receives -> raw bytes -> SPI -> NodeCore::handle_ingest()
```

We skip the KISS layer entirely — there's no serial host to talk to. The
NodeCore drives the radio directly through the `rete-iface-lora` interface.

### LoRa Radio Parameters We Must Match

These come from the RNode firmware source (`sx126x.cpp`, `sx127x.cpp` in
github.com/markqvist/RNode_Firmware):

| Parameter | Value | Source |
|-----------|-------|--------|
| **Sync Word** | SX127x: `0x12`, SX126x: `0x1424` | Hardcoded in firmware (`SYNC_WORD_6X`, `SYNC_WORD_7X`) |
| **Preamble** | 18 symbols (default, adaptive) | Minimum 18, formula: `ceil(24 / symbol_time_ms)` |
| **CRC** | Enabled (LoRa hardware CRC) | `enableCrc()` called in `begin()` |
| **Header Mode** | Explicit | Default, not overridden for data packets |
| **Coding Rate** | 4/5 (default) | Configurable via KISS `CMD_CR` (0x05) |
| **Frequency** | Network-dependent | Configured via KISS `CMD_FREQUENCY` (0x01) |
| **Bandwidth** | Network-dependent (usually 125kHz) | Configured via KISS `CMD_BANDWIDTH` (0x02) |
| **Spreading Factor** | Network-dependent (usually SF7-SF12) | Configured via KISS `CMD_SF` (0x04) |
| **TX Power** | Network-dependent | Configured via KISS `CMD_TXPOWER` (0x03) |

### Sync Word Compatibility

This is the trickiest detail. SX127x chips use a 1-byte sync word register
(reg `0x39`), while SX126x chips use 2 bytes. The mapping:

- SX127x `0x12` = SX126x `0x1424` (private LoRa — what RNode uses)
- SX127x `0x34` = SX126x `0x3444` (LoRaWAN public — NOT used by RNode)

The conversion rule: a 1-byte sync word `0xYZ` maps to `0xY4Z4` on SX126x
(the `4`s are hardware control bits). Both the RNode firmware and the
`lora-phy` Rust crate use `0x1424` for SX126x, so they are already
compatible out of the box.

### Split Packets (HW_MTU = 508)

LoRa has a 255-byte maximum payload per radio frame. RNS MTU is 500 bytes.
The RNode firmware handles this by splitting large packets:

- Packets <= 255 bytes: sent as a single LoRa frame (no modification)
- Packets 256-508 bytes: split into two LoRa frames

Each fragment gets a 1-byte header prepended:
```
Header byte:  [upper nibble: sequence number] [lower nibble: flags]
Flag 0x01:    FLAG_SPLIT — indicates this is a split packet fragment
```

The receiver reassembles by matching sequence numbers and concatenating
payloads. Our `rete-iface-lora` implementation must handle this same
split/reassembly to support full-sized RNS packets over LoRa.

### What We Do NOT Need

- **KISS framing on the air** — KISS is serial-only, never transmitted
- **RNode KISS command protocol** — we configure our radio directly via SPI,
  not through KISS commands. The KISS protocol is only relevant if we also
  want to support a host connecting to our device as a TNC (optional).
- **RNode firmware compatibility** — we're not pretending to be an RNode
  peripheral. We're a full node that speaks the same LoRa PHY.

### Popular Network Settings

From the Reticulum community wiki:

| Region | Frequency | Bandwidth | Spreading Factor |
|--------|-----------|-----------|-----------------|
| EU | 867.2 MHz | 125 kHz | SF8-9 |
| EU (alt) | 869.525 MHz | 125 kHz | SF7-9 |
| US | 914.875 MHz | 125 kHz | SF7-9 |
| AU | 925.875 MHz | 125 kHz | SF8-9 |
| CN | 470-473 MHz | 125 kHz | SF8-9 |

Radios using different TX power and coding rate values can still communicate —
only frequency, bandwidth, and spreading factor must match.

### Reference: RNode KISS Commands

For completeness (needed if we ever want TNC mode or host-device comms):

| Command | Byte | Data Format |
|---------|------|-------------|
| `CMD_DATA` | `0x00` | Variable-length packet payload |
| `CMD_FREQUENCY` | `0x01` | 4 bytes, big-endian Hz |
| `CMD_BANDWIDTH` | `0x02` | 4 bytes, big-endian Hz |
| `CMD_TXPOWER` | `0x03` | 1 byte, dBm |
| `CMD_SF` | `0x04` | 1 byte (5-12) |
| `CMD_CR` | `0x05` | 1 byte (5-8 for 4/5 through 4/8) |
| `CMD_RADIO_STATE` | `0x06` | 1 byte (on/off) |
| `CMD_RADIO_LOCK` | `0x07` | Lock/unlock radio |
| `CMD_DETECT` | `0x08` | Probe for RNode presence |
| `CMD_IMPLICIT` | `0x09` | Implicit header mode toggle |
| `CMD_PROMISC` | `0x0E` | Promiscuous mode |
| `CMD_READY` | `0x0F` | Device ready signal |
| `CMD_STAT_RX` | `0x21` | RX byte count |
| `CMD_STAT_TX` | `0x22` | TX byte count |
| `CMD_STAT_RSSI` | `0x23` | Last RSSI |
| `CMD_STAT_SNR` | `0x24` | Last SNR |

Frame structure: `FEND(0xC0) + command_byte + escaped_data + FEND(0xC0)`
Escaping: `0xC0 -> 0xDB 0xDC`, `0xDB -> 0xDB 0xDD`

---

## Three Radios, One Chip

The ESP32-S3 has WiFi, BLE, and with an SPI-connected SX1262 module, LoRa.
Each serves a different role:

| Radio | Role | Range |
|-------|------|-------|
| **LoRa** | Mesh backbone — long-range packet transport | 1-20+ km |
| **WiFi** | Client access — serve WASM UI, WebSocket bridge | ~50m |
| **BLE** | Client access — low-power phone connection | ~30m |

All three feed into the same multi-interface node loop. A packet received
over LoRa can be forwarded to WiFi and BLE clients, and vice versa.

---

## Browser Connection Paths

### Path A: WiFi AP + WebSocket (self-contained)

The device creates a WiFi access point and serves everything:

```
Phone connects to WiFi "ReteNode-XXXX"
  --> browser opens 192.168.4.1
  --> picoserve serves gzipped WASM + HTML
  --> WASM loads, generates identity
  --> WebSocket connects to /rns
  --> packets flow: browser <-> WebSocket <-> NodeCore <-> LoRa <-> mesh
```

Advantages:
- Completely self-contained. No internet, no external server.
- Works with any browser on any phone.
- Captive portal can auto-open the page on connection.

Considerations:
- WiFi AP draws ~100-150mA continuously.
- picoserve (Embassy-native HTTP) needed in firmware.
- 2-4 concurrent WebSocket clients practical.

### Path B: BLE + Web Bluetooth (externally hosted client)

The device only advertises a BLE GATT service. The web client is hosted
elsewhere (GitHub Pages, CDN, any static host):

```
Browser loads https://rete-app.example.com (static WASM+HTML)
  --> Web Bluetooth API scans for nearby devices
  --> user pairs with "ReteNode-XXXX"
  --> BLE GATT characteristic carries RNS packets
  --> packets flow: browser <-> BLE <-> NodeCore <-> LoRa <-> mesh
```

Advantages:
- Device firmware is simpler (no HTTP server, no WiFi AP).
- Lower power (BLE ~5-10mA vs WiFi ~100-150mA).
- Web client updates independently of device firmware.
- Client can be a polished PWA with CDN delivery.

Considerations:
- Web Bluetooth requires Chromium (Chrome, Edge). No Firefox, limited Safari.
- Requires internet for initial page load (cached offline after first visit via PWA).
- BLE throughput is lower than WiFi (~20KB/s vs ~1MB/s), but LoRa is the
  bottleneck anyway (~0.5-5KB/s depending on SF).

### Path C: Both (maximum flexibility)

WiFi AP for serving the client + BLE as low-power transport. Or WiFi for
high-throughput connections + BLE for always-on background connections.
The multi-interface architecture supports any combination.

### Path D: BLE to native app

A native mobile app (not browser) connects over BLE using standard mobile
BLE APIs. This is how Meshtastic works. Could integrate with Sideband or
a dedicated rete companion app. Not dependent on Web Bluetooth support.

---

## Use Cases

| Use case | Description |
|----------|-------------|
| **Pocket mesh gateway** | Phone browser -> WiFi/BLE -> ESP32 -> LoRa -> mesh. Zero install messaging. |
| **Field deployment** | Mount at high point with antenna + solar. Multiple phones connect via WiFi. |
| **Demo device** | "Connect to this WiFi, open the page, send me a message over LoRa." |
| **Emergency comms** | No cell towers, no internet. LoRa + WiFi AP + browser = messaging. |
| **LXMF from any phone** | Send encrypted LXMF messages to Sideband users from a browser tab. |
| **IoT gateway** | Sensors send data over LoRa; browser dashboard displays it over WiFi. |
| **Multi-user radio** | 2-4 phones share one LoRa radio. Like a repeater with a UI. |
| **Mesh extender** | LoRa + WiFi/BLE makes it a transport relay with local client access. |

---

## Rete RNode vs Standard RNode

|  | Standard RNode | Rete RNode |
|---|---|---|
| Protocol processing | None (dumb KISS TNC) | Full stack (routing, crypto, links, LXMF) |
| Requires host computer | Yes (Python RNS on connected device) | No (standalone) |
| Multi-client | No (1 serial connection) | Yes (WiFi AP + BLE, 2-4 browsers) |
| Web interface | None | Built-in browser client |
| Transport relay | No (host does it) | Yes (forward packets between interfaces) |
| LXMF messaging | No (host does it) | Yes (built-in) |
| Field deployable alone | No (needs laptop/Pi) | Yes |
| BLE phone connection | Bluetooth serial (needs app) | Web Bluetooth (browser) + BLE GATT (app) |
| Cost | ~$30 RNode + host | ~$25 standalone (ESP32-S3 + SX1262) |

The key difference: a standard RNode is a peripheral. A rete RNode is a
complete node. It doesn't need anything else to participate in the mesh.

---

## Feasibility

### Memory (ESP32-S3: 512KB SRAM + 8MB PSRAM)

| Component | RAM |
|-----------|-----|
| EmbeddedNodeCore (64 paths, 16 announces, 128 dedup, 4 links) | ~30KB |
| Embassy executor + net stack | ~20KB |
| WiFi driver buffers (if WiFi path used) | ~30KB |
| TCP socket buffers (3 HTTP/WS connections) | ~12KB |
| BLE stack (if BLE path used) | ~15KB |
| LoRa packet buffers | ~2KB |
| Channel buffers (multi-interface) | ~8KB |
| Heap (Vec allocations in NodeCore) | ~20KB |
| Task stacks (~5 Embassy tasks) | ~80KB |
| **Total (WiFi path)** | **~200KB** |
| **Total (BLE-only path)** | **~175KB** |

Both fit comfortably in 512KB SRAM. PSRAM provides generous headroom.

### Flash (4-16MB typical on ESP32-S3 modules)

| Component | Size |
|-----------|------|
| Firmware (rete + Embassy + radio drivers + HTTP/BLE) | ~400-500KB |
| WASM + HTML/JS/CSS (gzipped, embedded via include_bytes) | ~80-100KB |
| **Total** | **~500-600KB** |

Fits easily in 4MB with room for OTA partitions and NVS.

### WASM binary size (served to browser)

| Component | Uncompressed | Gzipped |
|-----------|-------------|---------|
| rete-core (crypto: x25519, ed25519, aes, sha2, hkdf) | ~80-120KB | ~40KB |
| rete-transport (routing, path tables, link state) | ~40-60KB | ~20KB |
| wasm-bindgen glue | ~10-20KB | ~5KB |
| Minimal HTML/JS/CSS UI | ~30KB | ~10KB |
| **Total served to browser** | **~160-230KB** | **~75-100KB** |

### Power

| Component | Current draw |
|-----------|-------------|
| ESP32-S3 active + WiFi | ~100-150mA |
| ESP32-S3 active + BLE only | ~30-50mA |
| SX1262 RX | ~5mA |
| SX1262 TX (14dBm) | ~45mA |
| SX1262 TX (22dBm) | ~120mA |

- 2000mAh LiPo (WiFi path): ~12-20 hours
- 2000mAh LiPo (BLE-only path): ~30-50 hours
- Solar (3-5W) + battery: indefinite in daylight

---

## Crate Structure (when ready to build)

```
crates/
  rete-iface-lora/        -- ReteInterface over SX1262/SX1276 via lora-phy
  rete-iface-ble/         -- ReteInterface over BLE GATT characteristic
  rete-embassy/           -- extend with EmbassyMultiNode / run_multi
  rete-web-wasm/          -- wasm-bindgen API (shared with WEB_CLIENT_PLAN.md)

examples/
  esp32s3-rnode/          -- the integrated device firmware
```

Key dependencies:
- `lora-phy` — no_std Embassy-compatible LoRa radio abstraction (SX1261/62/76/78)
- `picoserve` — no_std Embassy-native HTTP server with WebSocket support
- `edge-dhcp` — no_std DHCP server for WiFi AP mode
- `esp-radio` — ESP32 WiFi + BLE driver for Embassy

---

## Implementation Phases (future)

1. **LoRa interface** — `rete-iface-lora` wrapping lora-phy, basic announce over RF
2. **Embassy multi-interface** — port `run_multi` pattern from rete-tokio to Embassy
3. **WiFi AP + HTTP** — picoserve serving static page, captive portal
4. **WebSocket bridge** — WS connections as virtual interfaces in node loop
5. **BLE GATT service** — BLE as alternative/parallel client connection path
6. **WASM client** — compile rete to WASM, minimal UI, embed in firmware
7. **LXMF messaging** — end-to-end: phone browser -> LoRa -> Sideband
8. **Polish** — mDNS, persistent identity, battery monitor, OTA, config UI

See also: [WEB_CLIENT_PLAN.md](WEB_CLIENT_PLAN.md) for the WASM client and
gateway server design (Phases A-F).

---

## Hardware Candidates

| Board | MCU | LoRa | WiFi | BLE | Flash | PSRAM | Notes |
|-------|-----|------|------|-----|-------|-------|-------|
| Heltec WiFi LoRa 32 V3 | ESP32-S3 | SX1262 | Yes | Yes | 8MB | 8MB | OLED display, popular |
| LilyGo T3-S3 | ESP32-S3 | SX1262 | Yes | Yes | 16MB | 8MB | Good antenna options |
| Custom PCB | ESP32-S3-WROOM | SX1262 module | Yes | Yes | 4-16MB | 2-8MB | Full control |

Any ESP32-S3 + SX1262 combination works. The `lora-phy` crate abstracts the
radio; `esp-radio` abstracts WiFi/BLE. Pin assignments vary by board.

---

## Open Questions

1. **Board selection** — Which dev board to target first? Heltec V3 is widely
   available and has good community support.
2. **LoRa parameters** — Which frequency/SF/BW to match for initial testing?
   Depends on what existing RNS network we're testing against.
3. **Web Bluetooth framing** — BLE characteristics have a 512-byte MTU limit.
   RNS MTU is 500 bytes so most packets fit in one write, but announces with
   large app_data may need fragmentation.
4. **Captive portal** — DNS redirect for auto-open on WiFi connect. Needs a
   tiny DNS server responding to all queries with 192.168.4.1.
5. **Identity persistence** — Store identity key in ESP32 NVS (non-volatile
   storage) so the device keeps its identity across reboots.
