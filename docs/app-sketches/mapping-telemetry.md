# Mapping And Telemetry Sketch

## Purpose

This sketch describes a shared mapping and telemetry system built for mesh and
delay-prone networks. The focus is compact updates, regional manifests, and
offline packs. It is not a web-tile streaming protocol.

## Why Reticulum Fits

Good fit:

- position reports
- markers and incidents
- route requests
- telemetry series
- shared vector objects
- offline pack distribution

Poor fit:

- live raster tile streaming
- high-rate continuous map redraw traffic
- remote pan/zoom behavior that assumes low latency

## Destination Layout

| Destination | Direction | Purpose |
|---|---|---|
| `map.telemetry` | inbound | small telemetry and position updates |
| `map.query` | inbound | map object and region queries |
| `map.objects` | inbound | object metadata and object body lookup |
| `map.pack` | inbound | offline pack metadata and pack transfer |

## Core Objects

### `PositionReport`

```json
{
  "report_id": "rep_2001",
  "source_id": "id_a",
  "lat": 37.7749,
  "lon": -122.4194,
  "alt_m": 18,
  "speed_mps": 0.0,
  "heading_deg": 0,
  "created_at": 1711977600
}
```

### `MapObject`

```json
{
  "object_id": "obj_1001",
  "object_type": "marker",
  "revision": 3,
  "region_id": "region_sf",
  "geometry_hash": "sha256:geom1",
  "properties": {
    "title": "Water cache",
    "icon": "supply"
  }
}
```

### `RegionManifest`

```json
{
  "region_id": "region_sf",
  "revision": 55,
  "object_ids": ["obj_1001", "obj_1002"],
  "pack_hashes": ["sha256:pack1"]
}
```

### `PackMeta`

```json
{
  "hash": "sha256:pack1",
  "name": "sf-vector-pack",
  "kind": "vector-pack",
  "size": 2876544,
  "region_id": "region_sf",
  "revision": 55
}
```

## Request Paths

| Path | Request Body | Response | Primitive |
|---|---|---|---|
| `/region/<region_id>/manifest` | empty | `RegionManifest` | `Request/Response` |
| `/bbox/query` | `{ "min_lat": ..., "min_lon": ..., "max_lat": ..., "max_lon": ..., "kinds": ["marker", "incident"] }` | matching object summaries | `Request/Response` |
| `/object/<object_id>` | empty | `MapObject` and referenced geometry hash | `Request/Response` |
| `/route` | `{ "from": [lat, lon], "to": [lat, lon], "mode": "foot" }` | route summary and step object IDs | `Request/Response` |
| `/pack/<hash>/meta` | empty | `PackMeta` | `Request/Response` |

Large geometry blobs, route bundles, imagery, and pack bytes should move over
`Resource` from `map.pack` after metadata lookup confirms size and hash.

## Which Primitive Carries Each Operation

| Operation | Primitive |
|---|---|
| small position report | `DATA` to `map.telemetry` |
| live telemetry stream | `Link` plus `Channel` |
| object or region query | `Request/Response` |
| offline pack transfer | `Resource` |

## Session Model

Use `DATA` for occasional position reports and short telemetry bursts. When a
client wants a steady stream from a peer or service, it should open a `Link`
and receive `Channel` messages carrying compact update envelopes.

### `Channel` Telemetry Envelope

```json
{
  "event_type": "telemetry.update",
  "source_id": "id_a",
  "created_at": 1711977600,
  "payload": {
    "lat": 37.7749,
    "lon": -122.4194,
    "battery_pct": 87
  }
}
```

## Sync And Caching Model

- Clients should keep base maps local whenever possible.
- Query services should return manifests and object IDs before large object bodies.
- Objects should be cached by object ID plus revision or by content hash.
- Geometry and large pack contents should be immutable and hash-addressed.
- Region synchronization should be manifest-driven:
  - fetch manifest
  - compare revisions and hashes
  - fetch only missing objects and packs

## Link-Quality Adaptation Rules

### `fast`

- allow live telemetry subscriptions
- prefetch nearby object metadata after a bounding-box query
- fetch vector packs automatically if marked required by the manifest

### `medium`

- reduce telemetry frequency
- return summaries before details
- defer pack download until explicitly requested

### `constrained`

- disable live telemetry streams
- use periodic position snapshots only
- prefer symbolic markers and text incident reports over imagery
- never auto-fetch packs or large geometry blobs

## Failure And Retry Model

- telemetry updates are best-effort and may be dropped
- region and object queries must be safe to retry
- pack downloads should be restartable by hash
- stale manifests should be tolerated until a new path is learned

## Out Of Scope

- slippy-map tile serving
- high-rate raster imagery transport
- continuous pan-and-zoom request storms
