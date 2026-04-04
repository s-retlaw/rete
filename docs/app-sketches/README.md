# Application Sketches

This directory contains implementation-oriented sketches for application
protocols built on top of Reticulum. These are not product requirements or
claims that the applications already exist in this repository. They are
starting points for future protocol and service implementations.

## Reticulum Building Blocks

| Primitive | Use | Notes |
|---|---|---|
| `Destination` | Address an application or service endpoint | Example: `chat.guild.control` |
| `Announce` | Advertise that a destination is reachable | Used for discovery and path learning |
| `DATA` | Small one-shot payloads | Best for compact notifications or telemetry |
| `Link` | Encrypted session between two peers | Use when a client expects multiple related operations |
| `Request/Response` | Small RPC-style calls over a `Link` | Good for manifests, metadata, queries, and control messages |
| `Channel` | Reliable ordered messages over a `Link` | Good for interactive sessions and live state updates |
| `Resource` | Bulk object transfer over a `Link` | Use for files, large bodies, media, packs, and archives |
| `LXMF` | Durable asynchronous messaging protocol | Good for DMs, notifications, delayed delivery, and store-and-forward |

## When To Use What

| Need | Preferred Primitive |
|---|---|
| Small control/query payload | `Request/Response` |
| Small unsolicited event | `DATA` or `LXMF` |
| Interactive session traffic | `Link` plus `Channel` |
| Large binary/object transfer | `Resource` |
| Durable human messaging | `LXMF` |

## Shared Conventions

- Service names use dot-separated destination names such as `content.root` or
  `bbs.board.news`.
- Request paths use slash-separated route strings such as `/thread/<id>/manifest`.
- Large objects are content-addressed where practical. Metadata references a
  payload hash and size before the payload itself is transferred.
- Clients should fetch manifests before bodies. A manifest-first protocol is
  easier to cache and works better over slow or intermittent paths.
- If a response does not fit in a single encrypted link packet for the current
  peer MTU, the service should return metadata and transfer the body with
  `Resource` instead of trying to inline it.

## Link Quality And Path Awareness

Applications can infer some path characteristics, but not the full real route.

### What A Service Can Usually Know

- hop count
- which local interface learned the path
- current link RTT after a `Link` is established
- negotiated link MTU
- observed transfer completion time
- observed retry or failure rate

### What A Service Cannot Know Natively

- exact end-to-end bitrate
- whether an unseen intermediate hop is LoRa, TCP, WiFi, or serial
- congestion or queue depth on remote relays
- the full remote route composition

### Recommended Link Classes

Applications should classify links from observed behavior rather than trying to
guess the full path:

| Class | Suggested Heuristics | Expected Behavior |
|---|---|---|
| `fast` | low RTT, low hops, good transfer completion | enable richer manifests and optional previews |
| `medium` | moderate RTT or hops, acceptable transfer rate | batch requests and keep previews compact |
| `constrained` | high RTT, high hops, slow transfer, frequent retries | text-first, metadata-first, explicit media fetch only |

## Shared Failure Model

- Announce loss or stale paths are normal. Clients should retry discovery and
  path lookup before treating a service as offline.
- Requests should be idempotent where possible. Re-requests after timeout are
  expected.
- `Resource` transfers should be resumable or restartable from manifest data.
- Clients should cache manifests, metadata, and immutable objects by hash.

## Documents

- [Chat Service](./chat-service.md)
- [Mapping And Telemetry](./mapping-telemetry.md)
- [Content Service](./content-service.md)
- [BBS And File Board](./bbs-file-board.md)
