# Chat Service Sketch

## Purpose

This sketch describes a Discord-like text and attachment service built with
Reticulum-native primitives. The target is durable text communication with an
optional live session layer, not voice/video or internet-style real-time UX.

## Why Reticulum Fits

Good fit:

- direct messages
- rooms and threads
- delayed synchronization
- offline delivery
- attachments
- low-rate live interaction

Poor fit:

- voice
- video
- very high-frequency presence updates
- large public servers with internet-style latency expectations

## Destination Layout

| Destination | Direction | Purpose |
|---|---|---|
| `chat.user.inbox` | inbound | DM delivery and durable notifications |
| `chat.guild.control` | inbound | guild, room, membership, and manifest queries |
| `chat.guild.room.<room_id>` | inbound | live room session entrypoint |
| `chat.media` | inbound | attachment metadata and transfer service |

## Core Objects

### `GuildSummary`

```json
{
  "guild_id": "gld_01",
  "name": "Mesh Ops",
  "room_count": 5,
  "revision": 42
}
```

### `RoomManifest`

```json
{
  "room_id": "ops",
  "guild_id": "gld_01",
  "revision": 188,
  "latest_message_id": "msg_0188",
  "participants": ["id_a", "id_b", "id_c"]
}
```

### `ChatMessage`

```json
{
  "message_id": "msg_0188",
  "room_id": "ops",
  "author_id": "id_a",
  "created_at": 1711977600,
  "thread_id": null,
  "body": "Status update",
  "attachment_hashes": ["sha256:abcd"],
  "reply_to": null
}
```

### `AttachmentMeta`

```json
{
  "hash": "sha256:abcd",
  "name": "photo.jpg",
  "mime": "image/jpeg",
  "size": 153245,
  "width": 1600,
  "height": 900
}
```

## Request Paths

All control queries go to `chat.guild.control` unless stated otherwise.

| Path | Request Body | Response | Primitive |
|---|---|---|---|
| `/guilds` | empty | array of `GuildSummary` | `Request/Response` |
| `/guild/<guild_id>/manifest` | empty | guild metadata and room revisions | `Request/Response` |
| `/guild/<guild_id>/rooms` | empty | array of room summaries | `Request/Response` |
| `/room/<room_id>/manifest` | empty | `RoomManifest` | `Request/Response` |
| `/room/<room_id>/backfill` | `{ "before": "msg_0188", "limit": 50 }` | message summaries or full bodies | `Request/Response` |
| `/message/<message_id>` | empty | `ChatMessage` | `Request/Response` |
| `/attachment/<hash>/meta` | empty | `AttachmentMeta` | `Request/Response` |

Large attachment bytes are fetched from `chat.media` over `Resource` after the
metadata request confirms the hash, size, and MIME type.

## Which Primitive Carries Each Operation

| Operation | Primitive |
|---|---|
| direct message | `LXMF` |
| offline mention notification | `LXMF` |
| list guilds or rooms | `Request/Response` |
| join a live room | `Link` to `chat.guild.room.<room_id>` |
| send live room event | `Channel` |
| fetch large attachment | `Resource` |

## Live Room Session

After a client opens a `Link` to `chat.guild.room.<room_id>`, the server should
use `Channel` messages for:

- new message events
- reaction updates
- message edit/delete events
- typing start/stop
- membership join/leave
- read-marker updates

### `Channel` Event Envelope

```json
{
  "event_type": "message.create",
  "room_id": "ops",
  "event_id": "evt_2044",
  "payload": {
    "message_id": "msg_0189"
  }
}
```

The event payload should carry only enough information to let the client update
local state or fetch missing objects. Full attachment bytes should never be
pushed over `Channel`.

## Sync And Caching Model

- Cache guild manifests, room manifests, and message objects locally.
- Treat message objects as immutable after creation except for small edit/tombstone
  overlays keyed by message ID.
- Use `/room/<room_id>/backfill` for missing-history repair.
- Identify attachments by content hash so repeated references do not trigger
  repeated uploads or downloads.

## Link-Quality Adaptation Rules

### `fast`

- open live room `Link` by default when the user enters a room
- allow inline image previews if metadata says the preview body fits a single
  encrypted response packet
- fetch recent backfill automatically

### `medium`

- batch room backfill in larger windows
- request attachment metadata automatically but do not fetch full media until opened
- send typing indicators at low frequency

### `constrained`

- no automatic attachment fetch
- no typing indicators
- request room summaries first, then explicit backfill
- prefer `LXMF` for direct user messaging and notifications

## Failure And Retry Model

- DMs must be accepted as asynchronous and delay-tolerant.
- Live room entry should fall back to a non-live manifest and backfill flow if
  link establishment fails.
- Attachments should be restartable by content hash after interruption.
- Duplicate message or reaction events should be safe to apply idempotently.

## Out Of Scope

- voice
- video
- screen sharing
- internet-scale member-count and presence semantics
