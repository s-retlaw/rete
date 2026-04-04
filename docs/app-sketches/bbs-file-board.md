# BBS And File Board Sketch

## Purpose

This sketch describes a bulletin-board and file-sharing service. This is one of
the most natural Reticulum application patterns because it is manifest-driven,
delay-tolerant, and attachment-friendly.

## Why Reticulum Fits

Good fit:

- boards
- threads
- posts
- subscription notifications
- file attachments
- archive replication

Poor fit:

- highly dynamic web-forum UX
- large-volume simultaneous live editing

## Destination Layout

| Destination | Direction | Purpose |
|---|---|---|
| `bbs.index` | inbound | board and service index lookups |
| `bbs.board.<board_name>` | inbound | per-board thread and manifest queries |
| `bbs.post` | inbound | post metadata and body lookup |
| `bbs.file` | inbound | attachment and archive transfer |
| `bbs.notify` | inbound | optional user notifications via `LXMF` integration |

## Core Objects

### `BoardSummary`

```json
{
  "board_name": "news",
  "title": "Network News",
  "thread_count": 42,
  "revision": 11
}
```

### `ThreadManifest`

```json
{
  "thread_id": "thr_1001",
  "board_name": "news",
  "revision": 16,
  "post_ids": ["pst_2001", "pst_2002"],
  "latest_post_at": 1711977600
}
```

### `Post`

```json
{
  "post_id": "pst_2002",
  "thread_id": "thr_1001",
  "author_id": "id_a",
  "created_at": 1711977600,
  "title": "Field report",
  "body": "The repeater was back online at 07:00 UTC.",
  "attachment_hashes": ["sha256:file1"]
}
```

### `FileMeta`

```json
{
  "hash": "sha256:file1",
  "name": "report.pdf",
  "mime": "application/pdf",
  "size": 803221
}
```

## Request Paths

| Path | Request Body | Response | Primitive |
|---|---|---|---|
| `/boards` | empty | array of `BoardSummary` | `Request/Response` |
| `/board/<board_name>/threads` | `{ "before": "thr_1001", "limit": 50 }` or empty | thread summaries | `Request/Response` |
| `/thread/<thread_id>/manifest` | empty | `ThreadManifest` | `Request/Response` |
| `/post/<post_id>` | empty | `Post` | `Request/Response` |
| `/file/<hash>/meta` | empty | `FileMeta` | `Request/Response` |

If a post body is too large for a single encrypted response packet, the service
should return post metadata and body hash first, then transfer the body through
`Resource` from `bbs.file`.

## Which Primitive Carries Each Operation

| Operation | Primitive |
|---|---|
| board list or thread list | `Request/Response` |
| post fetch | `Request/Response` |
| attachment or archive transfer | `Resource` |
| subscription notification | `LXMF` |

## Sync And Caching Model

- Cache board summaries by board name and revision.
- Cache thread manifests by thread ID and revision.
- Cache posts by post ID.
- Cache files and large post bodies by content hash.
- Synchronize incrementally:
  - fetch board list
  - fetch thread summaries for a board
  - fetch thread manifest
  - fetch only missing posts and missing files

## Notification Model

`bbs.notify` is optional. If enabled, users can subscribe to:

- new thread in board
- new post in thread
- direct reply to authored post

Notifications should be delivered through `LXMF` and carry only compact
metadata:

```json
{
  "event": "thread.reply",
  "board_name": "news",
  "thread_id": "thr_1001",
  "post_id": "pst_2002"
}
```

The client must still fetch the actual post through the BBS service.

## Link-Quality Adaptation Rules

### `fast`

- fetch thread manifest and latest post bodies automatically when opening a thread
- fetch attachment metadata automatically

### `medium`

- fetch thread manifest first
- fetch post bodies on open or page change
- attachments only when explicitly selected

### `constrained`

- list boards and thread summaries only by default
- no automatic post-body backfill
- no automatic attachment metadata fetch
- attachments are manual pull only

## Failure And Retry Model

- repeated list and post requests should be safe and idempotent
- thread manifests are the source of truth for repairing missing posts
- interrupted attachment transfers should restart by hash
- stale boards or manifests are acceptable until the next successful sync

## Out Of Scope

- collaborative editing
- live rich-text forum behavior
- web-style moderation and admin dashboards
