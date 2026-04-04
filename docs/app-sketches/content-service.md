# Content Service Sketch

## Purpose

This sketch describes a document and asset service that feels HTTP-like to an
application while remaining Reticulum-native. The service favors manifests,
immutable assets, and explicit bulk transfer instead of web-style request
chattiness.

## Why Reticulum Fits

Good fit:

- document catalogs
- knowledge bases
- manuals
- content feeds
- small APIs
- downloadable assets

Poor fit:

- browser-style pages that trigger many tiny dependent requests
- high-frequency polling
- large dynamic front-end bundles

## Destination Layout

| Destination | Direction | Purpose |
|---|---|---|
| `content.root` | inbound | directory and index lookups |
| `content.api` | inbound | metadata and query service |
| `content.asset` | inbound | large asset and document body transfer |

## Core Objects

### `IndexEntry`

```json
{
  "doc_id": "doc_intro",
  "title": "Getting Started",
  "revision": 7,
  "body_hash": "sha256:body1",
  "summary": "Introductory guide"
}
```

### `DocumentMeta`

```json
{
  "doc_id": "doc_intro",
  "title": "Getting Started",
  "revision": 7,
  "mime": "text/markdown",
  "body_hash": "sha256:body1",
  "body_size": 12450,
  "asset_hashes": ["sha256:img1"]
}
```

### `AssetMeta`

```json
{
  "hash": "sha256:img1",
  "name": "diagram.png",
  "mime": "image/png",
  "size": 442101
}
```

### `SearchResult`

```json
{
  "doc_id": "doc_intro",
  "title": "Getting Started",
  "excerpt": "This guide explains the first deployment steps..."
}
```

## Request Paths

| Path | Request Body | Response | Primitive |
|---|---|---|---|
| `/index` | empty | array of `IndexEntry` | `Request/Response` |
| `/doc/<doc_id>/meta` | empty | `DocumentMeta` | `Request/Response` |
| `/doc/<doc_id>/body` | empty | inline body if it fits, otherwise transfer metadata | `Request/Response` |
| `/asset/<hash>/meta` | empty | `AssetMeta` | `Request/Response` |
| `/search` | `{ "query": "reticulum", "limit": 20 }` | array of `SearchResult` | `Request/Response` |

If `/doc/<doc_id>/body` does not fit a single encrypted response packet, the
service should respond with:

```json
{
  "mode": "resource",
  "hash": "sha256:body1",
  "size": 12450,
  "mime": "text/markdown"
}
```

The client then fetches the body from `content.asset` over `Resource`.

## Which Primitive Carries Each Operation

| Operation | Primitive |
|---|---|
| index lookup | `Request/Response` |
| metadata query | `Request/Response` |
| multi-step browsing session | `Link` |
| large document body transfer | `Resource` |
| large image or binary transfer | `Resource` |

## Session Model

Clients should open a `Link` when they plan to perform multiple related reads,
such as index fetch, several document metadata queries, and then one or more
asset transfers. The service does not need `Channel` for the baseline design;
`Request/Response` plus `Resource` is sufficient.

## Sync And Caching Model

- Cache indexes and metadata by document ID and revision.
- Cache document bodies and assets by content hash.
- Treat assets as immutable once published.
- Prefer a manifest-first fetch order:
  - `/index`
  - `/doc/<doc_id>/meta`
  - body and asset transfers as needed

## HTTP Comparison

The analogy to HTTP is useful for mental framing, but the protocol should not
literally mirror HTTP semantics.

Similar:

- named paths
- metadata lookup
- body fetch
- content type and size metadata

Different:

- no browser-style request fan-out
- explicit large-object transfer with `Resource`
- stronger emphasis on hash-addressed immutable content
- session establishment is explicit with `Link`

## Link-Quality Adaptation Rules

### `fast`

- prefetch document body after metadata if marked small
- prefetch first-page or first-section summaries
- fetch inline previews for small images if they fit a single packet

### `medium`

- metadata first, body on open
- never prefetch large assets
- cap search result count conservatively

### `constrained`

- index and metadata only by default
- explicit body fetch only
- summaries before full body
- no automatic asset fetch

## Failure And Retry Model

- repeated metadata requests should be safe and idempotent
- interrupted body or asset transfers should restart by content hash
- stale indexes are acceptable until a new path or announce is learned

## Out Of Scope

- literal HTTP wire compatibility
- browser-oriented page assembly
- heavy client-side web application behavior
