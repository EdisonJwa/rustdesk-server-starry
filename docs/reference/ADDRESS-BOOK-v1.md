# Address Book v1 — what starry-api stores for the client

Status: implemented
English | [简体中文](ADDRESS-BOOK-v1.zh-CN.md)

## What it is

The RustDesk client's Address Book tab pulls and pushes one JSON document. v1
stores that document per account and returns it unchanged. The server does not
model peers, tags or colours, and that is a deliberate design choice rather than a
shortcut:

- The client owns the shape. It serialises `{tags, peers, tag_colors}` itself and
  parses the same structure back, so any server-side rewriting would corrupt a
  client update.
- A client release that adds a field must not require a server migration.

## Contract

Verified against rustdesk 1.5.x (`flutter/lib/models/ab_model.dart`).

| Method | Path | Auth | Body / Response |
| --- | --- | --- | --- |
| GET | `/api/ab` | Bearer | `{"data": "<json string>", "licensed_devices": N}` — or literal `null` |
| POST | `/api/ab` | Bearer | `{"data": "<json string>"}` → `null` |

The document the client sends:

```json
{
  "tags": ["office"],
  "peers": [
    {"id": "123", "username": "", "hostname": "", "platform": "",
     "alias": "prod-db", "tags": ["office"], "hash": "<secret password hash>"}
  ],
  "tag_colors": "{\"office\":\"#00ff00\"}"
}
```

Note `tag_colors` is itself a JSON **string** inside the document. Any tooling
that rewrites this payload has to preserve that nesting.

### Why `null` and 401 are different answers

- `null` means "this account has no address book yet" and is normal.
- `401` makes the client sign out.

Returning `null` for an unauthenticated request would make a broken session look
like data loss, so an unauthenticated pull is always 401.

`licensed_devices` is the ceiling the client trims the book to. Starry does not
licence devices, so it reports a value high enough never to truncate: a small
number here would silently drop peers from a user's book.

## Storage

One row per account in `address_books`, upserted on push (the client always sends
the whole document, so there is nothing to merge). Payloads are bounded at 4 MiB —
separately from the 16 KiB bound every credential endpoint uses, because an
address book with a few hundred peers legitimately exceeds the latter.

A push is validated as JSON before it is stored. That is not schema validation: it
only ensures a corrupt push cannot make every later pull unparseable. A rejected
push leaves the previous document intact.

## What this deliberately does not do

- **No sharing, no groups, no roles.** v1 is one book per account. The client's
  shared-profile and device-group endpoints (`/api/ab/shared/profiles`,
  `/api/device-group/accessible`, `/api/users`, `/api/peers`) are not implemented,
  and the client treats their absence as "no shared books" rather than an error.
- **No conflict resolution.** Last push wins. Two devices pushing under the same
  account overwrite each other, which matches what the official server does.
- **No encryption on the server side.** The document contains password hashes
  produced by the client; they are stored as sent. Treat the database as a secret,
  the same way the account password hashes are treated.

## Gates

- `tests/auth_server.rs` — pull before push returns `null`, a push round-trips
  byte-for-byte, a malformed push is refused without clobbering the stored
  document, and an unauthenticated pull is 401.
- `src/auth_server.rs` unit test — the document survives storage verbatim and a
  second push replaces rather than accumulates.
- Reverting the pull to answer with an empty document fails the e2e with
  `the document must round-trip unchanged`.
