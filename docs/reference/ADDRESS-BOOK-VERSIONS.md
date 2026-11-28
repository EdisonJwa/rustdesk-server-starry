# Legacy address book — versions and lost updates

Status: implemented (2026-11-28)
[简体中文](ADDRESS-BOOK-VERSIONS.zh-CN.md) | English

## The problem this solves

The official client's `pushAb` posts the **whole** book and never sends a
precondition. Verified at `flutter/lib/models/ab_model.dart`:

```dart
final body = jsonEncode({"data": jsonEncode(_serialize())});
http.Response resp = await http.post(Uri.parse(api), headers: authHeaders, body: body);
```

Two devices editing the same account therefore necessarily lose one side: last
write wins, and the loser is gone with no record. That is the client's model and
it cannot be changed from the server.

What the server *can* do is make the loss visible and recoverable. That is all of
this feature.

## What was added

### A version per account

`GET /api/ab` now carries two headers alongside the unchanged body:

| Header | Meaning |
| --- | --- |
| `ETag` | `"ab-<version>"` — a quoted entity-tag |
| `x-ab-version` | the same number, unquoted, for convenience |

A book that has never been written is version `0`. The body is byte-identical to
what the client has always parsed, and the client ignores unknown headers, which
is what makes this safe to add.

The version always increases on a write that changes the document. A write that
matches what is stored does **not** increase it and is not counted as
superseding, because the client re-pushes on every local edit and must not appear
to be conflicting with itself.

### An opt-in precondition

`POST /api/ab` accepts `If-Match`. A caller that sends it has opted into the
check; a caller that does not — the official client — behaves exactly as before.

| Case | Answer |
| --- | --- |
| no `If-Match`, or `*` | write proceeds, last write wins |
| `If-Match` matches the stored version | write proceeds |
| `If-Match` does not match | **412** `{"error":"AddressBookChanged"}` with the current `ETag` |
| `If-Match` is malformed | **400** `{"error":"InvalidIfMatch"}` |

412 rather than 409: RFC 7232 requires `Precondition Failed` for a failed
`If-Match`, and a client that retries on 409 would loop.

A malformed value is refused rather than ignored. Ignoring it would let a caller
believe it had protection it did not have, which is worse than failing.

### Recovery of the replaced document

`GET /api/ab/previous`:

```json
{"data": "<the document the last write replaced>", "version": 3, "superseded_count": 2}
```

or, when nothing has been superseded:

```json
{"data": null, "superseded_count": 0}
```

`superseded_count` is how many writes have discarded a *different* document.
Non-zero means this book is being edited from more than one place — the
observable symptom of the problem, which is otherwise invisible.

Every superseding write also logs a `warn` naming the account and the new version,
so an operator sees it without polling.

## What this deliberately does not do

- **No merge.** A server-side three-way merge of a client-owned JSON document
  would need to understand `{tags, peers, tag_colors}` deeply, and the client
  owns that schema by design. Refusing or reporting is honest; guessing at a merge
  is not.
- **No automatic conflict rejection for the client.** The client cannot send a
  precondition, so requiring one would break every push.
- **No history beyond one document.** Keeping a full history of a password-bearing
  payload is a data-retention liability with no query to justify it. One
  recoverable generation is what a person can actually act on.

## Gates

- `src/auth_server.rs` unit tests — the ETag is a quoted entity-tag, a missing or
  `*` precondition asserts nothing, and a malformed `If-Match` is refused rather
  than ignored.
- `tests/api_endpoints.rs` — a book round-trips with `null` before it exists; a
  re-push of the same document is not a conflict; a stale precondition gets 412
  with the current `ETag` while the matching one succeeds; the replaced document
  is recoverable and counted; an unauthenticated caller cannot read anyone's
  previous book; a malformed precondition is 400.
- Mutation-verified twice: discarding the replaced document fails
  `a_replaced_document_is_recoverable` naming the lost laptop book, and ignoring
  the precondition fails `a_stale_precondition_is_refused_with_412` with `200`
  where `412` is required.
