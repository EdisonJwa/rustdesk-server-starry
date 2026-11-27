# OIDC login — single sign-on for the RustDesk client

Status: implemented
[简体中文](OIDC-LOGIN.zh-CN.md)

## What it does

`starry-api` can authenticate a user against an external identity provider and
then issue its own EdDSA connection token. The client gains provider buttons on
its login screen; it never sees the IdP's token, and `hbbs` never learns that
single sign-on was involved.

This is the "authenticate the human elsewhere, keep issuing our own credential"
split. Starry stays the authority for what a connection may do; the IdP only
answers who the human is.

## The wire contract

Verified against the official client (`src/hbbs_http/account.rs`,
`flutter/lib/models/user_model.dart` in rustdesk master). It is a device-code
pattern with a polling half, and four details are load-bearing:

### 1. Advertising providers

`GET /api/login-options` returns a `List<String>`. Two prefixes exist:

- `oidc/<name>` — one provider, no icon
- `common-oidc/<json array>` — each entry `{name, icon}`

The client checks for `common-oidc/` **first**, so Starry answers with that form:

```json
["common-oidc/[{\"name\":\"azure\",\"icon\":\"microsoft\"}]"]
```

An empty array (`[]`) means "password login only", which is what a
configuration with no providers produces.

### 2. Starting a login

```
POST /api/oidc/auth
{"op":"azure","id":"<device id>","uuid":"<device uuid>",
 "deviceInfo":{"os":"Linux","type":"client","name":"..."},"apiDomain":"..."}
```

Answer:

```json
{"code":"<opaque>","url":"https://idp.example/authorize?..."}
```

The client opens `url` in a browser and starts polling `code` once a second for
up to three minutes.

### 3. Polling

```
GET /api/oidc/auth-query?code=<code>&id=<device id>&uuid=<device uuid>
```

The answer is **wrapped**:

```json
{"body": "{\"error\": \"No authed oidc is found\"}"}
```

The outer object is parsed first, then the inner string. The client decides
success versus failure from the inner payload's shape, not the HTTP status:

- an inner object with an `error` key means "keep waiting" when the value
  contains `No authed oidc is found`, and means "stop and show this" otherwise;
- an inner object without `error` is the credential document.

That substring match is why a not-yet-finished login must never answer anything
else: any other error text makes the client give up.

### 4. The credential

Once the browser half completes, the poll answers the same document as
`/api/login`:

```json
{"access_token":"<EdDSA JWT>","type":"access_token","tfa_type":"","secret":"",
 "user":{"name":"alice","display_name":"Alice","avatar":"","email":"a@b.test",
         "note":"","status":1,"is_admin":false,"info":{}}}
```

`access_token` **is** the connection credential: the client replays it verbatim
as `PunchHoleRequest.token` / `RequestRelay.token`. It is issued **once** — a
second poll for the same code answers `No authed oidc is found`, because a spent
code must not mint a second credential.

## The browser half

`GET /oidc/callback?code=...&state=...` is what the IdP redirects to. Starry then:

1. finds the pending login by its `state`, refusing an unknown or expired one;
2. redeems the code at the provider's token endpoint with the stored PKCE
   verifier;
3. fetches the provider's JWKS and verifies the id_token signature;
4. validates the claims;
5. records the completed login, which the client's next poll collects.

## Security properties

| Property | How |
| --- | --- |
| CSRF on the callback | `state` is random per login and must match the issued value; a mismatch cannot complete a login |
| Code interception | PKCE `S256`; the verifier never leaves the server, so observing the redirect is not enough to redeem the code |
| Token replay across logins | the id_token's `nonce` must equal the one this login issued |
| Forged tokens | only RS256/384/512 and ES256/384 are accepted; `none` and the HMAC family are refused, because with HMAC anyone holding `client_id` could mint a token |
| Wrong issuer or audience | `iss` must equal the configured issuer, and `aud` must contain `client_id` |
| Unbounded tokens | `exp` is mandatory; a token without one is refused rather than treated as long-lived |
| Clock skew | 60 seconds of leeway on `exp` and `iat`, no more |
| Redirect hijack of discovery | discovery and JWKS fetches do not follow redirects, and the document's `issuer` must match the configured one |
| Identity takeover | bindings are keyed on `(provider, subject)`, never on an e-mail address; a name collision creates a suffixed account instead of attaching to the existing one |
| Unbounded pending state | at most 1024 in-flight logins; expired entries are swept on insert |

### What this deliberately does not do

- **No group or role mapping.** Claims do not assign scopes. Authorisation stays
  in the strategy document, so an IdP compromise cannot widen access.
- **No token passthrough.** The IdP's token is read for claims and discarded.
- **No refresh.** Like password login, the token lasts `STARRY_API_TOKEN_TTL_SECONDS`
  and the user signs in again afterwards.
- **No local password for SSO users.** A first login creates an account with a
  random password that is never returned, so `/api/login` cannot be used for it.

## Configuration

```json
{
  "request_ttl_seconds": 180,
  "providers": [
    {
      "name": "azure",
      "icon": "microsoft",
      "issuer": "https://login.microsoftonline.com/<tenant>/v2.0",
      "client_id": "...",
      "client_secret": "...",
      "redirect_uri": "https://rustdesk.example.network/oidc/callback",
      "scopes": ["profile"],
      "username_claim": "preferred_username",
      "allowed_email_domains": ["example.test"],
      "require_verified_email": true
    }
  ]
}
```

Point `STARRY_OIDC_CONFIG` at that file. Unset means OIDC is off and
`/api/login-options` stays `[]`.

Field notes:

- `name` is a slug (`[A-Za-z0-9_-]`). It travels inside the `common-oidc` JSON and
  comes back as `op`, so anything else would make the round trip ambiguous.
- `issuer` and `redirect_uri` must be `https`, except that `http` is accepted for
  a loopback host so a local test provider works. The host is parsed, not
  prefix-matched, so `http://127.0.0.1.evil.test` is refused.
- `client_secret` is optional: a public client uses PKCE and none.
- `allowed_email_domains` empty means "any domain". Set it to restrict a
  deployment to one organisation.
- `require_verified_email` fails closed: a missing `email_verified` claim does
  not satisfy it.

The redirect URI registered at the IdP must be
`https://<api host>/oidc/callback`.

## Gates

- `src/oidc.rs` unit tests — claim validation across issuer/audience/nonce
  mismatch, expiry, skew, missing `exp`, future `iat`, domain allow-list,
  verified-email, username fallback; PKCE against the RFC 7636 vector;
  asymmetric-algorithms-only; pending-login once-only completion, state
  mismatch, expiry, capacity; loopback-http acceptance and lookalike-host
  rejection.
- `tests/oidc_login.rs` — a hand-written identity provider on a socket drives the
  real `starry-api` binary through the exact client sequence: options →
  start → poll-while-pending → authorize → callback → poll-for-credential →
  poll-again-is-empty.
- Mutation-verified: removing the nonce check fails
  `oidc_callback_refuses_a_token_with_a_bad_nonce`; leaving a completed login
  un-consumed fails `oidc_login_round_trip_mints_a_usable_access_token`; dropping
  the `{"body": ...}` wrapper fails the same test.
