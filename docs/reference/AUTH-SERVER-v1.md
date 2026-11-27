# Auth Server v1 — accounts, login, and connection tokens

Status: implemented (route P0)
English | [简体中文](AUTH-SERVER-v1.zh-CN.md)

## What it is

`starry-api` is a lightweight RustDesk-compatible API server (port 21114)
that closes the authentication loop:

1. **User accounts** (SQLite + bcrypt) with local password login.
2. **Official-client login**: the exact `POST /api/login` response the 1.5
   client parses, plus `GET /api/login-options`, `POST /api/currentUser`, and
   `POST /api/logout`. With an API server configured, clients no longer emit
   the "Connection refused on :21114" noise or a body-parse error, and the
   account remains signed in across restarts.
3. **Connection tokens**: the `access_token` returned by `/api/login` **is** an
   Ed25519-signed JWT (`typ: at+jwt`), because official clients store it and
   replay it verbatim as `PunchHoleRequest.token` / `RequestRelay.token`.
4. **HBBS enforcement**: point the Starry config's `connection_auth.jwks.file`
   at the JWKS this service publishes and set `connection_auth.mode: enforce`.
   HBBS then refuses connections whose token is absent, forged, expired, or
   missing a required scope. Strategy v1 group rules apply on top.

Boundary of v1: this is a credential issuer, not an OIDC identity provider.
Enterprise SSO (OIDC/LDAP) and TOTP are v1.1; the user table already has the
fields (`status`, `auth_version`, `extra_scopes`) they will need.

## Wire contract (verified against rustdesk 1.5.x client source)

| Method | Path | Auth | Request → Response |
| --- | --- | --- | --- |
| GET | `/api/login-options` | none | `[]` — a JSON **array** of third-party provider strings; empty means password login only |
| POST | `/api/login` | none | `{username, password, id, uuid, autoLogin, type:"account", deviceInfo}` → `{access_token, type:"access_token", user:{name, display_name, avatar, email, note, status, is_admin, info}}` |
| POST | `/api/currentUser` | Bearer | `{id, uuid}` → flat `UserPayload`; `401` makes the client sign out |
| POST | `/api/logout` | Bearer | revokes the session; answers `null` |
| POST | `/api/connection-token` | Bearer | `{token, expires_in}` — a shorter-lived JWT for scripts and non-official clients |
| POST | `/api/introspect` | none | `{token}` → `{active, sub, reason}` (RFC 7662 shape, for HBBS's optional verifier) |
| GET | `/api/ab` | Bearer | `null` — the client's own "no address book" reply, so the Address Book tab stays clean until P1 |
| GET | `/healthz` | none | `{"status":"live"}` |

Errors are `{"error": "<code>"}` with a non-2xx status, e.g.
`UsernameOrPasswordError` (the client shows this string), `UserDisabled`,
`TooManyAttempts`, `ParamsError`.

Claims carried by every token (all of them are checked by HBBS):
`iss`, `aud`, `token_use: "access"`, `scope`, `sub == user_id`,
`user_id != 0`, `auth_version != 0`, `jti` (UUID), `iat`, `nbf`, `exp`.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `STARRY_API_LISTEN` | `0.0.0.0:21114` | Bind address. |
| `STARRY_API_DB` | `<cwd>/users.db` | SQLite database (users + sessions). |
| `STARRY_API_KEY_FILE` | `<cwd>/api-signing-key` | Ed25519 key, base64 of the 64-byte secret (same format as `id_ed25519`). Generated on first boot with mode 0600. |
| `STARRY_API_JWKS_FILE` | `<cwd>/auth/jwks.json` | JWKS published for HBBS. A digest-bound `<file>.metadata.json` freshness stamp is written beside it. |
| `STARRY_API_ISSUER` | `https://api.starry.local` | `iss` claim. **Must be an HTTPS URL** and must equal HBBS's `connection_auth.issuer`. |
| `STARRY_API_AUDIENCE` | `rustdesk-connect` | `aud` claim; must equal HBBS's `connection_auth.audience`. |
| `STARRY_API_SCOPE` | `connect:initiate` | Base scope minted into tokens; per-user `--scopes` are merged in. |
| `STARRY_API_TOKEN_TTL_SECONDS` | `604800` (7 days) | Login token lifetime. This is also the connection-credential lifetime: clients never refresh it, they sign in again. |
| `STARRY_API_CONNECTION_TOKEN_TTL_SECONDS` | `3600` | Lifetime for `/api/connection-token`. |
| `STARRY_API_JWKS_HEARTBEAT_SECONDS` | `300` | How often the keyset freshness stamp is renewed. Must stay below HBBS's `max_stale_seconds` (default 3600, ≥ 30 enforced). |
| `STARRY_API_BCRYPT_COST` | `12` | bcrypt cost (4–15). |
| `ADMIN_PASSWORD` | unset | Bootstraps/updates the `admin` account. Unset leaves accounts alone; a changed value bumps `auth_version`, revoking old sessions. |
| `STARRY_API_TRUST_PROXY` | `0` | Read `X-Forwarded-For` for login rate limiting when behind a TLS terminator. |

## Account management

```sh
# create accounts (password from STDIN or STARRY_API_NEW_PASSWORD, never argv)
printf '%s\n' "$PASSWORD" | starry-api user add alice --display-name "Alice"
starry-api user add contractor --scopes "connect:group:contractors"
starry-api user list
starry-api user passwd alice     # bumps auth_version: old tokens stop working
starry-api user disable alice    # status 0 + auth_version bump
```

Passwords must be at least 8 characters. Login is rate limited per client
address (10 failures / 5 minutes), and unknown usernames still cost a bcrypt
comparison so response timing does not reveal whether an account exists.

## Deployment

Run `starry-api.service` next to HBBS. The first boot writes the JWKS, which
is what HBBS verifies against:

```yaml
# /var/lib/starry/data/starry/config.yaml
connection_auth:
  mode: audit            # keep audit until a real client round-trip is seen
  issuer: https://api.starry.local
  audience: rustdesk-connect
  token_use: access
  required_scope: connect:initiate
  jwks:
    file: auth/jwks.json # relative to this config file's directory
```

Clients reach the API at `http://<host>:21114`. Passwords must not cross the
network in clear text beyond a trusted network, so terminate TLS in front of it
(set `STARRY_API_TRUST_PROXY=1` and point the client's API Server field at the
HTTPS URL).

### The JWKS freshness rule

HBBS fails closed when its keyset stamp is older than
`connection_auth.jwks.max_stale_seconds`, so a running issuer must keep
renewing the stamp. `starry-api` rewrites `jwks.json` plus
`jwks.json.metadata.json` (version, `fetched_at_epoch_seconds`, `jwks_sha256`)
every heartbeat; HBBS re-reads the file on its own refresh interval and adopts
the issuer's stamp. Consequences worth knowing:

- If `starry-api` stops for longer than `max_stale_seconds`, HBBS starts
  denying new connections — by design (fail closed). Keep the unit running, or
  raise `max_stale_seconds` for your outage tolerance.
- Key rotation is atomic and online: replace the key file and restart
  `starry-api`; HBBS picks up the new kid on its next refresh.

### Revocation semantics

Logout and disable take effect immediately for every API endpoint. For the
**connection** path, an already-issued JWT remains cryptographically valid until
`exp` unless HBBS is configured with `connection_auth.introspection.url`
pointing at `/api/introspect` (mTLS + HTTPS, as HBBS requires). Choose one:

- short `STARRY_API_TOKEN_TTL_SECONDS` (users sign in again sooner), or
- HBBS introspection (instant revocation, more infrastructure), or
- emergency global revocation: rotate the signing key.

## Verification

`tests/auth_server.rs` starts the real binary and asserts the whole contract:
login-options shape, wrong-password rejection, the login response shape, JWT
header claims, a signature check against the published JWKS, the freshness
sidecar digest, `currentUser`, logout revocation, and — the decisive gate — a
real `hbbs` in `enforce` mode accepting an API-minted token while rejecting both
anonymous and forged-token punches.
