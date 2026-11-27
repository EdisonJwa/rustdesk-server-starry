# Auth Server v1 — accounts, login, and connection-token issuance

Status: implemented (route P0)
English | [简体中文](AUTH-SERVER-v1.zh-CN.md)

## What it is

`starry-api` is a lightweight RustDesk-compatible API server (port 21114)
that closes the authentication loop:

1. **User accounts** (SQLite + bcrypt password hashing) with local login.
2. **RustDesk client login contract**: `POST /api/login` returns the
   `user_info` + `access_token` shape the official client expects, and
   `GET /api/login-options` reports that password login is available.
3. **Connection-token issuance**: `POST /api/connection-token` (Bearer
   session) returns a short-lived Ed25519-signed JWT with
   `scope: connect:initiate`, signed by a key pair the service generates at
   first boot and publishes as a JWKS file.
4. **HBBS enforcement**: point the Starry config's `connection_auth.jwks.file`
   at that JWKS output and set `connection_auth.mode: enforce` — HBBS then
   refuses connections whose token is missing/expired/group-underscoped.
   Strategy v1 group rules apply on top (per-group scopes, group deny).

Design boundary: the API server mints **connection** tokens but is not an
OIDC identity provider. Enterprise SSO (OIDC/LDAP) and TOTP are v1.1 (the
login handler and user schema already carry the fields).

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `STARRY_API_LISTEN` | `0.0.0.0:21114` | Bind address for the HTTP API. |
| `STARRY_API_DB` | `<cwd>/users.db` | SQLite database (users + sessions). |
| `STARRY_API_KEY_FILE` | `<cwd>/api-signing-key` | Ed25519 private key (base64, 64 bytes); generated at first boot if absent. |
| `STARRY_API_JWKS_FILE` | `<cwd>/auth/jwks.json` | JWKS published for HBBS `connection_auth.jwks.file`. Written at startup. |
| `ADMIN_PASSWORD` | unset | Creates/updates the `admin` user at startup; unset leaves existing users alone. |

## Endpoints

| Method | Path | Auth | Body / Response |
| --- | --- | --- | --- |
| GET | `/api/login-options` | none | `{"hidden": false}` |
| POST | `/api/login` | none | `{username, password}` → `{user_info:{name,id}, access_token}` (bcrypt-verified, 7-day session) |
| GET | `/api/current-user` | Bearer session | `{user_info:{name,id}}` |
| POST | `/api/connection-token` | Bearer session | `{token}` — EdDSA JWT, `exp` +1 h, `scope: connect:initiate` |

The wire contract for `/api/login` mirrors the shape official RustDesk
clients parse (`user_info` + `access_token`); v1 has been contract-checked
against the 1.5 client response schema and **must be verified against a real
client before enabling enforce mode**.

## Deployment

Runs as `starry-api.service` beside hbbs. The JWKS file it writes is the one
HBBS verifies against, so after first boot:

```sh
# point HBBS at the API-published JWKS
# (connection_auth.jwks.file: /var/lib/starry/data/auth/jwks.json)
sudo systemctl restart starry-hbbs
```

Keep `connection_auth.mode: audit` until a real client login + connection
token round-trip has been observed; then switch to `enforce`.
