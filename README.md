# auth-server

Command Center **auth-server**: username/password **self-register**, login, and token issuance for the desktop app.

This is the home of the auth-server service (repo [`nlaero/command-center-auth`](https://github.com/nlaero/command-center-auth)). The desktop app stays in [`nlaero/CommandCenter`](https://github.com/nlaero/CommandCenter).

- **Service / binary name:** `auth-server` (never “Pi auth” / “Pi server”)
- **Test host (not the product name):** Fedora on a Raspberry Pi (any LAN Linux host works)
- **Signup:** users self-register from Command Center (`POST /auth/register`). `authctl create-user` is optional host recovery only.

This service does **not** store Broadcastify or other source API credentials. Those stay on the desktop OS keyring. See the project design doc `auth-login-design.md`.

## API

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/health` | `{ "ok": true, "service": "auth-server" }` |
| `POST` | `/auth/register` | `{ username, password }` → tokens (create + session) |
| `POST` | `/auth/login` | `{ username, password }` → tokens |
| `POST` | `/auth/refresh` | `{ refreshToken }` → rotated pair |
| `POST` | `/auth/logout` | `{ refreshToken? }` → 204 |
| `GET` | `/auth/me` | Bearer access → `{ id, username }` |

Full contract: [`openapi.yaml`](./openapi.yaml).

Self-register is **on by default**. Set `AUTH_ALLOW_REGISTER=false` to lock signup (emergency / host-only).

## Local lab run

```bash
cp .env.example .env
# edit AUTH_JWT_SECRET
cargo run --bin auth-server
curl -s http://127.0.0.1:8080/health
curl -s -X POST http://127.0.0.1:8080/auth/register \
  -H 'content-type: application/json' \
  -d '{"username":"nathan","password":"your-password"}'
```

Optional host recovery: `cargo run --bin authctl -- create-user nathan`

Lab tokens use **HS256** + `AUTH_JWT_SECRET`. Upgrade to Ed25519/RS256 before wider use (`authctl rotate-keys` prints the lab procedure).

## Fedora test-host install (sketch)

1. Build release binaries on the host (or cross-compile): `cargo build --release`
2. Install: `auth-server` + `authctl` → `/usr/local/bin/`
3. User/data: `useradd -r -d /var/lib/auth-server auth-server` and `/var/lib/auth-server`
4. Env: copy `deploy/auth-server.env.example` → `/etc/auth-server.env` (mode 600)
5. Unit: copy `deploy/auth-server.service` → `/etc/systemd/system/` and `systemctl enable --now auth-server`
6. TLS: put Caddy (or nginx) in front using `deploy/Caddyfile.example` + mkcert/step-ca; point desktops at `https://auth-server.local:8443`

## Scope note

Includes working register/login/refresh/logout/me, Argon2id, SQLite, refresh rotation + reuse revoke, and a basic rate limiter. Not yet: asymmetric JWT, TTY-hidden `authctl` passwords, or production-hardened rate limits. Desktop register UI lands with the Command Center auth client.
