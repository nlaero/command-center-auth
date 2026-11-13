# auth-server

Username/password auth for [Command Center](https://github.com/nlaero/CommandCenter): self-register, login, refresh, logout. Rust (Axum) + SQLite + Argon2id.

Repo: [`nlaero/command-center-auth`](https://github.com/nlaero/command-center-auth). Binary and service name: `auth-server`. A Fedora Pi (or any LAN Linux host) is fine for testing — that is not the product name.

Users sign up from the desktop app via `POST /auth/register`. `authctl create-user` is host recovery only.

Does **not** store Broadcastify or other source API credentials. Those stay on the desktop keyring.

## API

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/health` | `{ "ok": true, "service": "auth-server" }` |
| `POST` | `/auth/register` | `{ username, password }` → tokens |
| `POST` | `/auth/login` | `{ username, password }` → tokens |
| `POST` | `/auth/refresh` | `{ refreshToken }` → rotated pair |
| `POST` | `/auth/logout` | `{ refreshToken? }` → 204 |
| `GET` | `/auth/me` | Bearer access → `{ id, username }` |

Contract: [`openapi.yaml`](./openapi.yaml).

Self-register is on by default. Set `AUTH_ALLOW_REGISTER=false` to lock signup (authctl only).

## Local run

```bash
cp .env.example .env
# set AUTH_JWT_SECRET to something long and random
cargo run --bin auth-server
curl -s http://127.0.0.1:8080/health
curl -s -X POST http://127.0.0.1:8080/auth/register \
  -H 'content-type: application/json' \
  -d '{"username":"nathan","password":"your-password"}'
```

Optional recovery user: `cargo run --bin authctl -- create-user nathan`

Lab JWTs are HS256 with `AUTH_JWT_SECRET`. Move to Ed25519/RS256 before anything beyond a lab (`authctl rotate-keys` prints the steps).

## Fedora test host

1. `cargo build --release`
2. Install `auth-server` and `authctl` to `/usr/local/bin/`
3. `useradd -r -d /var/lib/auth-server auth-server` and create `/var/lib/auth-server`
4. Copy `deploy/auth-server.env.example` → `/etc/auth-server.env` (mode 600)
5. Copy `deploy/auth-server.service` → `/etc/systemd/system/`, then `systemctl enable --now auth-server`
6. Put Caddy or nginx in front (`deploy/Caddyfile.example` + mkcert/step-ca). Point desktops at `https://auth-server.local:8443`

## Status

Working: register, login, refresh, logout, me; Argon2id; SQLite; refresh rotation + reuse revoke; basic rate limit.

Not yet: asymmetric JWT, TTY-hidden `authctl` passwords, production-grade rate limits. Desktop register UI ships with the Command Center auth client.
