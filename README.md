# auth-server

Future multi-user server for [Command Center](https://github.com/nlaero/CommandCenter). On that repo, `main` is the single-user app: no login, settings and AI data on the device. The [`multi-user`](https://github.com/nlaero/CommandCenter/tree/multi-user) branch is the future server version. This server can run on that computer or on another machine. It is not part of the single-user app. Shared caption memory (`/ai/memory`) belongs with `multi-user`, not with `main`.

This repository holds that later server: username and password, Rust (Axum) + SQLite + Argon2id. The program name is `auth-server`. A Fedora Pi (or any LAN Linux host) is fine for testing — that is not the product name.

Accounts are created with `POST /auth/register`. `authctl create-user` is host recovery only. The current Command Center build does not call this server.

When the multi-user app is built, the server can run in either place:

- **This computer only** (`AUTH_MODE=device`, bound to `127.0.0.1`). Other machines cannot connect. This mode may store source passwords and API keys (`AUTH_SECRET_STORE=true`, `GET` / `PUT /vault`).
- **Another machine** (`AUTH_MODE=shared`). Other computers would sign in here. Passwords and API keys stay on each computer. The vault route answers `403 secret_store_disabled`.

`GET` / `PUT /settings` is the board and source setup. Secret *names* are fine in that document. Secret *values* are rejected there even when the vault is on.

`GET` / `PUT /ai/memory` is caption text for the on-device model. The same account document is stored whether this server is the one on the computer or a remote one. Audio and the model stay on the computer. A backup includes those caption fixes. An older backup that does not mention them restores without them.

Every install can export and import a backup (`authctl backup` or `auth-server --backup-export` / `--backup-import`). The file holds board accounts (password hashes, not the password), the server admin (also a hash), refresh sessions, boards, caption fixes, and any secrets the vault was storing. Stop the server before import. The JWT signing secret stays in the env file and is not part of the backup.

Setup asks for a server admin. That account opens the server settings page at `http://127.0.0.1:<port>/admin`. It is not a Command Center board login, and a board account cannot open that page. The page can add and remove board accounts, turn self-registration on or off, and turn secret storage on or off when this server is device-only. It can also switch between a Windows service and starting at login.

On Windows, setup asks how the server should run:

- **Windows service.** It keeps running when nobody is signed in. There is no taskbar icon. Creating the service needs administrator approval. Open server settings from the Start menu shortcut.
- **Start at login.** It starts when you sign in and shows an icon in the taskbar. Open server settings from that icon.

The Windows uninstaller removes the program, the service, the login startup entry, and the server files. Board settings that live next to it are removed when the uninstall page's delete-app-data box is checked.

## API

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/health` | `{ "ok": true, "service": "auth-server", "mode": "device"\|"shared", "secretStore": false }` |
| `GET` | `/vault` | Bearer. Source passwords and API keys for this user. Device mode with secret storage only |
| `PUT` | `/vault` | Bearer. Replace that map. Session tokens are rejected |
| `POST` | `/auth/register` | `{ username, password }` → tokens |
| `POST` | `/auth/login` | `{ username, password }` → tokens |
| `POST` | `/auth/refresh` | `{ refreshToken }` → rotated pair |
| `POST` | `/auth/logout` | `{ refreshToken? }` → 204 |
| `GET` | `/auth/me` | Bearer access → `{ id, username }` |
| `GET` | `/settings` | Bearer access → board document, or 404 |
| `PUT` | `/settings` | Bearer access. `{ revision, document }` → saved, or 409 with the current document |
| `GET` | `/ai/memory` | Bearer access → caption fixes, or 404 |
| `PUT` | `/ai/memory` | Bearer access. `{ revision, document }` → saved, or 409. Text only |
| `GET` | `/admin` | Server settings page. Loopback only. Server admin, not a board login |
| `POST` | `/admin/api/login` | Server admin username and password. Token audience is `command-center-server-admin` |

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

Install files for a desktop-managed server. The admin file is one username line, then the password. That account is only for server settings.

```bash
printf '%s\n%s\n' 'server-admin' 'a-long-password' > /tmp/cc-admin.txt
chmod 600 /tmp/cc-admin.txt
./target/debug/auth-server --install --home "$HOME/.config/command-center" \
  --role device --port 8080 --secret-store --startup login \
  --admin-file /tmp/cc-admin.txt --autostart
```

`--startup service` registers a Windows service (or a user service on Linux). `--startup login` starts at sign-in. On Windows that also puts an icon in the taskbar. `--role shared` listens on `0.0.0.0` so other devices can connect, and it will refuse `--secret-store`.

`auth-server --uninstall --home <dir>` removes the service and the login entry. It does not delete the database; the Windows uninstaller does that.

Backup:

```bash
cargo run --bin authctl -- backup export ./auth-backup.json
# stop auth-server, then:
cargo run --bin authctl -- backup import ./auth-backup.json --yes
```

Lab JWTs are HS256 with `AUTH_JWT_SECRET`. Move to Ed25519/RS256 before anything beyond a lab (`authctl rotate-keys` prints the steps).

## Fedora test host

1. `cargo build --release`
2. Install `auth-server` and `authctl` to `/usr/local/bin/`
3. `useradd -r -d /var/lib/auth-server auth-server` and create `/var/lib/auth-server`
4. Copy `deploy/auth-server.env.example` → `/etc/auth-server.env` (mode 600)
5. Copy `deploy/auth-server.service` → `/etc/systemd/system/`, then `systemctl enable --now auth-server`
6. Put Caddy or nginx in front (`deploy/Caddyfile.example` + mkcert/step-ca). Point desktops at `https://auth-server.local:8443`

## Status

Working: register, login, refresh, logout, me; per-user board document at `/settings`; caption fixes at `/ai/memory`; device-only secret vault; backup export/import; Argon2id; SQLite; refresh rotation + reuse revoke; basic rate limit.

Not yet: the multi-user app itself, asymmetric JWT, TTY-hidden `authctl` passwords, production-grade rate limits. The current single-user Command Center does not sign in here.
