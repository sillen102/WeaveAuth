# WeaveAuth

Lightweight Backend-for-Frontend (BFF) with OAuth2 capabilities.

A Cargo workspace with three Rust binaries: an Axum backend, a static login page,
and a Topcoat admin tool.

## Architecture

Cargo workspace (`backend/` + `frontend/` + `login/`), three binaries:

- **`weaveauth`** (Axum, backend) — `:1983`. API + OAuth2 logic.
- **`weaveauth-login`** (axum + `ServeDir`, static + OAuth2 client) — `:8080`. Login page plus the server-side PKCE exchange.
- **`weaveauth-frontend`** (Topcoat, admin tool) — `:1984`. No admin pages implemented yet; its `#[page("/")]` route still renders a transitional login page that links into the login service.

Login (authorization-code + PKCE) flow:

1. Admin tool links to the login service `GET /login?redirect_uri=<back-to-admin>`.
2. Login service generates a `code_verifier`, derives `code_challenge` (S256), stores `(verifier, redirect_uri)` in memory keyed by `state`, and 303-redirects to the backend `GET /oauth/authorize`.
3. Backend stubs the authorize step: it 303-redirects back to the login service `/callback` with `code` and `state`.
4. Login service looks up the state, POSTs `code` + `code_verifier` to the backend `POST /oauth/token` (server-side, no browser cross-origin call), then redirects the browser to the original `redirect_uri` with `?access_token=...`.

Login routes:

| Method | Path                  | Returns                                                |
|--------|-----------------------|--------------------------------------------------------|
| GET    | `/`                   | Login page (`login/static/index.html`)                 |
| GET    | `/login`              | 303 → backend `/oauth/authorize` with PKCE params      |
| GET    | `/callback`           | Exchanges `code` for a token, 303 → `redirect_uri`     |
| GET    | `/static/*`           | Static assets (`login/static/`)                        |

Backend routes:

| Method | Path             | Returns                                                |
|--------|------------------|--------------------------------------------------------|
| GET    | `/health`        | `ok`                                                   |
| GET    | `/oauth/login`   | `{ "authenticated": true }` (legacy stub)              |
| GET    | `/oauth/authorize` | 303 → `redirect_uri?code=stub-code&state=...` (stub) |
| POST   | `/oauth/token`   | `{ "access_token": "stub-access-token", "token_type": "Bearer" }` (stub) |

## TODO ledger (safe only while tokens are stubs)

Real trust gates land with real auth. Until then this is PKCE-shaped scaffolding,
not PKCE — the code is bearer-equivalent with none of the bindings below wired up:

1. **PKCE verification** — backend drops `code_challenge` at `/oauth/authorize` and never
   checks `code_verifier` against it at `/oauth/token`. Requires backend storage of the
   challenge per issued `code` (in-memory, expiring).
2. **`redirect_uri` allowlist** — `/oauth/authorize` echoes any `redirect_uri`, and the
   login service forwards its own query param unvalidated. Once real tokens exist this is
   open-redirect / token-exfiltration (`/login?redirect_uri=https://evil.com`). Add an
   allowlist checked on both sides.
3. **Token delivery** — `?access_token=...` leaks into browser history, server logs, and
   Referer headers. Fix with a fragment (`#access_token=`), a POST-back, or an HttpOnly
   cookie (preferred for an admin tool).
4. **State single-use + expiry** — a captured state/code pair stays replayable; add expiry
   and ensure consumption is atomic with the exchange.

The PKCE exchange runs server-side in the login service, so the verifier/challenge pair
isn't buying much in this topology (a confidential-client auth-code flow would work too);
the real protection will be #2 + `state`.

## Prerequisites

- Rust (stable) — `cargo` on PATH. No Node required.

## Development

Terminal 1 — backend:

```bash
cargo run -p weaveauth
```

Terminal 2 — login (static page, opens http://localhost:8080):

```bash
cargo run -p weaveauth-login
```

Terminal 3 — admin (frontend):

```bash
cargo run -p weaveauth-frontend
```

Open http://localhost:1984 for the transitional login route served by the admin tool.
Open http://localhost:8080 for the real login page.

## Configuration (environment variables)

| Variable                  | App      | Default                             | Description                                              |
|---------------------------|----------|-------------------------------------|----------------------------------------------------------|
| `WA_PORT`                 | backend  | `1983`                              | Backend listen port                                      |
| `WA_ADMIN_PORT`           | frontend | `1984`                              | Admin listen port                                        |
| `WA_LOGIN_PORT`           | login    | `8080`                              | Login page listen port                                   |
| `WA_CLAIM_ENRICHMENT_URL` | backend  | *(unset)*                           | Optional upstream claim-enrichment endpoint (unused yet) |
| `WA_LOGIN_URL`            | login    | `http://localhost:8080`             | Public base URL of the login service (used as `redirect_uri` in the PKCE flow) |
| `WA_BACKEND_URL`          | login    | `http://localhost:1983`             | Backend base URL the login service exchanges codes against |
| `WA_DEFAULT_REDIRECT_URI` | login    | `http://localhost:1984`             | Where to send the user after sign-in when `/login` has no `redirect_uri` |
| `WA_OAUTH_LOGIN_URL`      | frontend | `http://localhost:8080/login?redirect_uri=http://localhost:1984/` | URL the "Sign in" link goes to |

## Testing

```bash
cargo test
```

Runs the workspace tests; backend integration tests live in `backend/tests/api_test.rs`.

## Docker

Single multi-stage `Dockerfile` at repo root. The `rust:1.98-slim` builder compiles all
three binaries (`--release -p weaveauth -p weaveauth-frontend -p weaveauth-login`); the
`debian:bookworm-slim` runtime copies the three binaries plus `/app/login/static` and
`entrypoint.sh`, which launches all three processes.

```bash
docker build -t weaveauth .
docker run -p 1983:1983 -p 8080:8080 -p 1984:1984 weaveauth
```

## License

Apache License 2.0. Copyright 2026 Silvio Sabo.
