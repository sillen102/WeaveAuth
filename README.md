# WeaveAuth

OAuth2/PKCE authorization server with a real Backend-for-Frontend (BFF).

A Cargo workspace with three Rust binaries: an Axum backend (unexposed to the internet),
a BFF that owns the OAuth client role and session cookies, and an optional static login
page.

## Architecture

Cargo workspace (`backend/` + `bff/` + `login/`), three binaries:

- **`weaveauth`** (Axum, backend) — `:1983`. API + OAuth2/PKCE authorization server
  logic. **Not exposed publicly** — only `bff` and `login` are internet-facing.
- **`weaveauth-bff`** (Axum, BFF) — `:8080`. The real OAuth client: drives the entire
  authorization-code + PKCE exchange with backend server-to-server on a single
  `/login` request — the browser never sees backend at all, only bff's one 303 back
  to the caller with a `Set-Cookie`. Owns the session store.
  Also acts as a reverse proxy for any other route: requests matching a
  configured `path_prefix` are forwarded to `upstream_url` with the session cookie
  swapped for an `Authorization: Bearer <access_token>` header (see Configuration
  below).
- **`weaveauth-login`** (axum + `ServeDir`, static UI) — `:8081`. Optional, thin,
  replaceable: serves the login page and a `/login` redirect straight into the bff's
  `/login`.

Login (authorization-code + PKCE) flow — the browser only ever talks to `login` and
`bff`; backend is never in the browser's network tab:

1. Browser hits `login`'s page, or any frontend links straight to the bff's
   `GET /login?redirect_uri=<back-to-caller>`.
2. `login` (if used) just redirects into the bff's `/login`.
3. `bff` generates a `code_verifier`, derives `code_challenge` (S256), and — entirely
   server-to-server via its own HTTP client — `GET`s the backend's `/oauth/authorize`
   with the caller's `redirect_uri` passed through unchanged.
4. Backend is the **single source of truth** for the allowlist: it validates
   `redirect_uri` against `WA_REDIRECT_URI_ALLOWLIST`/`config.yaml` and refuses to
   store a PKCE challenge or issue a code for anything not on it (`400`) — bff cannot
   get a token for a `redirect_uri` backend doesn't recognize, full stop. On success,
   backend stores the challenge keyed by a single-use, TTL'd auth code and responds
   (to bff, not the browser) with a 303 whose `Location` carries the `code`. bff reads
   `code` straight out of that header — it never actually navigates there.
5. Still within the same request, `bff` POSTs `code` + `code_verifier` to the backend
   `POST /oauth/token` (server-to-server), verifies success, mints a session, stores it
   in its session store, and *only now* replies to the browser: one 303 straight to the
   original `redirect_uri` with a `Set-Cookie: wa_session=...; HttpOnly` header — no
   token in the URL, and no browser-visible hop through backend at any point.

This collapses what classic OAuth does in two browser-visible round trips into one,
which only works because backend's `/oauth/authorize` has no interactive step today
(anonymous stub, see TODO ledger item 5). If real user authentication requiring a
browser-visible step lands on backend, this needs revisiting.

bff routes:

| Method | Path                         | Returns                                                                                                                                                              |
|--------|------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| GET    | `/health`                    | `ok`                                                                                                                                                                 |
| GET    | `/login?redirect_uri=<uri>`  | Drives the whole PKCE exchange server-to-server, sets session cookie, 303 → `redirect_uri`; `400` if `redirect_uri` is missing                                       |
| *      | *(configured `path_prefix`)* | Proxied to the matching route's `upstream_url` (prefix stripped), cookie swapped for `Authorization: Bearer`; `401` if no/unknown session, `404` if no route matches |

login routes:

| Method | Path        | Returns                                |
|--------|-------------|----------------------------------------|
| GET    | `/`         | Login page (`login/static/index.html`) |
| GET    | `/login?redirect_uri=<uri>` | 303 → bff `/login`; `400` if `redirect_uri` is missing |
| GET    | `/static/*` | Static assets (`login/static/`)        |

Backend routes:

| Method | Path               | Returns                                                                                                                              |
|--------|--------------------|--------------------------------------------------------------------------------------------------------------------------------------|
| GET    | `/health`          | `ok`                                                                                                                                 |
| GET    | `/oauth/login`     | `{ "authenticated": true }` (legacy stub)                                                                                            |
| GET    | `/oauth/authorize` | 303 → `redirect_uri?code=...&state=...` if `redirect_uri` is allowlisted, else `400`                                                 |
| POST   | `/oauth/token`     | Verifies `code_verifier` against the stored (single-use, TTL'd) challenge; `{ access_token, refresh_token, token_type, expires_at }` |

## TODO ledger

1. ~~**PKCE verification**~~ — done: backend stores `code_challenge` at
   `/oauth/authorize` and checks `code_verifier` against it at `/oauth/token`.
2. ~~**`redirect_uri` allowlist**~~ — done, backend-only: bff forwards whatever
   `redirect_uri` a caller passes to `/login` straight through to backend's
   `/oauth/authorize` as-is; backend is the single place that allowlists it, and
   refuses to issue a code (so bff can't hand out a token) for anything not listed.
   Deliberately not duplicated in bff — one allowlist, one place it can drift.
3. ~~**Token delivery**~~ — done: bff sets an HttpOnly session cookie instead of a
   query-string access token.
4. ~~**State/code single-use + expiry**~~ — done: backend's PKCE store enforces
   single-use + TTL (bff no longer needs its own pending-auth store — the whole
   exchange with backend happens inside one request, see the login flow above).
5. **Real user authentication** — `/oauth/authorize` is still anonymous; no login
   credential check happens before a code is issued. `backend/src/model/user.rs` and
   `InMemoryUserStorage` exist but are unwired. Deferred.
6. **Client authentication** — the bff's token-exchange request already carries
   `client_id`/`client_secret` fields (currently always `None`); wiring real client
   credentials into the backend's `/oauth/token` is future work for defense in depth
   alongside PKCE.
7. **Cookie `Secure` attribute** — bff's session cookie has no `Secure` flag yet (local
   HTTP dev); needed before any real HTTPS deployment.

## Prerequisites

- Rust (stable) — `cargo` on PATH. No Node required.

## Development

Each crate has its own `mise.toml` with a `dev` task (plain `cargo run`), run with the
crate's own directory as the working directory — this matters because each crate's
`config.yaml` is looked up as a bare relative path (see Configuration below), so it
only resolves when run from inside that crate's directory.

```bash
mise run services   # backend + bff + login together, from the repo root
```

or individually, one per terminal:

```bash
cd backend && mise run dev   # or: cd backend && cargo run
cd bff && mise run dev       # or: cd bff && cargo run
cd login && mise run dev     # or: cd login && cargo run
```

Running `cargo run -p <crate>` from the repo root also works, but the crate's
`config.yaml` won't be found (wrong cwd) — it'll silently fall back to hardcoded
defaults instead, which is easy to mistake for a config bug. Set `WA_CONFIG_FILE` to
an absolute path if you need to run that way.

Open http://localhost:8081 for the optional standalone login page.

## Configuration

Each of `backend` and `bff` reads an optional YAML file first (bare `config.yaml`,
relative to the process's working directory — override the path with
`WA_CONFIG_FILE`; a missing file is not an error, defaults apply), then lets the
`WA_*` env vars below override individual scalar fields on top of it. `login` is
env-only (nothing structured to configure). A route list (`routes:` on bff) only
exists in the YAML file — there's no sane env-var shape for it.

bff's `config.yaml` `routes` list controls its reverse-proxy behavior. It currently
points at the two standalone test doubles in `testing/` (see below):

```yaml
routes:
  - path_prefix: /api/downstream
    upstream_url: http://localhost:10001
  - path_prefix: /api/downstream2
    upstream_url: http://localhost:10002
```

Any request whose path starts with `path_prefix` (longest prefix wins if more than one
matches) is forwarded to `upstream_url` with that prefix stripped, `Cookie` dropped, and
`Authorization: Bearer <access_token>` set from the session looked up via the request's
`wa_session` cookie. No session → `401`; no matching route → `404`.

The `redirect_uri` a caller passes to bff's `/login` is not separately allowlisted by
bff — it's forwarded as-is to backend's `/oauth/authorize`, and backend's
`WA_REDIRECT_URI_ALLOWLIST` / `config.yaml` is the only place it's checked (see the
login flow above). `backend/config.yaml`'s allowlist therefore needs to list every
real destination callers of `/login` are allowed to land on, e.g. `login`'s own page:

```yaml
redirect_uri_allowlist:
  - http://localhost:8081/
```

### Test doubles (`testing/`)

Two standalone Rust binaries (own `Cargo.toml` with an empty `[workspace]` table each,
so they're excluded from the root workspace — not real services, just fixtures for
exercising bff's proxy):

- **`testing/downstream-service`** — any path, any method: 401 without an
  `Authorization` header, otherwise serves a small HTML demo page showing it back.
  `cargo run` in that directory, `$PORT` default `10001`.
- **`testing/user-service`** — `POST /users`: 401 without `Authorization`, otherwise
  saves the JSON body in memory under a generated `id` and returns it (`201`). `cargo
  run` in that directory, `$PORT` default `10002`.

| Variable                    | App          | Default                         | Description                                                                                                                             |
|-----------------------------|--------------|---------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| `WA_CONFIG_FILE`            | backend, bff | `config.yaml` (relative to cwd) | Path to the optional YAML config overlay                                                                                                |
| `WA_PORT`                   | backend      | `1983`                          | Backend listen port                                                                                                                     |
| `WA_REDIRECT_URI_ALLOWLIST` | backend      | `http://localhost:8081/`        | Comma-separated allowlist of valid `redirect_uri` values — checked once, at `/oauth/authorize`, for whatever bff forwards from `/login` |
| `WA_PKCE_CODE_TTL_SECS`     | backend      | `300`                           | How long an issued auth code stays redeemable                                                                                           |
| `WA_LOGIN_PORT`             | login        | `8081`                          | Login page listen port                                                                                                                  |
| `WA_BFF_PORT`               | bff          | `8080`                          | bff listen port                                                                                                                         |
| `WA_BFF_URL`                | bff, login   | `http://localhost:8080`         | Public base URL of the bff, used by login to redirect into it                                                                           |
| `WA_BACKEND_URL`            | bff          | `http://localhost:1983`         | Backend base URL the bff exchanges codes against                                                                                        |
| `WA_SESSION_COOKIE_NAME`    | bff          | `wa_session`                    | Name of the HttpOnly session cookie set after login                                                                                     |
| `WA_CLAIM_ENRICHMENT_URL`   | backend      | *(unset)*                       | Optional upstream claim-enrichment endpoint (unused yet)                                                                                |

## Testing

```bash
cargo test
```

Runs the full workspace test suite (backend, bff, login — `testing/downstream-service`
and `testing/user-service` are excluded, being standalone fixtures, not workspace
members):

- `backend`: unit tests inline per module (`model/*`, `storage/in_memory.rs`,
  `config.rs` — env/YAML precedence via a small `EnvGuard` + shared `Mutex` since
  `Config::load()` touches process env) plus `backend/tests/api_test.rs` (black-box,
  via `weaveauth::server::app`) covering `/health`, the legacy `/oauth/login` stub, and
  `/oauth/authorize` + `/oauth/token`'s allowlist/PKCE/single-use/TTL behavior.
- `bff`: unit tests inline (`config.rs`, `storage/in_memory.rs`, and `proxy.rs`'s pure
  `is_hop_by_hop`/`extract_cookie` helpers) plus `bff/tests/pkce_flow.rs` (the full
  server-to-server login exchange, its failure modes, and that backend is never
  browser-visible) and `bff/tests/proxy.rs` (bearer-swap, prefix matching, query/body
  forwarding, auth failures).
- `login`: unit tests inline (`Config::load()`) plus `login/tests/redirect_test.rs`
  (the `/login` redirect and that static assets still serve correctly).

## Docker

Single multi-stage `Dockerfile` at repo root. The `rust:1.98-slim` builder compiles all
three binaries (`--release -p weaveauth -p weaveauth-bff -p weaveauth-login`); the
`debian:bookworm-slim` runtime copies the three binaries plus `/app/login/static` and
`entrypoint.sh`, which launches all three processes.

```bash
docker build -t weaveauth .
docker run -p 1983:1983 -p 8080:8080 -p 8081:8081 weaveauth
```

## License

Apache License 2.0. Copyright 2026 Silvio Sabo.
