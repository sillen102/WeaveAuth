# WeaveAuth

OAuth2/PKCE authorization server with a real Backend-for-Frontend (BFF).

A Cargo workspace with three Rust binaries: an Axum backend (unexposed to the internet),
a BFF that owns the OAuth client role and session cookies, and an optional static login
page.

## Architecture

Cargo workspace (`backend/` + `bff/` + `login/`), three binaries:

- **`weaveauth`** (Axum, backend) — `:1983`. API + OAuth2/PKCE authorization server
  logic. **Not exposed publicly** — only `bff` and `login` are internet-facing.
- **`weaveauth-bff`** (Axum, BFF) — `:8080`. The real OAuth client: verifies user
  credentials and drives the entire authorization-code + PKCE exchange with backend
  server-to-server on a single `/login` request — the browser never sees backend at
  all, only bff's one 303 back to the caller with a `Set-Cookie`. Owns the session
  store.
  Also acts as a reverse proxy for any other route: requests matching a
  configured `path_prefix` are forwarded to `upstream_url` with the session cookie
  swapped for an `Authorization: Bearer <access_token>` header (see Configuration
  below).
- **`weaveauth-login`** (axum + `ServeDir`, static UI) — `:8081`. Optional, thin,
  replaceable: serves the login page, the registration page, and `/config.js` (injects
  `window.BFF_URL` so those static pages know where to POST). Both HTML files are
  plain, deployer-replaceable static assets — no templating, no build step.

Login (authorization-code + PKCE) flow — the browser only ever talks to `login` and
`bff`; backend is never in the browser's network tab:

1. Browser hits `login`'s page (`index.html`), which renders a real username/password
   form (its `action` is set client-side to `{WA_BFF_URL}/login`, read from
   `/config.js`) plus a link to `register.html` (same pattern, posts to
   `{WA_BFF_URL}/register`).
2. Submitting the login form does a **plain cross-origin form POST straight to bff**
   (not a `fetch`) — this is what lets bff's `Set-Cookie` response end up scoped to
   bff's own origin, and needs no CORS since it's a real browser navigation, not a
   script-read response.
3. `bff` first calls backend's `POST /oauth/login` with the submitted
   identifier/password. Backend hashes-and-compares (Argon2) against `UserStorage` and,
   on success, returns a short-lived, single-use `login_session` token. Wrong
   credentials → bff 303s the browser back to the login page with `?error=1` (the page
   shows an inline message) — `/oauth/authorize` is never even called.
4. `bff` generates a `code_verifier`, derives `code_challenge` (S256), and — entirely
   server-to-server via its own HTTP client — `GET`s the backend's `/oauth/authorize`
   with the caller's `redirect_uri` and the `login_session` from step 3.
5. Backend's `/oauth/authorize` first consumes `login_session` (`401` if missing,
   unknown, expired, or already used — this is what makes "authenticate before
   authorize" a real, server-enforced ordering per RFC 6749 §4.1.1, rather than
   something every caller has to get right on its own). It then checks `redirect_uri`
   against `WA_REDIRECT_URI_ALLOWLIST`/`config.yaml` — the **single source of truth**
   for that allowlist — and refuses to issue a code for anything not on it (`400`). On
   success, backend stores the challenge keyed by a single-use, TTL'd auth code and
   responds (to bff, not the browser) with a 303 whose `Location` carries the `code`.
   bff reads `code` straight out of that header — it never actually navigates there.
6. Still within the same request, `bff` POSTs `code` + `code_verifier` to the backend
   `POST /oauth/token` (server-to-server), verifies success, mints a session, stores it
   in its session store, and *only now* replies to the browser: one 303 straight to the
   original `redirect_uri` with a `Set-Cookie: wa_session=...; HttpOnly` header — no
   token in the URL, and no browser-visible hop through backend at any point.

Registration follows the same shape: `register.html` posts identifier/password
straight to bff's `POST /register`, which forwards to backend's `POST /register`
(Argon2-hashes the password, saves the user) and 303s the browser back to `next` (the
login page, supplied by the form) — `?error=1` appended on failure, e.g. a taken
identifier.

Because `/oauth/login` and `/oauth/authorize` are separate, independently callable
endpoints, the `login_session` requirement on `/oauth/authorize` is what prevents a
future direct caller (e.g. an SPA built straight against backend, bypassing bff) from
skipping authentication by calling things in the wrong order — the ordering is enforced
by backend's own state, not by convention.

bff routes:

| Method | Path                         | Returns                                                                                                                                                                                                                      |
|--------|------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| GET    | `/health`                    | `ok`                                                                                                                                                                                                                         |
| POST   | `/login`                     | Form `{identifier, password, redirect_uri, next}`. Verifies credentials, drives the PKCE exchange, sets session cookie, 303 → `redirect_uri`; wrong credentials → 303 → `next?error=1`; `403` if `Origin`/`Referer` isn't in `trusted_origins`; `422` if a required field is missing |
| POST   | `/register`                  | Form `{identifier, password, next}`. Forwards to backend, 303 → `next` (success) or `next?error=1` (failure, e.g. taken identifier); `403` if `Origin`/`Referer` isn't in `trusted_origins`                                  |
| *      | *(configured `path_prefix`)* | Proxied to the matching route's `upstream_url` (prefix stripped), cookie swapped for `Authorization: Bearer`; `401` if no/unknown session, `404` if no route matches                                                         |

login routes:

| Method | Path             | Returns                                                              |
|--------|------------------|----------------------------------------------------------------------|
| GET    | `/`              | Login page (`login/static/index.html`)                               |
| GET    | `/register.html` | Registration page (`login/static/register.html`)                     |
| GET    | `/config.js`     | `window.BFF_URL = "...";` — lets the static pages know where to POST |
| GET    | `/static/*`      | Static assets (`login/static/`)                                      |

Backend routes:

| Method | Path               | Returns                                                                                                                                               |
|--------|--------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|
| GET    | `/health`          | `ok`                                                                                                                                                  |
| POST   | `/oauth/login`     | Verifies identifier/password (Argon2) against `UserStorage`; `{ login_session }` on success, `401` otherwise                                          |
| POST   | `/register`        | Hashes the password (Argon2) and saves a new user; `201`, or `409` if the identifier is taken                                                         |
| GET    | `/oauth/authorize` | Consumes `login_session` (`401` if invalid/expired/reused), then 303 → `redirect_uri?code=...&state=...` if `redirect_uri` is allowlisted, else `400` |
| POST   | `/oauth/token`     | Verifies `code_verifier` against the stored (single-use, TTL'd) challenge; `{ access_token, refresh_token, token_type, expires_at }`                  |

## TODO ledger

Open items, in priority order (highest first):

- [ ] **No rate limiting.** `/oauth/login`, `/register`, `/oauth/token` have no
      attempt throttling. Argon2 raises the cost per guess but doesn't stop
      distributed brute-forcing or registration spam.
- [ ] **No server-side password policy.** `minlength="8"` on `register.html` is
      client-side only; `register.rs` accepts any length, including empty, via a
      direct API call.
- [ ] **Client authentication** — the bff's token-exchange request already carries
      `client_id`/`client_secret` fields (currently always `None`); wiring real
      client credentials into the backend's `/oauth/token` is future work for
      defense in depth alongside PKCE.
- [ ] **Cookie `Secure` attribute** — bff's session cookie has no `Secure` flag yet
      (local HTTP dev); needed before any real HTTPS deployment.
- [ ] **No CSRF token on the authenticated proxy layer.** Once a user has the
      `wa_session` cookie, any state-changing request `proxy.rs` forwards is the
      classic CSRF shape (ambient cookie auth, attached automatically regardless of
      which site triggered the request). Currently mitigated only by
      `SameSite=Lax` on the cookie (blocks it on cross-site POST, but still sent on
      a top-level cross-site GET, and offers nothing if the cookie ever needs
      `SameSite=None`, e.g. for a cross-site embedded frontend). A double-submit
      cookie (random value set on login, required to match a header/field on
      state-changing proxied requests) would add real defense-in-depth here,
      independent of browser SameSite support. Lower priority than the items
      above -- SameSite=Lax is a working mitigation today, this is belt-and-suspenders.

Done:

- [x] **PKCE verification** — backend stores `code_challenge` at `/oauth/authorize`
      and checks `code_verifier` against it at `/oauth/token`.
- [x] **`redirect_uri` allowlist** — backend-only: bff forwards whatever
      `redirect_uri` a caller passes to `/login` straight through to backend's
      `/oauth/authorize` as-is; backend is the single place that allowlists it, and
      refuses to issue a code (so bff can't hand out a token) for anything not
      listed. Deliberately not duplicated in bff — one allowlist, one place it can
      drift.
- [x] **Token delivery** — bff sets an HttpOnly session cookie instead of a
      query-string access token.
- [x] **State/code single-use + expiry** — backend's PKCE store enforces single-use
      + TTL (bff no longer needs its own pending-auth store — the whole exchange
      with backend happens inside one request, see the login flow above).
- [x] **Real user authentication** — `POST /oauth/login` verifies
      identifier/password (Argon2) against `UserStorage` and returns a single-use
      `login_session` that `/oauth/authorize` requires before it will issue a code,
      so authentication is enforced server-side regardless of caller order.
      `POST /register` creates users. `login`'s static pages have real
      login/register forms.
- [x] **Access tokens now carry user identity.** `/oauth/authorize` threads the
      `user_id` `take_session` resolves into the PKCE record (`PkceStorage` now
      stores/returns it alongside `code_challenge`/`method`/`redirect_uri`);
      `/oauth/token`'s `TokenResponse` carries it as `user_id`, and bff's
      `SessionData` carries it through to its own session store. A valid token can
      now be attributed to the user who authenticated for it — this was the
      prerequisite for JWKS/JWT work (a JWT can now get a real `sub` claim).
- [x] **Username enumeration via login timing fixed.** `login.rs` now always
      hashes: an unknown `identifier` verifies against a fixed dummy Argon2 hash
      (`DUMMY_PASSWORD_HASH`, generated once and cached) instead of returning
      immediately, so an unknown identifier costs the same as a known one with a
      wrong password. Response timing no longer distinguishes the two. Both this
      and the token-identity fix's Argon2 calls run inside `spawn_blocking` (CPU-
      heavy synchronous work off the tokio worker thread), via one shared,
      lazily-built `Argon2` instance (`crate::crypto::ARGON2`).
- [x] **Uniqueness check on `identifier` at registration.** `UserStorage::create_user`
      now checks-and-inserts atomically under one lock (`InMemoryUserStorage`), so a
      second registration for a taken `identifier` is rejected (`409`) instead of
      silently coexisting with the first under an undefined "which one wins" order.
- [x] **Login/register CSRF fixed.** `POST /login` and `POST /register` now check
      the request's `Origin` header (falling back to `Referer`) against
      `trusted_origins` (`WA_TRUSTED_ORIGINS`) before doing anything else —
      `403` if it's missing or not on the list. A hostile site can no longer
      auto-submit a login/register form to bff and have it processed.

## Prerequisites

- Rust (stable) — `cargo` on PATH.

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

The `redirect_uri` a caller's login form submits to bff's `/login` is not separately
allowlisted by bff — it's forwarded as-is to backend's `/oauth/authorize`, and
backend's `WA_REDIRECT_URI_ALLOWLIST` / `config.yaml` is the only place it's checked
(see the login flow above). `backend/config.yaml`'s allowlist therefore needs to list
every real destination callers of `/login` are allowed to land on, e.g. `login`'s own
page:

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

| Variable                    | App          | Default                         | Description                                                                                                                                                                                                                                    |
|-----------------------------|--------------|---------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `WA_CONFIG_FILE`            | backend, bff | `config.yaml` (relative to cwd) | Path to the optional YAML config overlay                                                                                                                                                                                                       |
| `WA_PORT`                   | backend      | `1983`                          | Backend listen port                                                                                                                                                                                                                            |
| `WA_REDIRECT_URI_ALLOWLIST` | backend      | `http://localhost:8081/`        | Comma-separated allowlist of valid `redirect_uri` values — checked once, at `/oauth/authorize`, for whatever bff forwards from `/login`                                                                                                        |
| `WA_PKCE_CODE_TTL_SECS`     | backend      | `300`                           | How long an issued auth code stays redeemable                                                                                                                                                                                                  |
| `WA_LOGIN_SESSION_TTL_SECS` | backend      | `60`                            | How long a `/oauth/login` session token stays valid for the follow-up `/oauth/authorize` call — just a server-to-server hop, so short-lived                                                                                                    |
| `WA_LOGIN_PORT`             | login        | `8081`                          | Login page listen port                                                                                                                                                                                                                         |
| `WA_BFF_PORT`               | bff          | `8080`                          | bff listen port                                                                                                                                                                                                                                |
| `WA_BFF_URL`                | bff, login   | `http://localhost:8080`         | Public base URL of the bff, used by login to redirect into it                                                                                                                                                                                  |
| `WA_BACKEND_URL`            | bff          | `http://localhost:1983`         | Backend base URL the bff exchanges codes against                                                                                                                                                                                               |
| `WA_SESSION_COOKIE_NAME`    | bff          | `wa_session`                    | Name of the HttpOnly session cookie set after login                                                                                                                                                                                            |
| `WA_TRUSTED_ORIGINS`        | bff          | `http://localhost:8081`         | Comma-separated origins allowed to POST to `/login`/`/register` (checked against `Origin`, falling back to `Referer`) — anything else gets `403`, which is what stops a hostile site from auto-submitting a login/register form ("login CSRF") |
| `WA_CLAIM_ENRICHMENT_URL`   | backend      | *(unset)*                       | Optional upstream claim-enrichment endpoint (unused yet)                                                                                                                                                                                       |

## Testing

```bash
cargo test
```

Runs the full workspace test suite (backend, bff, login — `testing/downstream-service`
and `testing/user-service` are excluded, being standalone fixtures, not workspace
members):

- `backend`: unit tests inline per module (`model/*`, `storage/in_memory.rs` —
  including `InMemoryLoginSessionStorage`'s single-use/expiry behavior, `config.rs` —
  env/YAML precedence via a small `EnvGuard` + shared `Mutex` since `Config::load()`
  touches process env) plus `backend/tests/api_test.rs` (black-box, via
  `weaveauth::server::app`) covering `/health`, `/register` + `/oauth/login` +
  `/oauth/authorize` + `/oauth/token`'s full authenticate-then-authorize round trip,
  and allowlist/PKCE/single-use/TTL behavior.
- `bff`: unit tests inline (`config.rs`, `storage/in_memory.rs`, and `proxy.rs`'s pure
  `is_hop_by_hop`/`extract_cookie` helpers) plus `bff/tests/pkce_flow.rs` (the full
  server-to-server login exchange including credential verification, its failure
  modes, and that backend is never browser-visible), `bff/tests/register.rs`
  (registration forwarding + its `next`/`?error=1` redirect), and `bff/tests/proxy.rs`
  (bearer-swap, prefix matching, query/body forwarding, auth failures).
- `login`: unit tests inline (`Config::load()`) plus `login/tests/redirect_test.rs`
  (`/config.js`, and that both the login and registration static pages, plus other
  static assets, still serve correctly).

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
