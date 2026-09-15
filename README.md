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
- **`weaveauth-login`** (axum + Tera, server-rendered UI) — `:8081`. Optional, thin,
  replaceable: `/` serves a small shell (`index.html`, compiled into the binary) that
  loads `login.html` by default and switches between it and `register.html` via HTMx,
  keeping the URL's query string (`redirect_uri`, etc.) intact across the swap.
  `login.html`/`register.html` are Tera templates rendered per-request from
  `login/templates/` — no build step, so a deployer can drop in reskinned versions of
  those files without touching the shell that wires them together. Per
  `login/AGENTS.md`, these templates must stay plain HTML/CSS with **no `<script>` or
  client-side logic at all** — every dynamic value (`redirect_uri`, the form's
  `action`, OIDC links, error messages, the OIDC password-confirm view) is computed
  server-side and injected via the Tera context; only the compiled-in shell is allowed
  its own JS.

Login (authorization-code + PKCE) flow — the browser only ever talks to `login` and
`bff`; backend is never in the browser's network tab:

1. Browser hits `login`'s shell (`/`), which loads `login.html`: a real
   username/password form (server-rendered with its `action` already set to
   `{WA_BFF_URL}/login`) plus a link to `register.html` (same pattern, posts to
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

Registration follows the same shape: `register.html` posts email/password straight to
bff's `POST /register`, which forwards to backend's `POST /register` (Argon2-hashes the
password, saves the user with `email_verified: false`), then immediately drives the same
login flow as step 3 onward above using those same credentials — one form submission
ends with a session cookie set and the browser on `redirect_uri`, no separate "now sign
in" step. Registration failure (e.g. a taken email) 303s back to `next?error=1` instead.

Because `/oauth/login` and `/oauth/authorize` are separate, independently callable
endpoints, the `login_session` requirement on `/oauth/authorize` is what prevents a
future direct caller (e.g. an SPA built straight against backend, bypassing bff) from
skipping authentication by calling things in the wrong order — the ordering is enforced
by backend's own state, not by convention.

### Third-party login (OIDC) and account linking

`GET /oauth/oidc/{provider}/login` / `GET /oauth/oidc/{provider}/callback` (backend) let
a user sign in via Google/LinkedIn/Apple etc. instead of a password; bff proxies both
(see its own `/oidc/{provider}/*` routes below) since backend isn't internet-exposed.
Accounts are linked across providers, and to a password account, **by email** — sign in
with Google today, LinkedIn tomorrow, same account, as long as the email matches. Each
`User` has an `email_verified` flag: `false` for a plain password registration (this app
sends no verification email), `true` once an OIDC provider has confirmed it.

The linking decision (`UserStorage::resolve_oidc_login`) never merges an OIDC identity
into an account whose email isn't already verified — an unverified account could belong
to an attacker who pre-registered a victim's email with a password of their own choosing;
merging into it on email match alone would hand that attacker a login path into the real
owner's account. So:

- New email, or the matching account is already verified → the identity links
  immediately, no extra step.
- Matching account exists but `email_verified: false` → backend returns
  `password_confirmation_required` instead of a session. The caller must submit that
  account's *current* password to `POST /oauth/oidc/confirm-link`; only on success does
  the account become `email_verified: true` and the identity link. (There's currently no
  password-reset flow, so if the matching account was squatted by someone else and the
  real owner never had its password, they're stuck — see TODO ledger.)

The email itself is only trusted as proof when it comes with independent confirmation —
`resolve_oidc_login` takes a `VerifiedEmail`, a type that can only be constructed by
naming what verified it (e.g. `claims.email_verified() == Some(true)` from a signature-
checked OIDC id_token). This is enforced by the type system, not just a doc comment, so a
future caller can't accidentally pass an unconfirmed email and reopen the same
account-takeover hole for the "already verified" merge path.

bff routes. Two independent per-IP rate-limit buckets (`tower_governor`, see TODO
ledger) sit in front: one shared by `/login` + `/register`, one shared by every
proxied route — hammering one side can't burn the other's budget. `/health` is
exempt (a cheap liveness check infra commonly polls, shouldn't get caught in either
bucket):

| Method | Path                         | Returns                                                                                                                                                                                                                                                                                                                                                                                                                              |
|--------|------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| GET    | `/health`                    | `ok`                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| POST   | `/login`                     | Form `{email, password, redirect_uri, next}`. Verifies credentials, drives the PKCE exchange, sets session cookie, 303 → `redirect_uri`; wrong credentials → 303 → `next?error=1`; `403` if `Origin`/`Referer` isn't in `trusted_origins`; `429` if the auth bucket is exhausted; `422` if a required field is missing                                                                                                               |
| POST   | `/register`                  | Form `{email, password, redirect_uri, next}`. Forwards to backend then immediately logs the new user in the same way `/login` does, 303 → `redirect_uri` with session cookie set; registration failure → 303 → `next?error=1` (e.g. taken email); `403` if `Origin`/`Referer` isn't in `trusted_origins`; `429` if the auth bucket is exhausted                                                                                      |
| GET    | `/oidc/{provider}/login`     | Fetches the provider's consent-screen URL from backend server-to-server and relays the redirect; stashes `redirect_uri`/`next` in short-lived `/oidc`-scoped cookies; `404` for an unknown provider                                                                                                                                                                                                                                  |
| GET    | `/oidc/{provider}/callback`  | Where the provider redirects back to (registered as this URL in the provider's console, not backend's). Forwards `code`+`state` to backend; on success finishes the login like `/login` would; if backend reports `password_confirmation_required`, 303 → `next?pending_link_token=...&email=...` instead (the login page's own prompt, not an error); failure → 303 → `next?error=1`; `400` if the flow cookies are missing/expired |
| POST   | `/oidc/confirm-link`         | Form `{pending_link_token, password, redirect_uri, next}`. Forwards to backend's `/oauth/oidc/confirm-link`; on success finishes the login like `/login` does, 303 → `redirect_uri` with session cookie set; wrong password or a dead/expired token → 303 → `next?error=link_failed` (the token is single-use on backend regardless of outcome, so there's nothing to retry); `403` if `Origin`/`Referer` isn't in `trusted_origins` |
| *      | *(configured `path_prefix`)* | Proxied to the matching route's `upstream_url` (prefix stripped), cookie swapped for `Authorization: Bearer`; `401` if no/unknown session, `404` if no route matches, `429` if the proxy bucket is exhausted                                                                                                                                                                                                                         |

login routes:

| Method | Path             | Returns                                                                                                                                                 |
|--------|------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| GET    | `/`              | Login shell (`login/src/index.html`, compiled into the binary) — loads `login.html` via HTMx                                                            |
| GET    | `/index.html`    | Same shell, for anyone linking there directly                                                                                                           |
| GET    | `/login.html`    | Login page, server-rendered from `login/templates/login.html` — also renders the OIDC password-confirm prompt when `?pending_link_token=...` is present |
| GET    | `/register.html` | Registration page, server-rendered from `login/templates/register.html`                                                                                 |
| GET    | `/static/*`      | Static assets (`login/static/`) — stylesheet, vendored `htmx.min.js`                                                                                    |

Backend routes:

| Method | Path                              | Returns                                                                                                                                                                                                                                                                                                                                                                   |
|--------|-----------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| GET    | `/health`                         | `ok`                                                                                                                                                                                                                                                                                                                                                                      |
| POST   | `/oauth/login`                    | Verifies email/password (Argon2) against `UserStorage`; `{ login_session }` on success, `401` otherwise                                                                                                                                                                                                                                                                   |
| POST   | `/register`                       | Hashes the password (Argon2) and saves a new user (`email_verified: false`); `201`, or `409` if the email is taken                                                                                                                                                                                                                                                        |
| GET    | `/oauth/authorize`                | Consumes `login_session` (`401` if invalid/expired/reused), then 303 → `redirect_uri?code=...&state=...` if `redirect_uri` is allowlisted, else `400`                                                                                                                                                                                                                     |
| POST   | `/oauth/token`                    | Verifies `code_verifier` against the stored (single-use, TTL'd) challenge; `{ access_token, refresh_token, token_type, expires_at }`, JWT carries `email`/`email_verified`                                                                                                                                                                                                |
| GET    | `/oauth/oidc/{provider}/login`    | Not for the browser directly -- bff proxies this. Redirects to the provider's consent screen; `404` for an unknown `provider`                                                                                                                                                                                                                                             |
| GET    | `/oauth/oidc/{provider}/callback` | Not for the provider directly -- bff forwards `code`+`state` here server-to-server. Resolves the OIDC identity to a user by verified email (see `UserStorage::resolve_oidc_login`); `{status: "authenticated", login_session}` on success, or `{status: "password_confirmation_required", pending_link_token, email}` if a matching account exists but isn't verified yet |
| POST   | `/oauth/oidc/confirm-link`        | `{pending_link_token, password}`. Verifies the password against the account named in the pending link; on success marks it `email_verified` and links the identity, `{ login_session }`; `401` on wrong password, `400` if the token is invalid/expired                                                                                                                   |

## TODO ledger

Open items, in priority order (highest first):

- [ ] **No password-reset flow.** An OIDC login whose email matches an existing
      but unverified local account can't merge into it automatically (would be
      an account-takeover vector -- see `UserStorage::resolve_oidc_login`), so
      it's routed to `/oauth/oidc/confirm-link`, which requires that account's
      *current* password. If the account was squatted by someone else (the
      real owner never had a password for it, e.g. an attacker pre-registered
      their email), there is currently no way back in -- the real owner is
      stuck. The fix is a standard email-based password-reset flow (proves
      mailbox control independently of any password), which also needs
      outbound email infrastructure this app doesn't have yet (no
      SMTP/transactional-email integration anywhere in the codebase). Once
      built, a completed reset should also flip that account's
      `email_verified` to `true` (mailbox control is proof of ownership,
      same as an OIDC provider's), which then lets a subsequent OIDC login
      link automatically via the existing verified-match path -- no special
      case needed for the reset-then-OIDC order.
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
- [x] **Rate limiting on bff's auth endpoints and proxy layer.** Per-IP limiting via
      [`tower_governor`](https://crates.io/crates/tower_governor) (a GCRA/leaky-bucket
      limiter built on the widely-used `governor` crate — chosen over rolling a
      custom limiter or reaching for a younger/unproven crate; see commit history
      for the comparison), applied as two independent `tower` layers, each with its
      own bucket per peer IP (`WA_RATE_LIMIT_MAX_ATTEMPTS` / `WA_RATE_LIMIT_WINDOW_SECS`,
      default 10 attempts/60s for both): one shared by `/login` + `/register`, one
      shared by every proxied route — hammering the proxy layer can't burn the auth
      bucket or vice versa. `/health` is exempt from both (a cheap liveness check
      infra commonly polls at its own cadence). Only bff needed this — backend's
      `/oauth/login`, `/register`, `/oauth/token` aren't directly internet-reachable
      (see Architecture above), so bff is the only actual attack surface for
      credential-stuffing/registration-spam volume.

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

| Variable                     | App          | Default                         | Description                                                                                                                                                                                                                                    |
|------------------------------|--------------|---------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `WA_CONFIG_FILE`             | backend, bff | `config.yaml` (relative to cwd) | Path to the optional YAML config overlay                                                                                                                                                                                                       |
| `WA_PORT`                    | backend      | `1983`                          | Backend listen port                                                                                                                                                                                                                            |
| `WA_REDIRECT_URI_ALLOWLIST`  | backend      | `http://localhost:8081/`        | Comma-separated allowlist of valid `redirect_uri` values — checked once, at `/oauth/authorize`, for whatever bff forwards from `/login`                                                                                                        |
| `WA_PKCE_CODE_TTL_SECS`      | backend      | `300`                           | How long an issued auth code stays redeemable                                                                                                                                                                                                  |
| `WA_LOGIN_SESSION_TTL_SECS`  | backend      | `60`                            | How long a `/oauth/login` session token stays valid for the follow-up `/oauth/authorize` call — just a server-to-server hop, so short-lived                                                                                                    |
| `WA_LOGIN_PORT`              | login        | `8081`                          | Login page listen port                                                                                                                                                                                                                         |
| `WA_BFF_PORT`                | bff          | `8080`                          | bff listen port                                                                                                                                                                                                                                |
| `WA_BFF_URL`                 | bff, login   | `http://localhost:8080`         | Public base URL of the bff, used by login to redirect into it                                                                                                                                                                                  |
| `WA_BACKEND_URL`             | bff          | `http://localhost:1983`         | Backend base URL the bff exchanges codes against                                                                                                                                                                                               |
| `WA_SESSION_COOKIE_NAME`     | bff          | `wa_session`                    | Name of the HttpOnly session cookie set after login                                                                                                                                                                                            |
| `WA_TRUSTED_ORIGINS`         | bff          | `http://localhost:8081`         | Comma-separated origins allowed to POST to `/login`/`/register` (checked against `Origin`, falling back to `Referer`) — anything else gets `403`, which is what stops a hostile site from auto-submitting a login/register form ("login CSRF") |
| `WA_RATE_LIMIT_MAX_ATTEMPTS` | bff          | `10`                            | Burst size for `/login`/`/register`'s per-IP rate limit (`tower_governor`) — independent bucket per route                                                                                                                                      |
| `WA_RATE_LIMIT_WINDOW_SECS`  | bff          | `60`                            | Approximate window the burst size applies over; replenishes at `max_attempts / window_secs` per second                                                                                                                                         |
| `WA_CLAIM_ENRICHMENT_URL`    | backend      | *(unset)*                       | Optional upstream claim-enrichment endpoint (unused yet)                                                                                                                                                                                       |

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
  (the embedded shell, that `login.html`/`register.html` render with `bff_url` baked in
  and no `<script>` tags, the OIDC password-confirm view, error-message rendering, and
  that static assets like `htmx.min.js` still serve correctly).

## Docker

Single multi-stage `Dockerfile` at repo root. The `rust:1.98-slim` builder compiles all
three binaries (`--release -p weaveauth -p weaveauth-bff -p weaveauth-login`); the
`debian:bookworm-slim` runtime copies the three binaries plus `/app/login/static`,
`/app/login/templates`, and
`entrypoint.sh`, which launches all three processes.

```bash
docker build -t weaveauth .
docker run -p 1983:1983 -p 8080:8080 -p 8081:8081 weaveauth
```

## License

Apache License 2.0. Copyright 2026 Silvio Sabo.
