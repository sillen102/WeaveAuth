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
  the account become `email_verified: true` and the identity link. (There's no email
  delivery for password resets yet, so if the matching account was squatted by someone else and the
  real owner never had its password, they're stuck — see [TODO.md](TODO.md).)

The email itself is only trusted as proof when it comes with independent confirmation —
`resolve_oidc_login` takes a `VerifiedEmail`, a type that can only be constructed by
naming what verified it (e.g. `claims.email_verified() == Some(true)` from a signature-
checked OIDC id_token). This is enforced by the type system, not just a doc comment, so a
future caller can't accidentally pass an unconfirmed email and reopen the same
account-takeover hole for the "already verified" merge path.

bff routes. Two independent per-IP rate-limit buckets (`tower_governor`) sit in front: one shared by `/login` + `/register`, one shared by every
proxied route — hammering one side can't burn the other's budget. `/health` is
exempt (a cheap liveness check infra commonly polls, shouldn't get caught in either
bucket):

| Method | Path                         | Returns                                                                                                                                                                                                                                                                                                                                                                                                                              |
|--------|------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| GET    | `/docs`, `/docs/scalar.js`, `/openapi.json` | OpenAPI schema and Scalar UI for the documented routes. Only mounted when `WA_DOCS_ENABLED` is true (`404` otherwise); rate-limited in its own bucket, separate from the auth and proxy buckets                                                                                                                                                                                       |
| GET    | `/health`                    | `ok`                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| POST   | `/login`                     | Form `{email, password, redirect_uri, next}`. Verifies credentials, drives the PKCE exchange, sets session cookie, 303 → `redirect_uri`; wrong credentials → 303 → `next?error=1`; `403` if `Origin`/`Referer` isn't in `trusted_origins`; `429` if the auth bucket is exhausted; `422` if a required field is missing                                                                                                               |
| POST   | `/register`                  | Form `{email, password, redirect_uri, next}`. Forwards to backend then immediately logs the new user in the same way `/login` does, 303 → `redirect_uri` with session cookie set; registration failure → 303 → `next?error=1` (e.g. taken email); `403` if `Origin`/`Referer` isn't in `trusted_origins`; `429` if the auth bucket is exhausted                                                                                      |
| GET    | `/oidc/{provider}/login`     | Fetches the provider's consent-screen URL from backend server-to-server and relays the redirect; stashes `redirect_uri`/`next` in short-lived `/oidc`-scoped cookies; `404` for an unknown provider                                                                                                                                                                                                                                  |
| GET    | `/oidc/{provider}/callback`  | Where the provider redirects back to (registered as this URL in the provider's console, not backend's). Forwards `code`+`state` to backend; on success finishes the login like `/login` would; if backend reports `password_confirmation_required`, 303 → `next?email=...` instead, with `pending_link_token` in a short-lived `wa_oidc_pending_link_token` cookie, never in the URL (the login page's own prompt, not an error); failure → 303 → `next?error=1` (`next?error=consent_required` if backend refused because a required permission was declined); `400` if the flow cookies are missing/expired |
| POST   | `/oidc/confirm-link`         | Form `{password, redirect_uri, next}`; `pending_link_token` is read from the `wa_oidc_pending_link_token` cookie, not the form. Forwards to backend's `/oauth/oidc/confirm-link`; on success finishes the login like `/login` does, 303 → `redirect_uri` with session cookie set; wrong password or a dead/expired token → 303 → `next?error=link_failed` (the token is single-use on backend regardless of outcome, so there's nothing to retry); `400` if `redirect_uri` isn't allowlisted; `403` if `Origin`/`Referer` isn't in `trusted_origins` |
| *      | *(configured `path_prefix`)* | Proxied to the matching route's `upstream_url` (prefix stripped), cookie swapped for `Authorization: Bearer`; `401` if no/unknown session or the refresh token is rejected, `502` if backend is unreachable or fails (5xx / bad body) during a token refresh, `404` if no route matches, `429` if the proxy bucket is exhausted                                                                                                                                                                                                                         |

login routes:

| Method | Path             | Returns                                                                                                                                                 |
|--------|------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| GET    | `/`              | Login shell (`login/src/index.html`, compiled into the binary) — loads `login.html` via HTMx                                                            |
| GET    | `/index.html`    | Same shell, for anyone linking there directly                                                                                                           |
| GET    | `/login.html`    | Login page, server-rendered from `login/templates/login.html` — also renders the OIDC password-confirm prompt when `?email=...` is present |
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
`WA_CONFIG_FILE`; a missing file is not an error, defaults apply, but one that exists and
can't be read — wrong permissions, say — stops the service from starting), then lets the
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
`wa_session` cookie. No session → `401`. If the access token has expired, bff refreshes it first: a rejected refresh token → `401`; backend unreachable or failing during the refresh → `502`. No matching route → `404`.

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

backend's `extra_data_handler` is YAML-only too. It decides what happens to fields a
register request carries beyond `email`/`password`: `kind: webhook` POSTs them to a URL,
`kind: process` runs an executable the deployer mounts and calls it over gRPC. A plugin
is an ordinary binary, so it uses ordinary libraries and keeps its own connection pools
— and it is **not sandboxed**: each plugin runs as its own user (`uid`/`gid`, defaults
1001 and 1002), but mounting one is still equivalent to shipping application code.
See **[docs/plugins.md](docs/plugins.md)**.

```yaml
extra_data_handler:
  kind: process
  command: /plugins/register
  env:
    LOG_LEVEL: info
```

Credentials are better passed as `WA_PLUGIN_REGISTRATION_ENV_<NAME>` in backend's own
environment — forwarded to that plugin as `<NAME>`, so they stay in your secret store
rather than in `config.yaml`. The plugin inherits nothing else, and every call carries a token
generated at startup that its SDK checks.

backend's `login_claims_handler` is the same shape, wired into a different flow: it's
called on every token mint (both `authorization_code` and `refresh_token` grants) and its
output is merged into the issued JWT as extra claims. Same two kinds — `kind: webhook`
POSTs `{user_id, email}` and expects a JSON object of claims back, `kind: process` calls the
plugin's one generic rpc with `hook: "login_claims"` and expects a `google.protobuf.Struct`
back (so claim values can nest, e.g. `roles: {"admin": ["user-1", "user-2"]}`). An error from
either kind fails
the token request — no token is ever issued without the claims it's configured to carry.
A claim name the handler returns that collides with a reserved one (`sub`, `email`,
`email_verified`, `iat`, `exp`) also fails the request, so a plugin/webhook can't spoof
identity claims.

```yaml
login_claims_handler:
  kind: process
  command: /plugins/login-claims
  env:
    LOG_LEVEL: info
```

Credentials for it are passed the same way, as `WA_PLUGIN_LOGIN_CLAIMS_ENV_<NAME>`.

An OIDC provider entry can set `scopes: [...]`, what its consent screen asks for besides
`openid` (always sent). Default `[email, profile]`; setting it replaces the list, so keep
`email`. A scope only changes what the provider puts in the id_token — claims it doesn't
return there (e.g. Google's phone number) aren't reachable by adding a scope.

It can also set `extra_claims: {<field>: <id_token claim>}` (e.g.
`last_name: family_name`; claim names vary by provider, so nothing is mapped by default).
On a user's first login through that provider the mapped claims are handed to
`extra_data_handler` like a register request's extra fields; a handler failure fails the login
(`502`) and no user is created.

```yaml
oidc_providers:
  google:
    client_id: set-in-.env
    client_secret: set-in-.env
    issuer: https://accounts.google.com
    redirect_uri: https://bff.example.com/oidc/google/callback
    scopes:                   # the default
      - email
      - profile
    extra_claims:
      first_name: given_name    # Google's id_token claim names (`profile` scope)
      last_name: family_name
extra_data_handler:
  kind: webhook
  url: http://localhost:10001/hooks/register
```

Setting `extra_claims` (or `profile_apis` below) without both an `extra_data_handler` and a
`login_claims_handler` makes backend refuse to start (the fields are pointless unless they
also come back as token claims).

Some claims never appear in the id_token. Google's phone number is one: it can only be read
from the People API. A provider's `profile_apis` is a list of extra GET calls made with the
user's access token on their first login, each mapping `field name -> JSON pointer` (RFC 6901)
into the response. Their fields are merged with the `extra_claims` ones and go to
`extra_data_handler` in the same call. `url` must be `https://` (loopback excepted), since it
carries the access token.

```yaml
oidc_providers:
  google:
    scopes:
      - email
      - profile
      - https://www.googleapis.com/auth/contacts.readonly
    profile_apis:
      - url: https://people.googleapis.com/v1/people/me?personFields=phoneNumbers
        required: false   # the default
        scope: https://www.googleapis.com/auth/contacts.readonly
        claims:
          phone_number: /phoneNumbers/0/canonicalForm
```

`scope` is the permission the call needs. Google's consent screen lets users untick individual
permissions and continue, so before calling, backend checks the scopes the token response says
were granted (a response without a `scope` field counts as granting what was asked). If the
user declined it, an optional entry is skipped without calling anything, and a `required` entry
refuses the login with `403`; bff then sends the browser back to the login page with
`?error=consent_required`, which says a permission is needed and to try again. Leave `scope`
out and the call is always made.

`required` decides what a failed call does. A failure is a transport error, a non-2xx
response or a body that isn't JSON. With `required: false` (the default) it is logged as a
warning and that call's fields are left out; the login carries on. With `required: true` the
login fails (`502`) and no user is created. A pointer that finds nothing (a Google account
with no saved phone number) is not a failed call: the field is simply left out, without a log
line, while the call's other fields still count. Only a `required: true` entry treats a
missing value as a failure.

About the Google example. The phone number saved under the account's Personal info is not
returned by `people/me` (not even with `user.phonenumbers.read`); Google returns phone numbers
from the user's own **contact card** ("Me" in Google Contacts), which needs the
`contacts.readonly` scope. Two consequences: that scope lets the app read *all* of the user's
contacts, and the number is whatever the user typed on their contact card, so it is not
verified, don't treat it as proof of ownership. `contacts.readonly` is a sensitive Google
scope: until your Google Cloud app passes OAuth verification, only its test users can grant it,
and it must be declared under the project's "Data Access" scopes. Users without a phone on that
card get no `phone_number` and log in normally (`required: false`).

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

A `.env` file in the working directory or any parent directory is loaded first. A missing one is fine; a malformed one stops backend and bff from starting. An invalid `WA_LOGIN_PORT` (or other invalid login setting) likewise stops login.

| Variable                     | App                 | Default                                                 | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|------------------------------|---------------------|---------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `WA_CONFIG_FILE`             | backend, bff        | `config.yaml` (relative to cwd)                         | Path to the optional YAML config overlay                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `WA_PORT`                    | backend             | `1983`                                                  | Backend listen port                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `WA_LOGIN_PORT`              | login               | `8081`                                                  | Login page listen port                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `WA_BFF_PORT`                | bff                 | `8080`                                                  | bff listen port                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `WA_BACKEND_URL`             | bff                 | `http://localhost:1983`                                 | Backend base URL the bff exchanges codes against                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `WA_BFF_URL`                 | bff, login          | `http://localhost:8080`                                 | Public base URL of the bff, used by login to redirect into it                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `WA_LOGIN_PUBLIC_URL`        | login, bff, backend | `http://localhost:8081`                                 | Login page's own public origin. login uses it as the `redirect_uri` fallback and to build `own_url`/`next` — pinned in config rather than trusted from `Host`/`X-Forwarded-Proto`. bff defaults `WA_TRUSTED_ORIGINS` from it, and backend defaults `WA_REDIRECT_URI_ALLOWLIST` from it (with a trailing `/` appended) — both only when that var isn't set explicitly. When all three run in the same container (`weaveauth-launcher`), setting just this one is enough. Not bff's or backend's own URL. |
| `WA_REDIRECT_URI_ALLOWLIST`  | backend             | `{WA_LOGIN_PUBLIC_URL}/`, else `http://localhost:8081/` | Comma-separated allowlist of valid `redirect_uri` values — checked once, at `/oauth/authorize`, for whatever bff forwards from `/login`. Exact string match, hence the trailing slash — matches login's own default `redirect_uri`                                                                                                                                                                                                                                                                 |
| `WA_TRUSTED_ORIGINS`         | bff                 | `WA_LOGIN_PUBLIC_URL`, else `http://localhost:8081`     | Comma-separated origins allowed to POST to `/login`/`/register` (checked against `Origin`, falling back to `Referer`) — anything else gets `403`, which is what stops a hostile site from auto-submitting a login/register form ("login CSRF")                                                                                                                                                                                                                                                     |
| `WA_SESSION_COOKIE_NAME`     | bff                 | `wa_session`                                            | Name of the HttpOnly session cookie set after login                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `WA_PKCE_CODE_TTL_SECS`      | backend             | `300`                                                   | How long an issued auth code stays redeemable                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `WA_LOGIN_SESSION_TTL_SECS`  | backend             | `60`                                                    | How long a `/oauth/login` session token stays valid for the follow-up `/oauth/authorize` call — just a server-to-server hop, so short-lived                                                                                                                                                                                                                                                                                                                                                        |
| `WA_RATE_LIMIT_MAX_ATTEMPTS` | bff                 | `10`                                                    | Burst size for `/login`/`/register`'s per-IP rate limit (`tower_governor`) — independent bucket per route                                                                                                                                                                                                                                                                                                                                                                                          |
| `WA_RATE_LIMIT_WINDOW_SECS`  | bff                 | `60`                                                    | Approximate window the burst size applies over; replenishes at `max_attempts / window_secs` per second                                                                                                                                                                                                                                                                                                                                                                                             |
| `WA_DOCS_ENABLED`            | bff                 | `false`                                                 | Serve the OpenAPI schema (`/openapi.json`) and Scalar UI (`/docs`). Off by default — bff is internet-facing and these are unauthenticated descriptions of the auth surface, so a deployment opts in                                                                                                                                                                                                                                                                                              |
| `WA_MAX_BCRYPT_COST`         | backend             | `12`                                                    | Highest bcrypt cost factor accepted when verifying an imported legacy-user password hash — caps how long a single login can tie up a blocking-pool thread                                                                                                                                                                                                                                                                                                                                        |
| `WA_SETUID_HELPER`           | backend             | *(unset; the image sets it)*                            | `weaveauth-plugin-exec`, the binary plugins are started through. It alone holds `CAP_SETUID`/`CAP_SETGID` and switches to each plugin's `uid`/`gid`, refusing 0. Unset, backend switches users itself, which needs `CAP_SETUID`/`CAP_SETGID` (or root), unless `uid`/`gid` are its own (local runs) |
| `WA_PLUGIN_<PLUGIN>_ENV_<NAME>` | backend             | *(unset)*                                               | Forwarded to the named plugin as `<NAME>`, prefix stripped — how a plugin gets its own credentials (`WA_PLUGIN_REGISTRATION_ENV_DATABASE_URL` reaches the registration plugin as `DATABASE_URL`) without them sitting in `config.yaml`. `<PLUGIN>` scopes them, so a later surface doesn't inherit this one's secrets; the extra-data plugin is `REGISTRATION`, the login-claims plugin is `LOGIN_CLAIMS`. The plugin inherits nothing else |

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

Single multi-stage `Dockerfile` at repo root. The `rust:1.98-slim-trixie` builder compiles
the three services plus `weaveauth-launcher` and `weaveauth-plugin-exec`. The `gcr.io/distroless/cc-debian13`
runtime (no shell) copies them plus `/app/login/static` and `/app/login/templates`, and
runs `weaveauth-launcher`, which starts all three and exits when any one of them does.
Everything runs as `weaveauth` (1000) with no capabilities. The exception is
`weaveauth-plugin-exec` (`WA_SETUID_HELPER`), which has `CAP_SETUID`/`CAP_SETGID` as file
capabilities, so plugins can run as their own users (`wa-registration` 1001,
`wa-login-claims` 1002). A deployment without plugins needs no capabilities. With
plugins, `capabilities.drop: [ALL]` (the Kubernetes restricted Pod Security Standard),
`--cap-drop SETUID`/`SETGID` or `no-new-privileges` stop them from starting, and backend
then refuses to boot; see [docs/plugins.md](docs/plugins.md#deploying). The launcher
doesn't forward `SIGTERM`, so use `docker run --init` for a prompt `docker stop`.

```bash
docker build -t weaveauth .
docker run -p 1983:1983 -p 8080:8080 -p 8081:8081 weaveauth
```

## License

Apache License 2.0. Copyright 2026 Silvio Sabo.
