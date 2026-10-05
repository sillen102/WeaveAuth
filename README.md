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
  `templates/pages/` — no build step, so a deployer can drop in reskinned versions of
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

Every bff and backend route that takes request input rejects malformed input (a missing field, a wrong
content type, a repeated query key) with the same JSON error body as any other failure, with
`reason: "InvalidRequest"` and status `400`, `415` or `422` -- never a plain-text message.

### Third-party login (OIDC) and account linking

`GET /oauth/oidc/login?provider={provider}` / `GET /oauth/oidc/callback?provider={provider}` (backend) let
a user sign in via Google/LinkedIn/Apple etc. instead of a password; bff proxies both
(see its own `/oidc/{provider}/*` routes below) since backend isn't internet-exposed.
An account can have several provider identities linked to it — Google today, LinkedIn
tomorrow, same account — and backend records each linked `(provider, subject)`. Each `User`
has an `email_verified` flag: `false` for a plain password registration until the user
enters the emailed 9-digit code or links a provider identity, `true` for an account an OIDC
login created.

A provider's verified email proves mailbox access, not that its user owns the account with
that email: the account may have been pre-registered by an attacker with a password of
their choosing. So the linking decision (`UserStorage::resolve_oidc_login`) never links a
new identity on email match alone:

- Identity already linked → signed in.
- New email → a new account is created with this identity linked.
- Matching account exists, identity not linked → backend returns
  `link_confirmation_required` (with `has_password` and `linked_providers`) instead of a
  session. The user confirms with the account's *current* password
  (`POST /oauth/oidc/confirm-link`), or by signing in through one of `linked_providers`,
  which bff sends back to `/oauth/oidc/callback` with the `pending_link_token`. Only then
  is the identity linked (and the account marked `email_verified: true`). The real owner
  of a squatted address, or of a password-less account who lost access to every linked
  provider, resets the password by email first ([docs/flows/password-reset.md](docs/flows/password-reset.md)).

The email itself is only trusted as proof when it comes with independent confirmation —
`resolve_oidc_login` takes a `VerifiedEmail`, a type that can only be constructed by
naming what verified it (e.g. `claims.email_verified() == Some(true)` from a signature-
checked OIDC id_token). This is enforced by the type system, not just a doc comment, so a
future caller can't accidentally create an account for an address the provider never
confirmed.

### bff routes

Three independent per-client rate-limit buckets (`tower_governor`) sit in front: one shared by
`/login`, `/register`, `/oidc/*`, `/verify-email*` and `/password-reset/*`, and one for `/docs`
and `/openapi.json`, both sized by `WA_RATE_LIMIT_MAX_ATTEMPTS`, plus one shared by every proxied
route, sized by `rate_limit_proxy_max_attempts` in `config.yaml` (YAML-only; `6000` for `dev`,
else `600`, per 60 seconds, since every API call a frontend makes draws from it; `0` stops bff
from starting) — hammering one can't burn another's budget. A client is its IPv4 address or
its IPv6 /64. Behind a reverse proxy, set `WA_TRUSTED_PROXIES`, or every client shares the proxy's
bucket. `/health` is exempt (a cheap liveness check infra commonly polls, shouldn't get caught in
any bucket):

| Method | Path                         | Returns                                                                                                                                                                                                                                                                                                                                                                                                                              |
|--------|------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| GET    | `/docs`, `/docs/scalar.js`, `/openapi.json` | OpenAPI schema and Scalar UI for the documented routes. Only mounted when `WA_DOCS_ENABLED` is true (`404` otherwise); rate-limited in its own bucket, separate from the auth and proxy buckets                                                                                                                                                                                       |
| GET    | `/health`                    | `ok`                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| POST   | `/login`                     | Form `{email, password, redirect_uri, next}`. Verifies credentials, drives the PKCE exchange, sets session cookie, 303 → `redirect_uri`; wrong credentials → 303 → `next?error=1`; an unverified email when backend requires verification → no session cookie, a restricted `wa_verify_session` cookie and 303 → login's `verify-email.html` (when verification is optional the user is logged in and gets that cookie too); `403` if `Origin`/`Referer` isn't in `trusted_origins`; `429` if the auth bucket is exhausted; `422` if a required field is missing                                                                                                               |
| POST   | `/register`                  | Form `{email, password, redirect_uri, next}`. Forwards to backend then immediately logs the new user in the same way `/login` does, 303 → `redirect_uri` with session cookie set; if backend requires a verified email, no session cookie but a restricted `wa_verify_session` cookie and 303 → login's `verify-email.html`; registration failure → 303 → `next?error=1` (e.g. taken email); `403` if `Origin`/`Referer` isn't in `trusted_origins`; `429` if the auth bucket is exhausted                                                                                      |
| GET    | `/oidc/{provider}/login`     | Fetches the provider's consent-screen URL from backend server-to-server and relays the redirect; stashes `redirect_uri`/`next` in short-lived `/oidc`-scoped cookies; clears a leftover pending-link cookie unless `confirm_link=true` (the login page's "Continue with" links); `404` for an unknown provider                                                                                                                                                                                                                                  |
| GET    | `/oidc/providers`            | Relays backend's `/oauth/oidc/providers`: the configured OIDC providers, for a login page (login's own or an external one) to offer: `{providers: [{key, display_name}]}`, ordered by key; `key` is what goes in `/oidc/{key}/login`. `502` if backend can't be reached. Shares the auth rate-limit bucket |
| GET    | `/oidc/{provider}/callback`  | Where the provider redirects back to (registered as this URL in the provider's console, not backend's). Forwards `code`+`state` to backend; on success finishes the login like `/login` would; if backend reports `link_confirmation_required`, 303 → `next?email=...&provider=<key>&has_password=true|false[&linked_providers=a,b]` instead, with `pending_link_token` in a short-lived cookie (`__Host-wa_oidc_pending_link_token` over HTTPS, so sibling subdomains can't plant it; `wa_oidc_pending_link_token` on plain-http dev), never in the URL (the login page's own prompt, not an error); a pending-link cookie still present (the flow was started with `confirm_link=true`) is forwarded to backend and cleared, so this sign-in confirms that pending link (`next?error=link_failed` if it isn't through a provider linked to that account); failure → 303 → `next?error=1` (`next?error=consent_required` if backend refused because a required permission was declined); `400` if the flow cookies are missing/expired |
| POST   | `/oidc/confirm-link`         | Form `{password, redirect_uri, next}`; `pending_link_token` is read from the pending-link cookie, not the form. Forwards to backend's `/oauth/oidc/confirm-link`; on success finishes the login like `/login` does, 303 → `redirect_uri` with session cookie set; wrong password or a dead/expired token → 303 → `next?error=link_failed` (the token is single-use on backend regardless of outcome, so there's nothing to retry); `400` if `redirect_uri` isn't allowlisted; `403` if `Origin`/`Referer` isn't in `trusted_origins` |
| POST   | `/verify-email`              | Form `{code, redirect_uri, next}`. Needs the `wa_verify_session` cookie `/login` set (it is only sent to this path). Sends the 9-digit code to backend's `/oauth/email-verification/confirm`; on success finishes the login with the session backend released, sets `wa_session` and 303 → `redirect_uri`; wrong/expired code → 303 → `next?status=invalid`; a code deleted by 5 wrong attempts → `next?status=code_used_up`; locked out after 10 wrong guesses (even the right code is refused) → `next?status=locked&retry_after=<secs>`, or `next?status=locked_until_reset` after 5 lockouts, both clearing `wa_verify_session`; missing/unknown verification session → 303 → `next?status=session_expired`; `400` if `next` isn't a same-origin path or trusted origin or `redirect_uri` isn't allowlisted; `403` if `Origin`/`Referer` isn't in `trusted_origins`; `429` if the auth bucket is exhausted |
| POST   | `/password-reset/request`    | Form `{email}`. Forwards to backend's `/oauth/password-reset/request` and always 303 → login's `forgot-password.html?status=sent`; `502` if backend is unreachable; `403` if `Origin`/`Referer` isn't in `trusted_origins`; `429` if the auth bucket is exhausted |
| POST   | `/password-reset/confirm`    | Form `{token, new_password}`. Forwards to backend's `/oauth/password-reset/confirm`; on success drops every bff session of the reset user (signing them out on all devices at once) and 303 → login's `login.html?status=password_reset` (not signed in), `reset-password.html?status=weak_password` (no token in the URL; the page kept it in `sessionStorage`), or `forgot-password.html?status=invalid_token` (also for a token that isn't 1–128 base64url characters, which never reaches backend); fixed destinations, no `next`; same `403`/`429`/`502` as above |
| POST   | `/verify-email/resend`       | Form `{next}`, same cookie. Asks backend for a new code; 303 → `next?status=sent&expires_in=<secs>`, `next?status=cooling_down&retry_after=<secs>` (nothing sent: inside the resend cooldown), `next?status=locked&retry_after=<secs>` (nothing sent: locked out after wrong guesses; also clears `wa_verify_session`), `next?status=locked_until_reset` (locked out five times; also clears it) or `next?status=session_expired` (also for an already verified account); same `400`/`403`/`429` as above |
| *      | *(configured `path_prefix`)* | Proxied to the matching route's `upstream_url` (prefix stripped), cookie swapped for `Authorization: Bearer`; `401` if no/unknown session or the refresh token is rejected, `502` if backend is unreachable or fails (5xx / bad body) during a token refresh, `404` if no route matches, `429` if the proxy bucket is exhausted                                                                                                                                                                                                                         |

login routes:

Any page opened without a `redirect_uri` falls back to `WA_DEFAULT_REDIRECT_URI` (`WA_EMAIL_LINK_DEFAULT_REDIRECT_URI` first on the pages it covers), then login's own origin (`reset-password.html` doesn't use one).

| Method | Path             | Returns                                                                                                                                                 |
|--------|------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| GET    | `/`              | Login shell (`login/src/index.html`, compiled into the binary) — loads `login.html` via HTMx                                                            |
| GET    | `/index.html`    | Same shell, for anyone linking there directly                                                                                                           |
| GET    | `/login.html`    | Login page, server-rendered from `templates/pages/login.html` — also renders the OIDC link-confirm prompt when `?email=...` is present: names the sign-in being linked (`provider`), a password form unless `has_password=false`, and a "Continue with" link per `linked_providers` key, carrying `confirm_link=true`. Names come from bff's `/oidc/providers` (fetched server-side via `WA_BFF_INTERNAL_URL`/`WA_BFF_URL`, only for this view, and cached for 5 minutes, 30 seconds after a failure), not the URL; keys it doesn't list are dropped. If that lookup fails, keys are shown as themselves, limited to `[A-Za-z0-9_-]`. With `has_password=false` and no `linked_providers` it says the sign-in can't be linked there instead. Links to `forgot-password.html` under the sign-in form and the link-confirm password form; `?status=password_reset` confirms a completed reset, removes the reset token from `sessionStorage` and, without a `redirect_uri`, falls back to `WA_EMAIL_LINK_DEFAULT_REDIRECT_URI` |
| GET    | `/register.html` | Registration page, server-rendered from `templates/pages/register.html`                                                                                 |
| GET    | `/verify-email.html` | Email verification page, server-rendered from `templates/pages/verify-email.html` — a form for the 9-digit code and one to request a new code; `?status=invalid\|code_used_up\|sent\|cooling_down\|locked\|locked_until_reset\|session_expired` shows the outcome, with `&retry_after=<secs>` (`cooling_down`, `locked`) or `&expires_in=<secs>` (`sent`); `?redirect_uri=` is where the user was headed |
| GET    | `/forgot-password.html` | Asks for an email and posts it to bff's `/password-reset/request`, from `templates/pages/forgot-password.html`; `?status=sent\|invalid_token` shows the outcome; `invalid_token` also removes a stored reset token from `sessionStorage`. Without a `redirect_uri` it falls back to `WA_EMAIL_LINK_DEFAULT_REDIRECT_URI` |
| GET    | `/reset-password.html` | Where the reset email links to, with the token in the `#token=` fragment; from `templates/pages/reset-password.html`. `reset-password.js` moves the token into the form and the tab's `sessionStorage` (so a reload or a rejected password keeps it) and out of the address bar, and only then shows the form (otherwise it points back to the email); served with `Referrer-Policy: strict-origin` (`no-referrer` would make the form's POST carry `Origin: null`, which bff refuses) and `Cache-Control: no-store`. Posts to bff's `/password-reset/confirm`; `?status=weak_password` shows that outcome |
| GET    | `/static/*`, `/*` | Static assets (`login/static/`) — stylesheet, vendored `htmx.min.js`, `countdown.js` (the verify page's cooldown countdown), `reset-password.js`. Served under `/static/` and, as the fallback, at the root (the pages load `/style.css`, `/countdown.js` and `/reset-password.js`) |

Backend routes:

| Method | Path                                | Returns                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
|--------|-------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| GET    | `/health`                           | `ok`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| POST   | `/oauth/login`                      | Verifies email/password (Argon2) against `UserStorage`; `{ login_session }` for a verified account, `401` otherwise. An unverified account also gets a `verification_session` (and its `verification_session_ttl_secs`): `{ login_session, verification_session }` when verification is optional, `{ verification_session }` only when `require_verified_email` is set (which also sends the code)                                                                                                                                                                                                                                                                                                    |
| POST   | `/register`                         | Hashes the password (Argon2) and saves a new user (`email_verified: false`), then sends the verification email if an `email_handler` is configured; `201`, `400` `WeakPassword` if the password is under 8 characters or over 1024 bytes, or `409` if the email is taken                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| GET    | `/oauth/authorize`                  | Consumes `login_session` (`401` if invalid/expired/reused), then 303 → `redirect_uri?code=...&state=...` if `redirect_uri` is allowlisted, else `400`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| POST   | `/oauth/token`                      | Verifies `code_verifier` against the stored (single-use, TTL'd) challenge; `{ access_token, refresh_token, token_type, expires_at }`, JWT carries `iss`/`email`/`email_verified`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| GET    | `/.well-known/jwks.json`            | `{ keys }`: the public key access tokens are signed with, plus, while present, the staged next key and the previous one (until its tokens have expired; see `WA_JWT_KEY_ROTATION_INTERVAL_SECS`). The next key is published before it signs, except right after a backend restart, when a fresh key signs at once and tokens signed before the restart no longer verify. Sends `Cache-Control: max-age`; cache no longer than that, and re-fetch when a token has an unknown `kid`, at most once per minute                                                                                                                                                                                           |
| GET    | `/.well-known/openid-configuration` | OpenID discovery document: `issuer` (`WA_BACKEND_URL`, which access tokens carry as `iss`), `jwks_uri`, the token endpoint and what it supports, for verifiers that configure themselves from an issuer URL. No `authorization_endpoint`: `/oauth/authorize` isn't a standard one, so generic OAuth/OIDC clients can't use this issuer                                                                                                                                                                                                                                                                                                                                                                     |
| GET    | `/oauth/oidc/login`                 | Not for the browser directly -- bff proxies this. Query: `provider`. Redirects to the provider's consent screen; `404` for an unknown `provider`; `400` if the query is missing or malformed                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| GET    | `/oauth/oidc/providers`             | The configured OIDC providers: `{providers: [{key, display_name}]}`, ordered by key; `display_name` is the provider's config `display_name`, default its key capitalized. bff relays it as `/oidc/providers`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| GET    | `/oauth/oidc/callback`              | Not for the provider directly -- bff forwards `provider`+`code`+`state` here server-to-server. Resolves the OIDC identity to a user (see `UserStorage::resolve_oidc_login`); `{status: "authenticated", login_session}` on success, or `{status: "link_confirmation_required", pending_link_token, email, has_password, linked_providers}` if an account with this email exists that the identity isn't linked to. With `pending_link_token` set, the sign-in instead confirms that pending link: it must be through an identity already linked to the pending link's account (`409` otherwise, or when the token is unknown or expired; nothing created); `400` if the query is missing or malformed |
| POST   | `/oauth/email-verification/request` | `{verification_session}` (what `/oauth/login` returned for an unverified account; `401` otherwise). Sends a fresh 9-digit code in the background: `202 {status: "sent", expires_in_secs}`. Nothing is sent inside the resend cooldown (`202 {status: "cooling_down", retry_after_secs}`), a lockout (`202 {status: "locked", retry_after_secs}`) or five lockouts (`202 {status: "locked_until_reset"}`). `401` too for an already verified account; `503` when no email handler is configured                                                                                                                                                                                                        |
| POST   | `/oauth/email-verification/confirm` | `{verification_session, code}`. Marks the email verified, ends the verification session and returns `200 { status: "verified", login_session }` (the one the login withheld); `400` if the code is wrong or expired, or with reason `CodeUsedUp` if 5 wrong attempts deleted it (the session stays usable); `423` `{ status: "locked", retry_after_secs }` or `{ status: "locked_until_reset" }` while locked out, even for the right code; `401` for an unknown/expired session                                                                                                                                                                                                                      |
| POST   | `/oauth/oidc/confirm-link`          | `{pending_link_token, password}`. Verifies the password against the account named in the pending link; on success marks it `email_verified` and links the identity, `{ login_session }`; `401` on wrong password, `400` if the token is invalid/expired                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| POST   | `/oauth/password-reset/request`     | `{email}`. Always `202`, whether or not the address matches an account or a mail went out (no enumeration). For a matching account, mails a single-use reset link to the account's own address through `email_handler`, at most once a minute; earlier links stay valid until one is redeemed, which spends them all. The token is never in the response or logged (see [docs/flows/password-reset.md](docs/flows/password-reset.md))                                                                                                                                                                                                                                                                                                                                                                                           |
| POST   | `/oauth/password-reset/confirm`     | `{token, new_password}`. Sets the new password, marks the email verified, and ends everything issued before: every login session, auth code, refresh token and email-verification session of the account is refused by its credential stamp (auth codes only refused; the rest also deleted); its email-verification code state (cooldown, failure count, lockout) is cleared, so someone who squatted the address keeps nothing across the reset. `200 {user_id}`; `400` `WeakPassword` if the password is under 8 characters or over 1024 bytes (the token stays usable); `400` if the token is unknown, expired or already used                                                                                                                                                                                                                                                                |

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
matches) is forwarded to `upstream_url` with that prefix stripped and
`Authorization: Bearer <access_token>` set from the session looked up via the request's
`wa_session` cookie. Next to it, bff forwards only `Content-Type` (`REQUEST_HEADERS` in
`bff/src/server/api/proxy.rs`): every other client header is dropped, `Cookie`, `Accept`,
`Upgrade` and any `X-Forwarded-*`/`Forwarded` included, and bff adds no forwarding headers of
its own (hyper still sets `Host` to the upstream's, and `Content-Length` or chunked framing for a
body). WebSocket isn't proxied: a handshake reaches the upstream as a plain `GET`. A header an
upstream needs gets added to `REQUEST_HEADERS`; adding `Upgrade` also means extending the
`Origin` check below to WebSocket handshakes.

The browser attaches the session cookie to any same-site request, and an upstream treats the
bearer token bff adds as CSRF-safe. So a proxied request that can change state, any method but
`GET`/`HEAD`/`OPTIONS`, must come from a `WA_TRUSTED_ORIGINS` origin or bff's own (`Origin`,
falling back to `Referer`), or gets `403`. bff answers no CORS yet (see `TODO.md`), so in
practice only a frontend served through bff itself can use the proxy; a cross-origin entry in
`WA_TRUSTED_ORIGINS` lets that origin send CORS-simple writes it can't read the answer to. The
check assumes an upstream changes nothing on `GET`/`HEAD`/`OPTIONS`: `SameSite=Lax` still sends
the cookie on a cross-site top-level `GET` navigation, so an upstream must not change state on
those methods, nor honour a `_method` query override on them.

Upstream responses keep only `Content-Type`, `Content-Disposition`, `Content-Security-Policy` and
`Cache-Control` (`RESPONSE_HEADERS`): the headers that only shape that one response, which an
upstream needs to keep its content (an uploaded file, say) from rendering or running on bff's
origin, or from being cached for another user. bff then always sets `X-Content-Type-Options:
nosniff`, and `Cache-Control: no-store` when the upstream sent none. A cache in front of bff sees
the cookie, not the `Authorization` the upstream answered, so a `Cache-Control` naming none of
`public`, `s-maxage`, a bare `private` or `no-store` gets `private` added: shared caches keep it
out, as RFC 9111 §3.5 would for an `Authorization` request. Stricter than the RFC,
`must-revalidate` doesn't count (upstreams send it on per-user data, and bff drops the `ETag`
a revalidation would use). A field-qualified `private="…"` doesn't either, since it only keeps
the named fields out. Everything else is dropped, so `Location`, `ETag` and the like don't reach
the browser, and a `HEAD` response loses the upstream's `Content-Length` (hyper frames it from
the empty body).

Proxied content shares bff's origin, and most other response headers would act on bff itself,
beyond the upstream's `path_prefix`: `Set-Cookie` and `Clear-Site-Data` would hit bff's own
cookie (`wa_session`), `Service-Worker-Allowed` would let a service worker see bff's own routes
(`/login`'s form POST, with the password, included), and `Strict-Transport-Security`/`Alt-Svc`
would change how the browser reaches bff's host. A route with `path_prefix: "/"` gets a
root-scoped service worker without any header: it trusts that upstream with everything bff
serves.

No session → `401`. If the access token has expired, bff refreshes it first: a rejected refresh
token → `401`; backend unreachable or failing during the refresh → `502`. No matching route →
`404`.

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
`kind: plugin` runs an executable the deployer mounts and calls it over gRPC. A plugin
is an ordinary binary, so it uses ordinary libraries and keeps its own connection pools
— and it is **not sandboxed**: each plugin runs as its own user (`uid`/`gid`, defaults
1001, 1002 and 1003), but mounting one is still equivalent to shipping application code.
See **[docs/plugins.md](docs/plugins.md)**.

```yaml
extra_data_handler:
  kind: plugin
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
POSTs `{user_id, email}` and expects a JSON object of claims back, `kind: plugin` calls the
plugin's one generic rpc with `hook: "login_claims"` and expects a `google.protobuf.Struct`
back (so claim values can nest, e.g. `roles: {"admin": ["user-1", "user-2"]}`). An error from
either kind fails the token request — no token is ever issued without the claims it's
configured to carry. A claim name the handler returns that collides with a reserved one
(`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`, `email`, `email_verified`) also fails the
request, so a plugin/webhook can't spoof identity or registered claims.

backend's `email_handler` delivers the verification email sent when a user registers (and
on login when verification is required and on a resend request). It contains a short-lived
9-digit code and the address of login's `/verify-email.html`, where the user types it in; the
login that triggered it handed out a restricted verification session for exactly that. The
same handler delivers password reset links (login's `/reset-password.html#token=...`).
Exactly one of three kinds; the link in the mail points at `login_public_url` (`WA_LOGIN_PUBLIC_URL`):

- `kind: smtp` renders the templates in `templates/emails/`
  (`verify-email.subject.txt`, `verify-email.txt`, `verify-email.html`, Tera syntax with
  `email`, `code`, `verify_page_url`, `expires_at`; `password-reset.subject.txt`,
  `password-reset.txt`, `password-reset.html` with `email`, `reset_url`, `expires_at`) and
  sends them through `host`/`port`.
  `tls` is `starttls` (default), `implicit` or `none` (`none` is refused for anything but a loopback host); `username`/`password` are optional
  (password better as `WA_EMAIL_SMTP_PASSWORD`). To use your own wording, replace those files
  in the image's `/app/templates/emails` (the login pages are in `/app/templates/pages`). Templates are read at startup, and a missing one stops backend
  from booting. Locally: `docker compose -f testing/mailpit/docker-compose.yml up -d`, then
  read the mail at http://localhost:7025.
- `kind: webhook` POSTs `{kind: "email_verification", user_id, email, code, verify_page_url, expires_at}`
  or `{kind: "password_reset", user_id, email, reset_url, expires_at}` (`expires_at` is RFC 3339, UTC) to a URL (https
  unless loopback) so a downstream service can send the email itself.
- `kind: plugin` calls a plugin with `hook: "email_verification"` or `hook: "password_reset"`
  (see [docs/plugins.md](docs/plugins.md); `WA_PLUGIN_EMAIL_ENV_<NAME>`, default user `wa-email` 1003).

The mail is sent in the background and a failed delivery is only logged, so it never delays
or fails the registration; the user can request a new code (at most one per minute). `require_verified_email: true`
(`WA_REQUIRE_VERIFIED_EMAIL`) makes `/oauth/login` withhold the login session from accounts
whose email isn't verified: they get only the verification session until they enter the code. See [docs/flows/verify-email.md](docs/flows/verify-email.md).

```yaml
login_public_url: https://login.example.com
email_handler:
  kind: smtp
  host: smtp.example.com
  port: 587
  username: apikey
  from: WeaveAuth <no-reply@example.com>
```

```yaml
login_claims_handler:
  kind: plugin
  command: /plugins/login-claims
  env:
    LOG_LEVEL: info
```

Credentials for it are passed the same way, as `WA_PLUGIN_LOGIN_CLAIMS_ENV_<NAME>`.

An OIDC provider entry can set `display_name`, how login pages name it ("Continue with
LinkedIn"). Unset, it's the entry's key with its first letter capitalized (`linkedin` →
"Linkedin"), so only set it when that reads wrong. Backend serves the list at
`/oauth/oidc/providers`, bff relays it as `/oidc/providers` (for external login pages too),
and login fetches it from there to name providers on its link-confirm prompt.

An OIDC provider entry can also set `scopes: [...]`, what its consent screen asks for besides
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
    # redirect_uri defaults to {WA_BFF_URL}/oidc/google/callback; set it only if
    # the provider's registered callback differs
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

Only the variables below are read, and a YAML key can set anything they can. The short lifetimes (auth codes, login sessions, verification codes, reset tokens) are fixed in code. A `.env` file in the working directory or any parent directory is loaded first. A missing one is fine; a malformed one stops backend and bff from starting. An invalid `WA_LOGIN_PORT` (or other invalid login setting) likewise stops login.

| Variable                                                 | App                 | Default                                                     | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
|----------------------------------------------------------|---------------------|-------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `WA_CONFIG_FILE`                                         | backend, bff        | `config.yaml` (relative to cwd)                             | Path to the optional YAML config overlay                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `WA_PROFILE`                                             | backend, bff, login | `prod`                                                      | `dev` or `prod`; anything else stops the service from starting. Under `prod`, all three refuse to start unless `WA_BFF_URL` and `WA_LOGIN_PUBLIC_URL` (and login's `WA_DEFAULT_REDIRECT_URI` and `WA_EMAIL_LINK_DEFAULT_REDIRECT_URI`, when set) are https URLs (an http one turns the `Secure` cookie flag off and puts http links in emails), `WA_LOGIN_PUBLIC_URL` being a bare origin (no path, query or fragment: it's compared with browsers' `Origin` header); backend also needs `WA_BACKEND_URL` set (http is fine there: it's internal). The profile picks the defaults of `WA_DOCS_ENABLED`, `WA_RATE_LIMIT_MAX_ATTEMPTS` and `WA_REQUIRE_VERIFIED_EMAIL`: `dev` turns the docs on, loosens the rate limit and doesn't require verified email; `prod` is the strict one. A value set explicitly always wins                                                                                                                                                      |
| `WA_PORT`                                                | backend             | `1983`                                                      | Backend listen port                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `WA_LOGIN_PORT`                                          | login               | `8081`                                                      | Login page listen port                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `WA_BFF_PORT`                                            | bff                 | `8080`                                                      | bff listen port                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `WA_BACKEND_URL`                                         | backend, bff        | `http://localhost:1983`                                     | Backend's address as bff reaches it, and, for backend, its `issuer`: the `iss` claim on access tokens and the base URL of `/.well-known/openid-configuration`, so it must be an address verifiers can reach (an internal URL; backend is never public). An http(s) URL without user info, path, query or fragment (backend serves discovery and its endpoints at its own root). Backend stores it normalized (scheme and host lowercased, default port and trailing `/` dropped), and that normalized form is what `iss` carries. Backend, when unset under `dev`: `http://localhost:{WA_PORT}` (`prod` refuses to start without it)                                                                                                                                                                                                                                                                                                      |
| `WA_BFF_URL`                                             | bff, login, backend | `http://localhost:8080`                                     | Public base URL of the bff. login links and redirects the browser to it, and also calls its `/oidc/providers` server-side unless `WA_BFF_INTERNAL_URL` is set. backend builds each OIDC provider's default `redirect_uri` from it: `{WA_BFF_URL}/oidc/<provider>/callback`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `WA_BFF_INTERNAL_URL`                                    | login               | `WA_BFF_URL`                                                | Where login itself reaches bff server-side (its `/oidc/providers`), for when the public `WA_BFF_URL` doesn't resolve from login's network (e.g. `localhost` in a separate container). Empty counts as unset. `weaveauth-launcher` sets it to `http://127.0.0.1:{WA_BFF_PORT}` (the bff beside login) unless it's set.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `WA_LOGIN_PUBLIC_URL`                                    | login, bff, backend | `http://localhost:8081`                                     | Login page's own public origin; a trailing `/` is dropped. login uses it as the last `redirect_uri` fallback (after `WA_DEFAULT_REDIRECT_URI`) and to build `own_url`/`next` — pinned in config rather than trusted from `Host`/`X-Forwarded-Proto`. backend also puts it in the verification email (the page where the code is entered). bff defaults `WA_TRUSTED_ORIGINS` from it, and backend defaults `WA_REDIRECT_URI_ALLOWLIST` from it (with a trailing `/` appended) — both only when that var isn't set explicitly (a `login_public_url` in `config.yaml` counts too). When all three run in the same container (`weaveauth-launcher`), the launcher points login's `WA_BFF_INTERNAL_URL` at the bff beside it (`http://127.0.0.1:{WA_BFF_PORT}`) unless that's set; under `prod` the container still needs `WA_BFF_URL` and `WA_BACKEND_URL` too (see `WA_PROFILE`). Not bff's or backend's own URL. |
| `WA_REDIRECT_URI_ALLOWLIST`                              | backend             | `{WA_LOGIN_PUBLIC_URL}/`, else `http://localhost:8081/`     | Comma-separated allowlist of valid `redirect_uri` values — checked once, at `/oauth/authorize`, for whatever bff forwards from `/login`. Exact string match, hence the trailing slash — matches login's own default `redirect_uri` while `WA_DEFAULT_REDIRECT_URI` and `WA_EMAIL_LINK_DEFAULT_REDIRECT_URI` are unset. The derived default doesn't include them; set this explicitly when using them: sign-in from the pages that fall back to them ends in a `400` from `/oauth/authorize` otherwise, and nothing complains at startup                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `WA_DEFAULT_REDIRECT_URI`                                | login               | `{WA_LOGIN_PUBLIC_URL}/`, else `http://localhost:8081/`     | Where the user goes after a login page opened without a `redirect_uri` (a bare visit to `login.html` or `register.html`, say), and the fallback for the pages `WA_EMAIL_LINK_DEFAULT_REDIRECT_URI` covers. Must be on `WA_REDIRECT_URI_ALLOWLIST`. Empty counts as unset; a value that isn't an absolute http(s) URL (https under `prod`) stops login from starting.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `WA_EMAIL_LINK_DEFAULT_REDIRECT_URI`                     | login               | `WA_DEFAULT_REDIRECT_URI`                                   | Overrides `WA_DEFAULT_REDIRECT_URI` for the pages reached from an email link, which carry no `redirect_uri`: the verification page after the correct code, the login page after a password reset (`login.html?status=password_reset`), and `forgot-password.html`. Must be on `WA_REDIRECT_URI_ALLOWLIST`. Empty counts as unset; a value that isn't an absolute http(s) URL (https under `prod`) stops login from starting.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `WA_TRUSTED_ORIGINS`                                     | bff                 | `WA_LOGIN_PUBLIC_URL`, else `http://localhost:8081`         | Comma-separated origins allowed to POST to every bff form route (`/login`, `/register`, `/oidc/confirm-link`, `/verify-email*`, `/password-reset/*`), and (with bff's own origin) to send state-changing proxied requests: any method but `GET`/`HEAD`/`OPTIONS` (checked against `Origin`, falling back to `Referer`) — anything else gets `403`, which is what stops a hostile site from auto-submitting a login/register form ("login CSRF") or riding the session cookie into an upstream (CSRF). List every frontend origin that calls the proxy. One list grants both rights: an origin added for the proxy can also POST the form routes, and the login page's origin can also write through the proxy                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `WA_SESSION_COOKIE_NAME`                                 | bff                 | `wa_session`                                                | Name of the HttpOnly session cookie set after login                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `WA_ACCESS_TOKEN_TTL_SECS`                               | backend             | `900`                                                       | How long an access token stays valid. 1 to 315360000 (10 years), and at most `WA_JWT_KEY_ROTATION_INTERVAL_SECS` minus 90000 (25 hours; see that row) when that is set                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `WA_REFRESH_TOKEN_TTL_SECS`                              | backend             | `2592000` (30 days)                                         | How long a refresh token stays redeemable. 1 to 315360000 (10 years)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `WA_JWT_KEY_ROTATION_INTERVAL_SECS`                      | backend             | 30 days, or longer if `WA_ACCESS_TOKEN_TTL_SECS` needs it   | How long a JWT signing key stays active before the next one takes over. The next key is published 24 hours before it signs, and the replaced key stays in `/.well-known/jwks.json` for `WA_ACCESS_TOKEN_TTL_SECS` plus 1 hour (margin for verifier `exp` leeway and clock skew). Those 25 hours plus `WA_ACCESS_TOKEN_TTL_SECS` must fit inside this value, or backend refuses to start; that keeps at most two keys published. Left unset, it is the longer of 30 days and that sum, so a long access token TTL never fails this check. 1 to 315360000. Keys are in memory, so a restart starts a fresh key and rotation clock, and access tokens signed before it stop verifying                                                                                                                                                                                                                                                        |
| `WA_RATE_LIMIT_MAX_ATTEMPTS`                             | bff                 | `100` for `dev`, else `10`                                  | Burst size, replenished over a 60 second window, of bff's auth (`/login`, `/register`, `/oidc/*`, `/verify-email*`, `/password-reset/*`, all sharing one) and docs per-client rate-limit buckets (`tower_governor`; see the bff routes above). The proxied routes' bucket has its own size, `rate_limit_proxy_max_attempts`. `0` stops bff from starting; above `60000` a bucket refills like `60000` (one attempt per millisecond at most) |
| `WA_TRUSTED_PROXIES`                                     | bff                 | *(unset)*                                                   | Comma-separated addresses or CIDR ranges (a `trusted_proxies:` list in `config.yaml` works too) of the reverse proxies in front of bff (e.g. `10.0.0.0/8, 172.30.0.2`), as bff sees them connect, not their public addresses. A request from one of them is rate-limited on the client address in its `X-Forwarded-For` (the rightmost entry that isn't itself a trusted proxy, or the leftmost if every entry is one; an `ip:port` entry counts as its address). Only `X-Forwarded-For` is read, not RFC 7239 `Forwarded`. An entry that is no address at all stops the walk, and the proxy's own address is used, logged once. From anyone else the header is ignored and the peer address counts. Unset behind a proxy, every client shares the proxy's budget. Under `prod`, an entry wider than IPv4 `/8` or IPv6 `/32` stops bff from starting (a guard against typos like `0.0.0.0/1`, not a check that the range is private): clients in such a range could claim any address and dodge the limit |
| `WA_DOCS_ENABLED`                                        | bff                 | `true` for `dev`, else `false`                              | Serve the OpenAPI schema (`/openapi.json`) and Scalar UI (`/docs`). Off for `prod` — bff is internet-facing and these are unauthenticated descriptions of the auth surface, so a deployment opts in                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `WA_OIDC_<KEY>_CLIENT_ID`, `WA_OIDC_<KEY>_CLIENT_SECRET` | backend             | *(unset)*                                                   | Override the `client_id`/`client_secret` of the `oidc_providers` entry named `<key>` (upper-cased), so the secret can stay out of `config.yaml`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `WA_EMAIL_SMTP_PASSWORD`                                 | backend             | *(unset)*                                                   | Password for an `email_handler` of `kind: smtp`; wins over `password` in `config.yaml`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `WA_REQUIRE_VERIFIED_EMAIL`                              | backend             | `true` for `prod` when `email_handler` is set, else `false` | Withhold the login session from accounts whose email isn't verified; they get a restricted verification session and the code-entry page                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `WA_SETUID_HELPER`                                       | backend             | *(unset; the image sets it)*                                | `weaveauth-plugin-exec`, the binary plugins are started through. It alone holds `CAP_SETUID`/`CAP_SETGID` and switches to each plugin's `uid`/`gid`, refusing 0. Unset, backend switches users itself, which needs `CAP_SETUID`/`CAP_SETGID` (or root), unless `uid`/`gid` are its own (local runs)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `WA_PLUGIN_<PLUGIN>_ENV_<NAME>`                          | backend             | *(unset)*                                                   | `<PLUGIN>` is `REGISTRATION`, `LOGIN_CLAIMS` or `EMAIL`. Forwarded to that plugin as `<NAME>`, prefix stripped — how a plugin gets its own credentials (`WA_PLUGIN_REGISTRATION_ENV_DATABASE_URL` reaches the registration plugin as `DATABASE_URL`) without them sitting in `config.yaml`. `<PLUGIN>` scopes them, so a later surface doesn't inherit this one's secrets; the extra-data plugin is `REGISTRATION`, the login-claims plugin is `LOGIN_CLAIMS`. The plugin inherits nothing else                                                                                                                                                                                                                                                                                                                                                                                                                                           |

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
- `bff`: unit tests inline (`config.rs`, `storage/in_memory.rs`, `cookie.rs`,
  `rate_limit.rs`, `server/mod.rs`'s expiry sweep and `proxy.rs`'s `refresh_session`) plus `bff/tests/pkce_flow.rs` (the full
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
runtime (no shell) copies them plus `/app/login/static`, `/app/templates` (`pages/` for the login pages, `emails/` for the emails) and an empty `/app/backend` (backend finds its templates at `/app/backend/../templates`), and
runs `weaveauth-launcher`, which starts all three and exits when any one of them does.
Everything runs as `weaveauth` (1000) with no capabilities. The exception is
`weaveauth-plugin-exec` (`WA_SETUID_HELPER`), which has `CAP_SETUID`/`CAP_SETGID` as file
capabilities, so plugins can run as their own users (`wa-registration` 1001,
`wa-login-claims` 1002, `wa-email` 1003). A deployment without plugins needs no capabilities. With
plugins, `capabilities.drop: [ALL]` (the Kubernetes restricted Pod Security Standard),
`--cap-drop SETUID`/`SETGID` or `no-new-privileges` stop them from starting, and backend
then refuses to boot; see [docs/plugins.md](docs/plugins.md#deploying). The launcher
doesn't forward `SIGTERM`, so use `docker run --init` for a prompt `docker stop`.

The image runs the `prod` profile, which won't start on localhost defaults: give it
`WA_BFF_URL` and `WA_LOGIN_PUBLIC_URL` (https) and `WA_BACKEND_URL`. To try it locally,
use `dev` instead. Backend's port isn't published: bff and login reach it inside the container,
and backend must never be exposed. Backend listens on every interface, so in Kubernetes give the
pod a NetworkPolicy, on a network plugin that enforces it (pods can otherwise reach each other on
any port): allow 8080/8081 from the ingress controller only, and 1983 only from the services you
trust to call backend directly, such as ones fetching `/.well-known/jwks.json` to verify access
tokens. Set `WA_BACKEND_URL` to the in-cluster Service address, so it works as the issuer those
services discover from. Set `WA_TRUSTED_PROXIES` to the ingress controller's pod addresses (or
their range), or every client shares one rate-limit bucket. A range is only safe while that
NetworkPolicy lets nothing but the ingress reach 8080: any pod in it could otherwise send its own
`X-Forwarded-For` and pick its own rate-limit key.

```bash
docker build -t weaveauth .
docker run -p 127.0.0.1:8080:8080 -p 127.0.0.1:8081:8081 -e WA_PROFILE=dev weaveauth
```

To run it the way production should, under `prod` behind a TLS proxy on a private network,
see [local-prod/](local-prod/README.md).

## License

Apache License 2.0. Copyright 2026 Silvio Sabo.
