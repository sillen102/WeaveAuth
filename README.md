# WeaveAuth

Sign-in for a web app with a real Backend-for-Frontend (BFF): password, Google (or any OIDC
provider) and passkeys, recovery and email verification, on top of **Ory Kratos** (identities) and
**Ory Hydra** (OIDC and JWT access tokens). The browser ends up with one HttpOnly session cookie on
the BFF's origin; the tokens stay on the server, which proxies API calls with a Bearer JWT.

WeaveAuth is the part around Ory: a Cargo workspace with three Rust services (`bff`, `login`,
`hooks`) and the Ory configuration (`ory/`). Kratos and Hydra run as their own containers from the
official images.

## Architecture

```
                         ┌──────────────── login host (Caddy / ingress) ───────────────┐
 browser ───────────────►│  /                          → login  :8081                  │
                         │  /self-service/*, /.well-known/ory/*                        │
                         │                             → login :8081 → Kratos public   │
                         │  /oauth2/auth, /oauth2/sessions/logout → Hydra public :4444 │
                         └──────────────────────────────────────────────────────────────┘
 browser ───────────────► bff host: everything          → bff    :8080 (public listener)

 internal only:  bff :8082 (/backchannel-logout, /internal/revoke)   hooks :1983
                 Kratos admin :4434   Hydra admin :4445   Hydra token/JWKS :4444   Postgres
```

- **`weaveauth-bff`** (Axum) — public `:8080`, internal `:8082`. The OAuth/OIDC client of Hydra: it
  starts the login (PKCE, `state`, `nonce`), redeems the code, verifies the id_token, keeps the
  tokens in its session store and gives the browser only `wa_session`. It also reverse-proxies the
  routes in its `config.yaml` with `Authorization: Bearer <access token>` (refreshing the token
  when due), runs logout, and receives Hydra's back-channel logout and hooks' revocations on its
  internal listener. **The redirect allowlist lives here.**
- **`weaveauth-login`** (Axum + Tera) — `:8081`. The server-rendered UI for Kratos' flows (login,
  registration, recovery, verification, settings, error) and for Hydra's login, consent and logout
  challenges. It is the **only** way anything public reaches Kratos (`/self-service/*`,
  `/.well-known/ory/*`): it applies per-client rate limits and a per-identifier throttle on password
  submissions. Pages are templates in `templates/pages/`, and provider logo images in `templates/providers/`, that a deployer can replace; per
  `login/AGENTS.md` they are plain HTML and CSS, scripts come only from the compiled-in layout and
  from Kratos' own script nodes. Templates call `form`, `messages`, `continuing` (a social sign-up
  missing traits) and `recovering` (settings right after a recovery); see `login/AGENTS.md`.
- **`weaveauth-hooks`** (Axum) — `:1983`, **internal only**. The web hooks Kratos and Hydra call:
  the claims for every token, the registration handoff (with provider profile APIs), and the purge
  after a recovery or password change. Every route but `/health` needs
  `Authorization: Bearer <WA_HOOKS_API_KEY>`.
- **Kratos and Hydra** — configured under `ory/` (see [ory/README.md](ory/README.md)); Postgres
  behind both. Local-prod runs them with the services behind TLS ([local-prod/](local-prod/README.md)).
- **`weaveauth-launcher`** — the container entrypoint: runs hooks, bff and login together.

Never expose hooks, bff's internal listener, or the Kratos and Hydra admin APIs. Hydra's only
public endpoints are `/oauth2/auth` and `/oauth2/sessions/logout`; its token endpoint and JWKS are
reached on the internal URL.

### Flows

Each flow has a sequence diagram and the details in [docs/flows/](docs/flows/):

| Flow | Doc |
|---|---|
| Login: password, Google/OIDC (and linking), passkey | [login.md](docs/flows/login.md) |
| Registration and email verification (both verified-first modes) | [registration.md](docs/flows/registration.md) |
| Recovery | [recovery.md](docs/flows/recovery.md) |
| Logout and back-channel logout | [logout.md](docs/flows/logout.md) |
| Token claims, refresh and the proxy | [tokens.md](docs/flows/tokens.md) |

In short, a login is: the app sends the browser to bff's `GET /login?redirect_uri=...` → Hydra →
`login`'s pages → Kratos checks the credential → Hydra → bff's `/callback`, which redeems the code and
answers one `303` to `redirect_uri` with `Set-Cookie: wa_session`. No token is ever in a URL or
readable by the browser.

### Third-party login (OIDC) and account linking

A provider (Google today) is a Kratos OIDC provider; its client id and secret live in Kratos'
config. Kratos' Jsonnet mapper copies the id_token's claims into identity traits and marks the
address verified **only** when the id_token says `email_verified: true`.

A provider's verified email proves mailbox access, not that its user owns the account with that
email (an attacker may have pre-registered it with a password). So an email match never links an
identity on its own (`account_linking_mode: confirm_with_existing_credential`): the user first
signs in with the existing account's own credential, then the provider is linked. Imported accounts
are never set to auto-link either.

## Routes

bff, public listener (`WA_BFF_PORT`, default `8080`). The first four routes share one per-client
rate-limit bucket (`tower_governor`; `WA_RATE_LIMIT_MAX_ATTEMPTS`), the proxy has its own
(`rate_limit_proxy_max_attempts`, YAML only: 600 a minute in `prod`, 6000 in `dev`; `0` stops bff
from starting). A client is its IPv4 address or IPv6 /64. Behind a reverse proxy set
`WA_TRUSTED_PROXIES`, or every client shares the proxy's bucket. The `prod` default (10 a minute
per client) is shared by everyone behind one NAT, and a login plus a logout costs 4 tokens: size
`WA_RATE_LIMIT_MAX_ATTEMPTS` for the busiest address next to `WA_TRUSTED_PROXIES`. `/health` is exempt:

| Method | Path | Returns |
|--------|------|---------|
| GET | `/login?redirect_uri=` | Starts a login. `redirect_uri` (absent or empty: `WA_DEFAULT_REDIRECT_URI`) must be an exact entry of `WA_REDIRECT_URI_ALLOWLIST` (`400` otherwise, or when neither is given). Keeps the PKCE verifier, `state`, `nonce` and the `redirect_uri` in the `wa_login` cookie (10 minutes; `__Host-wa_login` under https) and `303`s to Hydra's `/oauth2/auth` |
| GET | `/callback` | Where Hydra sends the browser back. Checks `state` against the `wa_login` cookie, redeems `code` (PKCE, `client_secret_basic`, Hydra's internal URL), verifies the id_token, stores the session, ends the session the browser already had (dropped, its refresh token revoked), `303` → the `redirect_uri` with `wa_session` set (`HttpOnly`, `SameSite=Lax`, `Max-Age` = the session's lifetime, fixed at login, see [tokens.md](docs/flows/tokens.md); `__Host-wa_session` under https). A user holds at most 20 sessions: a login beyond that ends the oldest, its refresh token revoked. A login cookie or session cookie sent twice counts as absent. `400` for no login in progress, a state mismatch, an `error` from Hydra, a missing code, a redirect no longer on the allowlist or a rejected code; `502` if Hydra is unreachable or its response is invalid |
| POST | `/logout[?redirect_uri=]` | Needs a trusted `Origin` (`403`). Drops the session, revokes its refresh token, clears `wa_session` and `303`s to Hydra's logout with the id_token as hint. `redirect_uri` is optional and rides along as `state` when it is on the allowlist; any other is dropped, since a logout must not fail on it (`/logged-out` then falls back to `WA_DEFAULT_REDIRECT_URI`) |
| GET | `/logged-out?state=` | Where Hydra sends the browser after the logout: `303` → `state` when it is on the allowlist, else `WA_DEFAULT_REDIRECT_URI`, else `400` |
| GET | `/health` | `ok` |
| * | *(configured `path_prefix`)* | Proxied to the matching route's `upstream_url` (prefix stripped), cookie swapped for `Authorization: Bearer`; `401` if no/unknown session or the refresh token is rejected, `502` if Hydra is unreachable or fails during a refresh, `404` if no route matches or the path has a segment of only dots, raw or encoded once or twice (a `;` path parameter is ignored when comparing, so `..;` counts) or an encoded `/` or `\`, `403` for a state-changing method from an untrusted `Origin`, `429` if the proxy bucket is exhausted. Every `OPTIONS` is answered by bff itself, before the session check and the rate limit, and never proxied. Only a trusted `Origin` gets `Access-Control-Allow-Origin` |

bff, internal listener (`WA_BFF_INTERNAL_PORT`, default `8082`; never route it publicly, no rate limit):

| Method | Path | Returns |
|--------|------|---------|
| POST | `/backchannel-logout` | Form `{logout_token}` from Hydra. Verifies the token (Hydra's JWKS, `iss`, `aud`, `iat`, `events`, no `nonce`), refuses a replayed `jti`, ends the sessions it names (by `sid`, `sub`, or both) and revokes their refresh tokens. `200`; `400` for an invalid or replayed token; `503` if Hydra's keys can't be fetched |
| POST | `/internal/revoke` | `{sub}`, `Authorization: Bearer <WA_BFF_INTERNAL_API_KEY>`. Ends every session of that user. `204`; `401` without the key |

login (`WA_LOGIN_PORT`, default `8081`). Every page route has the general rate-limit bucket:

| Method | Path | Returns |
|--------|------|---------|
| GET | `/login`, `/registration` | With `?flow=ID`, the Kratos flow rendered server-side. With a Hydra `login_challenge`, `303` → Kratos' browser flow with it. With neither, `303` → bff's `/login?redirect_uri=` (the query's, else `WA_DEFAULT_REDIRECT_URI`); with neither of those, `400` |
| GET | `/recovery`, `/verification`, `/settings` | The same, starting their own flows (no challenge needed) |
| GET | `/error?id=` | Kratos' error, rendered. Hydra's `error`/`error_description` text is never shown |
| GET | `/logout?logout_challenge=` | Ends the Kratos session and accepts Hydra's logout, only for a logout the application started (`400` page otherwise) |
| GET | `/consent?consent_challenge=` | Accepts for `WA_BFF_CLIENT_ID` and scopes within `openid offline_access`, granting the requested audience; rejects anything else. No screen |
| GET, POST | `/self-service/*` | Forwarded to Kratos' public API (cookies passed both ways; `GET` and `POST` only, paths with `..`, `%` or `//` refused, native `/api` flows `404`, `POST /self-service/login` in another case or with a trailing `/` `404`). `POST` has a smaller per-client bucket; `POST /self-service/login` with a password is also throttled per identifier (5 free attempts, then one per 30 s, then one per 5 min; a delay, not a lockout) |
| GET | `/.well-known/ory/*` | Forwarded to Kratos' public API |
| GET | `/health` | `ok`; touches nothing upstream |
| GET | `/ui.js`, `/static/*` | The compiled-in script that binds Kratos' passkey triggers; the stylesheet |
| GET | `/providers/*` | Provider logos from `templates/providers/` (a deployer can replace them), cacheable for a day |

hooks (`WA_HOOKS_PORT`, default `1983`; internal only). Everything but `/health` needs
`Authorization: Bearer <WA_HOOKS_API_KEY>` (`401`) and has a request timeout:

| Method | Path | Called by | Returns |
|--------|------|-----------|---------|
| GET | `/health` | infra | `ok` |
| POST | `/hydra/token-hook` | Hydra, on every token grant (code and refresh) | `{session: {access_token, id_token}}` claims: `email`, `email_verified` from Kratos plus what `login_claims_handler` returns. `403` for an unknown or inactive identity, an identity without an email, an unverified email (`require_verified_email`), or a webhook that returns a reserved claim name; `502` if Kratos or the webhook fails: no token is issued |
| POST | `/kratos/after-registration` | Kratos, after an identity is created | Hands `{user_id, email, email_verified, fields}` to `registration_handler` (after the provider's `profile_apis` for a social sign-up). On failure a `4xx`/`502` and the identity is deleted |
| POST | `/kratos/after-recovery` | Kratos, once a recovery code is accepted | Replaces the password with a random one, deletes the passkey/webauthn/totp/lookup credentials and every linked social login, revokes Kratos, Hydra and bff sessions. `502` if a step failed (Kratos retries) |
| POST | `/kratos/after-password-change` | Kratos, after the settings flow changes a password | The same revocations except the current Kratos session, without the purge |

## Prerequisites

- Rust (stable) — `cargo` on PATH; [mise](https://mise.jdx.dev) for the tasks below.
- Docker, for the Ory stack, the Docker image and `mise run test-docker`.

## Development

From the repo root:

```bash
mise run all         # Ory + Postgres in Docker (dev/), hooks + bff + login + test apps on the host
mise run services    # hooks + bff + login on the host only (Ory not started)
mise run dev-ory-up  # just the Docker part of `all`; dev-ory-down stops it and drops its data
mise run ory-up      # the whole stack in containers, behind TLS (local-prod/)
mise run ory-down    # stop it and drop its data (docker compose down -v)
mise run rotate-keys # rotate Hydra's token signing keys in that stack
mise run test        # cargo test --workspace
mise run test-docker # the system tests: real Kratos, Hydra and Postgres (testcontainers)
```

- **`all`** starts Postgres, Kratos, Hydra and Mailpit from `dev/docker-compose.yml` (configs
  rendered from `ory/` by `dev/render.sh`, plain http on `localhost`, fixed dev-only secrets, the
  breached-password check off, and the demo user-service's `first_name`, `last_name` and
  `phone_number` allowed as top-level token claims; local-prod keeps them under `ext`) and runs the
  services on the host: login `http://localhost:8081`, bff `:8080`, Hydra `:4444`, mail UI
  `http://localhost:8025`. Kratos and Hydra reach hooks and bff through `host.docker.internal`.
  Ctrl-C stops the host services; `mise run dev-ory-down` stops the containers.
- **Google sign-in in `all`**: Docker Compose reads `dev/.env` (next to `dev/docker-compose.yml`,
  git-ignored) and passes `KRATOS_CONFIG_EXTRA`, `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` to
  Kratos. Set `KRATOS_CONFIG_EXTRA=/etc/kratos/oidc-google.yml` (or `oidc-google-phone.yml`, see
  *profile_apis* under
  [hooks: the deployer's webhooks](#hooks-the-deployers-webhooks))
  and both Google values, run `mise run dev-ory-down` if Kratos is already up, and register
  `http://localhost:8081/self-service/methods/oidc/callback/google` at Google.
- **`ory-up`** is the production-like alternative, behind TLS. It starts Postgres, Kratos, Hydra, a
  Mailpit mail sink and the shipped image (hooks, bff, login) behind a Caddy TLS proxy at
  `https://login.localhost:8443` and `https://bff.localhost:8443`. Run `local-prod/gen-certs.sh`
  and `local-prod/gen-secrets.sh` once first, and trust `local-prod/certs/ca.crt`; see
  [local-prod/README.md](local-prod/README.md). Verification and recovery codes arrive in Mailpit at
  http://127.0.0.1:8025.
- **`services`** runs the three services on the host with each crate's `dev` task (`cargo run`),
  with dev credentials and the `dev` profile. It does **not** start Ory: Kratos and Hydra must be
  reachable at the defaults (`localhost:4433`/`4434` for Kratos, `4444`/`4445` for Hydra), and the
  URLs in `ory/` are `local-prod`'s, so a host-based setup needs its own Kratos and Hydra config.
  `ory-up` does not publish those ports to the host.
- Each service also runs on its own, one per terminal: `cd hooks && mise run dev` (likewise `bff`,
  `login`). Run from inside the crate: `hooks` and `bff` look for `config.yaml` as a bare relative
  path, so `cargo run -p <crate>` from the repo root doesn't find it and the default `prod` profile refuses to start. Set
  `WA_CONFIG_FILE` to an absolute path if you need to run that way.
- **Test doubles** (`testing/`, outside the workspace): `mise run test-apps` starts
  `downstream-service` (`$PORT`, default `10001`: any path, 401 without `Authorization`, otherwise a
  page showing the bearer token it received) and `user-service` (`$PORT`, default `10002`, 401
  without `Authorization`: the webhook target of hooks, `POST /users` stores a new account's
  `fields` (kept in `users.json`) and `POST /users/claims` answers them as token claims, `404` for
  an unknown user so the login fails; no bff route points at it).
  bff's `config.yaml` proxies `/downstream` to the first.

## Configuration

`hooks` and `bff` read an optional YAML file first (bare `config.yaml`, relative to the process's
working directory — override the path with `WA_CONFIG_FILE`; a missing file is not an error,
defaults apply, but one that exists and can't be read stops the service from starting), then let
the `WA_*` env vars below override individual scalar fields. `login` is env-only. Only the variables
below are read, and a YAML key can set anything they can. A `.env` file in the working directory or
any parent directory is loaded first by `hooks` and `bff`; a malformed one stops them.

| Variable | App | Default | Description |
|---|---|---|---|
| `WA_CONFIG_FILE` | hooks, bff | `config.yaml` (relative to cwd) | Path to the optional YAML config |
| `WA_PROFILE` | hooks, bff, login | `prod` | `dev` or `prod`; anything else stops the service. `prod` refuses to start unless the browser-facing URLs are https (bff: `WA_BFF_URL`, `WA_HYDRA_PUBLIC_URL`; login: `WA_BFF_URL`, `WA_LOGIN_PUBLIC_URL`, a bare origin, and `WA_DEFAULT_REDIRECT_URI` when set; an http one turns the `Secure` cookie flag off) and the addresses with a localhost default are set (bff: `WA_HYDRA_PUBLIC_URL`, `WA_HYDRA_INTERNAL_URL`; hooks: `WA_KRATOS_ADMIN_URL`, `WA_HYDRA_ADMIN_URL`, `WA_BFF_INTERNAL_URL`; login: `WA_KRATOS_PUBLIC_URL`, `WA_HYDRA_ADMIN_URL`). The profile also picks the defaults of `WA_RATE_LIMIT_MAX_ATTEMPTS` and `rate_limit_proxy_max_attempts`. A value set explicitly always wins |
| `WA_HOOKS_PORT` | hooks | `1983` | hooks listen port |
| `WA_HOOKS_API_KEY` | hooks | *(required to serve)* | The key Kratos and Hydra present on every hook call (`Authorization: Bearer`). Empty refuses to serve; `prod` needs 16 or more characters. Ory's configs carry it as `@WA_HOOKS_API_KEY@`, substituted at start, so use hex or base64url |
| `WA_KRATOS_ADMIN_URL` | hooks | `http://localhost:4434` | Kratos' admin API (identities, sessions, credentials) |
| `WA_REQUIRE_VERIFIED_EMAIL` | hooks | `true` | `false` lets the token hook serve an unverified address; set it with `KRATOS_SESSION_ON_REGISTRATION=1` |
| `WA_HYDRA_ADMIN_URL` | hooks, login | `http://localhost:4445` | Hydra's admin API: hooks revokes consent and login sessions; login accepts consent and logout challenges. Never browser-facing |
| `WA_BFF_INTERNAL_URL` | hooks | `http://localhost:8082` | bff's internal listener, where hooks calls `/internal/revoke` |
| `WA_BFF_INTERNAL_API_KEY` | hooks, bff | *(required)* | Presented by hooks to, and checked (constant time) by, bff's `/internal/revoke`. Required under every profile; at least 16 characters under `prod`, which also refuses the one committed in `bff/config.yaml` |
| `WA_BFF_PORT` | bff | `8080` | bff public listen port |
| `WA_BFF_INTERNAL_PORT` | bff | `8082` | bff internal listen port; must differ from `WA_BFF_PORT` |
| `WA_BFF_URL` | bff, login | `http://localhost:8080` | bff's public base URL. Hydra sends the browser back to `{WA_BFF_URL}/callback` (register it as the client's redirect URI); login's fallback goes to `{WA_BFF_URL}/login`; https under `prod`. Its scheme decides whether bff's cookies are `Secure` |
| `WA_HYDRA_PUBLIC_URL` | bff | `http://localhost:4444` | Hydra's issuer as the browser and the tokens' `iss` see it (the login host, `https://login.example.com`): bff sends the browser to `{…}/oauth2/auth` and `/oauth2/sessions/logout`, and checks `iss` against it. A trailing `/` is dropped |
| `WA_HYDRA_INTERNAL_URL` | bff | `http://localhost:4444` | Where bff reaches Hydra server-side: the token and revocation endpoints and the JWKS. Plain http inside the network is fine. Set explicitly, no discovery: the issuer is public |
| `WA_BFF_CLIENT_ID` | bff, login | `bff` | The Hydra OAuth2 client bff is; login's `/consent` auto-accepts only for it |
| `WA_BFF_CLIENT_SECRET` | bff | *(required)* | That client's secret (`client_secret_basic`); keep it out of `config.yaml`. `prod` refuses the one committed in `bff/config.yaml` |
| `WA_HYDRA_AUDIENCE` | bff | `weaveauth` | The `audience` bff asks for, so access tokens carry it as `aud` (Hydra only puts a requested audience there, and the client's `audience` list must allow it). Empty: none |
| `WA_HYDRA_REFRESH_TOKEN_TTL_SECS` | bff | `2592000` (30 days) | How long Hydra's refresh tokens live: set it to Hydra's `ttl.refresh_token` (`720h` in `ory/hydra/hydra.yml`). A session ends that long after the last refresh that rotated its refresh token (and never later than 30 days after its login, whatever that is set to). 1 to 315360000 |
| `WA_REDIRECT_URI_ALLOWLIST` | bff | *(empty; required under `prod`)* | Comma-separated allowlist of `redirect_uri` values for `/login` and `/logout` (and `/logged-out`'s `state`): exact string match, so mind the trailing slash. Each an absolute http(s) URL (https under `prod`) without user info or a fragment |
| `WA_DEFAULT_REDIRECT_URI` | bff, login | *(unset)* | bff: where `/login` goes when it names no `redirect_uri`, and where `/logged-out` goes when the logout named no allowlisted destination. login: where a page opened without a challenge or a flow goes, through bff's `/login`, so it must be on `WA_REDIRECT_URI_ALLOWLIST`. login also sends the browser here after a password is changed in settings (Kratos returns to login's `/login`, unless the flow carried a `return_to`, which wins); unset, that ends on an error page, so set it whenever settings are used. Empty counts as unset; https under `prod` |
| `WA_TRUSTED_ORIGINS` | bff | *(unset; bff's own origin is always trusted)* | Comma-separated origins allowed to `POST /logout` and to send state-changing proxied requests (checked against `Origin`, falling back to `Referer`), and to read proxied responses cross-origin with credentials (CORS) — so an XSS on any of them reads API data, not just writes it. Each a bare origin as the browser sends it (lowercase, no path, no default port, no `*`; a trailing `/` is dropped), https under `prod` |
| `WA_KRATOS_SESSION_COOKIE` | login | `ory_kratos_session` | Name of Kratos' session cookie; must equal `session.cookie.name` in Kratos' config. A login answer that doesn't set it isn't a success for the per-identifier throttle |
| `WA_SESSION_COOKIE_NAME` | bff | `wa_session` | Name of the HttpOnly session cookie, a cookie-name token (letters, digits, `-`, `_`, `.` and a few other symbols). Under https the browser sees it as `__Host-<name>` (and the login cookie as `__Host-wa_login`), which stops a sibling subdomain from planting one |
| `WA_RATE_LIMIT_MAX_ATTEMPTS` | bff, login | `100` for `dev`, else `10` | Burst size, replenished over 60 seconds, of bff's auth bucket (`/login`, `/callback`, `/logout`, `/logged-out`) and of login's submission bucket (`POST` through the Kratos proxy). `0` stops the service; above `60000` it refills like `60000` |
| `WA_TRUSTED_PROXIES` | bff, login | *(unset)* | Comma-separated addresses or CIDR ranges (a `trusted_proxies:` list in `config.yaml` works for bff) of the reverse proxies in front of the service (e.g. `10.0.0.0/8, 172.30.0.2`), as it sees them connect. A request from one is rate-limited on the client address in its `X-Forwarded-For` (the rightmost entry that isn't itself a trusted proxy). From anyone else the header is ignored. Unset behind a proxy, every client shares the proxy's budget. Under `prod`, an entry wider than IPv4 `/8` or IPv6 `/32` stops the service from starting |
| `WA_LOGIN_PORT` | login | `8081` | login listen port |
| `WA_LOGIN_PUBLIC_URL` | login | `http://localhost:8081` | login's own browser-facing origin (Kratos and Hydra are on the same host behind the proxy); a trailing `/` is dropped; a bare origin, https under `prod` |
| `WA_KRATOS_PUBLIC_URL` | login | `http://localhost:4433` | Kratos' public API, server to server: where login fetches flows and what its `/self-service/*` proxy forwards to |

YAML-only settings:

- **bff** `routes` (below) and `rate_limit_proxy_max_attempts`.
- **hooks** `registration_handler`, `login_claims_handler`
  (`{url, timeout_secs, bearer_token?}`, 10 seconds default, above 0 and at most `request_timeout_secs / 2`; https unless the host is loopback, no
  redirects; `bearer_token`, when set, is sent as `Authorization: Bearer`),
  `profile_apis`, `request_timeout_secs` (30) and `upstream_timeout_secs` (10, each call to Kratos,
  Hydra or bff; `upstream_timeout_secs * 2` must stay below `request_timeout_secs`). Unknown keys in a webhook or `profile_apis` entry are refused.

Lifetimes nobody tunes per deployment are constants in code.

### Proxy routes

bff's `config.yaml` `routes` list controls its reverse-proxy behaviour. It currently points at the
test double in `testing/`:

```yaml
routes:
  - path_prefix: /downstream
    upstream_url: http://localhost:10001
```

Any request whose path is `path_prefix` or under it (whole segments: `/api` does not match `/apix`; longest
prefix wins) is forwarded to `upstream_url` with that prefix stripped, once, and `Authorization: Bearer <access_token>` set from the
session named by the request's `wa_session` cookie. Next to it bff forwards only `Content-Type`, `Accept`,
`Accept-Language` and the conditional headers `If-Match`, `If-None-Match`, `If-Modified-Since` and
`If-Unmodified-Since` (`REQUEST_HEADERS` in `bff/src/server/api/proxy.rs`): every other client header is dropped,
`Cookie`, `Upgrade` and any `X-Forwarded-*`/`Forwarded` included, and bff adds no forwarding headers
of its own. WebSocket isn't proxied. A header an upstream needs gets added to `REQUEST_HEADERS`;
adding `Upgrade` also means extending the `Origin` check to WebSocket handshakes. A path with a `.` or `..`
segment (`;` path parameters ignored, so `..;` counts), or an encoded `/` or `\`, is `404` before anything is forwarded. An upstream has 30 seconds to start
answering (`504`) and a request body may be 10 MiB (`502` past it). A route with `path_prefix: "/"` serves
everything no other route or bff endpoint takes. Routes are checked at startup (a prefix that starts with `/`
without a trailing `/`, `{}*?#%` or `.`/`..` segments; one route per prefix, none on bff's own `/login`, `/callback`, `/logout`, `/logged-out` or `/health`; an http(s) `upstream_url` with no
user info, query or fragment), and under `prod` an `upstream_url` must be https or loopback, since the
session's bearer token goes to it.

The browser attaches the session cookie to any same-site request, and an upstream treats the bearer
token bff adds as CSRF-safe. So a proxied request that can change state, any method but
`GET`/`HEAD`/`OPTIONS`, must come from a `WA_TRUSTED_ORIGINS` origin or bff's own, or gets `403`.
This assumes an upstream changes nothing on `GET`/`HEAD`: `SameSite=Lax` still sends the cookie on
a cross-site top-level `GET` navigation, so an upstream must never change state on `GET`. Active
content (pages with scripts) served through a route runs on bff's origin, which is always trusted: an
XSS there can call every other route and `POST /logout`, so apps with active content belong on their
own origin.

Proxied routes answer CORS (`tower-http`'s `CorsLayer`) for those same origins: a trusted `Origin`
gets `Access-Control-Allow-Origin` (exact match, never `*`) and `Access-Control-Allow-Credentials:
true`, on every proxy response, errors included. Every `OPTIONS` is answered by bff before the
session check and the rate limit (a preflight is cacheable for 10 minutes); only the headers bff
forwards are allowed, so a request naming any other fails in the browser. The session cookie is
`SameSite=Lax`, so CORS only helps a frontend that is cross-origin but same-site as bff
(`app.example.com` → `bff.example.com`). A `WA_TRUSTED_ORIGINS` entry on another *site* than
`WA_BFF_URL` gets no cookie with its requests (always `401`), and its `POST /logout` ends Hydra's
session but not bff's: keep trusted origins same-site as bff.

Upstream responses keep only `Content-Type`, `Content-Encoding`, `Content-Disposition`, `Content-Security-Policy`,
`Cache-Control`, `Location`, `Vary`, `ETag`, `Last-Modified`, `WWW-Authenticate` and `Retry-After`
(`RESPONSE_HEADERS`). bff always sets `X-Content-Type-Options: nosniff`, a `Content-Security-Policy` of
`sandbox; frame-ancestors 'none'` when the upstream sent none (proxied pages run on bff's origin, so an
upstream that serves a page sends its own CSP), and `Cache-Control: no-store` when the upstream sent none; a `Cache-Control` naming none of `public`,
`s-maxage`, a bare `private` or `no-store` gets `private` added. Everything else, `Set-Cookie`,
`Clear-Site-Data`, `Service-Worker-Allowed`, `Strict-Transport-Security` and the rest,
is dropped, because proxied content shares bff's origin and those headers would act on bff itself.
A `Location` passes through unchanged, so an upstream must send relative or public ones, never its
internal hostname.
A route with `path_prefix: "/"` gets a root-scoped service worker without any header: it trusts
that upstream with everything bff serves.

No session → `401`. If the access token has expired bff refreshes it first (see
[tokens.md](docs/flows/tokens.md)); a refresh Hydra refuses by its OAuth `error` (`invalid_grant`, `token_inactive`, `access_denied`) ends the session → `401`; `invalid_client`/`unauthorized_client` (bff's own credentials) → `502`, logged, session kept; any other failure or an unreachable Hydra → `502`, session kept. No matching route → `404`. bff's sessions are in memory: a restart ends them all.

### hooks: the deployer's webhooks

hooks' `config.yaml` (default `config.yaml`, or `WA_CONFIG_FILE`) names the deployer's services. Both
are plain JSON `POST`s to a URL (https unless loopback):

```yaml
# {user_id, email, email_verified, fields} for every new identity; an error fails the registration.
registration_handler:
  url: http://localhost:10002/users
# {user_id, email, email_verified, client_id, scopes} on every token mint; the returned JSON object becomes claims in the access token.
login_claims_handler:
  url: http://localhost:10002/users/claims
```

- `registration_handler` gets the identity id (the future `sub`), the email, whether Kratos has
  verified it (`email_verified`; a new identity's address is unverified until its code is entered,
  unless a provider vouched for it), and `fields`: every
  trait but `email` (add traits to `ory/kratos/identity.schema.json`), plus fields from
  `profile_apis`. A refusal (4xx) or failure aborts the registration and hooks deletes the identity. The webhook can be called again for an identity whose first attempt timed out or was cancelled (the deployer may already hold a record, and a retry can overlap the first attempt), so the endpoint must be idempotent per `user_id`.
- `login_claims_handler` is called on every token mint, refresh included, with `email_verified`
  next to the email (a user can change their email in settings, and the new address is unverified:
  derive nothing from it unless it is `true`). An error fails the token
  request; no token is issued without the claims it is configured to carry. A claim named like a
  reserved one (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`, `email`, `email_verified`, `scp`,
  `scope`, `client_id`, `azp`, `cnf`, `act`, `may_act`, `typ`, `token_use`, `ext`, `sid`, `nonce`,
  `auth_time`, `acr`, `amr`, `at_hash`, `c_hash`, `rat`) also fails it. An identity that is not
  `active` gets no token, refresh included. Hydra only makes a returned claim a top-level JWT claim if it is in
  `oauth2.allowed_top_level_claims` in `ory/hydra/hydra.yml` (`roles`, `email`, `email_verified`
  there; `dev/render.sh` also adds `first_name`, `last_name` and `phone_number` for `mise run all`);
  other names end up under `ext`. Keep that list in step with the webhook.

Some profile data never appears in the id_token. Google's phone number is one: it can only be read
from the People API. A provider's `profile_apis` entry (keyed by Kratos' provider id) is a list of
extra `GET` calls made with the access token Kratos stored for the identity, right after a social
sign-up; each maps `field name -> JSON pointer` (RFC 6901) into the response, and the fields go to
`registration_handler` next to the traits. `url` must be `https://` (loopback excepted), since it
carries the access token.

```yaml
profile_apis:
  google:
    - url: https://people.googleapis.com/v1/people/me?personFields=phoneNumbers
      required: false   # the default
      scope: https://www.googleapis.com/auth/contacts.readonly
      claims:
        phone_number: /phoneNumbers/0/canonicalForm
```

`required` decides what a failed call does. A failure is a transport error, a non-2xx response or
a body that isn't JSON. With `required: false` (the default) it is logged as a warning and that
call's fields are left out. With `required: true` the registration fails and no identity is kept.
A pointer that finds nothing is not a failed call: the field is simply left out, except for a
`required` entry, which treats it as a failure. `scope` is meant to skip the call when the user
unticked that permission, but hooks cannot see which scopes a user granted at the provider (Kratos
passes no tokens or scopes to its hooks), so the call is always made; a declined permission only
shows up as a failed call. The scope itself must also be in the provider's `scope` list in Kratos'
config, or the access token won't have it.

About the Google example. `people/me` reads the phone number from the user's own contact card,
which takes `https://www.googleapis.com/auth/contacts.readonly`, read access to *all* of the user's
contacts. The narrower `user.phonenumbers.read` only sees numbers on the Google Account profile,
which most accounts don't have: `people/me` answers 200 with no `phoneNumbers`. The scope must be
asked for at sign-in, so load `ory/kratos/oidc-google-phone.yml` instead of `oidc-google.yml` (the
base file asks for email and profile only, and every deployer who never configures
`profile_apis.google` keeps it that way); the `scope:` here and in that file have to stay in step.
It is a sensitive Google scope: until your Google Cloud app passes OAuth verification, only its test
users can grant it.

Fields from `profile_apis` do not pass through the identity schema, so the `phone_number` pattern
(`^\+[1-9][0-9]{6,14}$`) is not applied to them. The number is whatever the user typed at Google, so
it is unverified and not necessarily in that format; validate it in `registration_handler`.

### Ory

Kratos and Hydra are configured entirely under `ory/` (pinned to `oryd/kratos:v26.2.0` and
`oryd/hydra:v26.2.0`); [ory/README.md](ory/README.md) explains every setting, which URLs to change
for a deployment, and the behaviour checks the design rests on. Secrets (`DSN`, `SECRETS_*`) are
env vars on the Ory containers, never in the files.

**Google sign-in.** Create an OAuth client (Web application) at Google and register the redirect
URI

```
https://<login host>/self-service/methods/oidc/callback/<provider>
```

(`.../callback/google` for the shipped `ory/kratos/oidc-google.yml`; the provider's `id` is the
last path segment). It is on the **login** host, not bff's: Kratos' `base_redirect_uri` is the
login host and login forwards the path to Kratos. Load the provider as a second Kratos config file
and give it the client id and secret (local-prod: `KRATOS_CONFIG_EXTRA=/etc/kratos/oidc-google.yml`,
or `oidc-google-phone.yml` when `profile_apis.google` reads the phone number, see *profile_apis* in
the hooks section above; `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` in `local-prod/.env`).
Kratos needs egress to Google and its public CAs. Any other OIDC provider works with
`ory/kratos/oidc/generic.jsonnet` as its mapper.

**Verified-email-first.** By default nobody is signed in until their address is verified: the
registration flow ends in a verification code, and a login with an unverified address starts a
verification instead of finishing (password, passkey and provider logins alike). A provider that
asserts `email_verified: true` skips the code. To sign users in right after registration instead,
load the overlay as a second Kratos config file:

```
kratos serve -c kratos.yml -c session-on-registration.yml
```

(local-prod: `KRATOS_SESSION_ON_REGISTRATION=1` in `.env`.) The verification mail is still sent but
not required (also set `WA_REQUIRE_VERIFIED_EMAIL=false`, or the token hook refuses the unverified address), so the `email_verified` claim in the tokens is what a service checks. Details and
the two Kratos traps in [registration.md](docs/flows/registration.md#verified-email-first).

**Key rotation.** Hydra signs JWT access tokens and id tokens with keys it creates on first start.
To rotate (no restart needed), create a new key; new tokens use it at once and the old one stays in
the JWKS so tokens in flight keep verifying:

```bash
mise run rotate-keys   # hydra create jwks hydra.jwt.access-token / hydra.openid.id-token, in local-prod
```

Once the old key is older than the access token TTL plus the longest JWKS cache of any consumer
(downstream services verifying the JWTs, and bff for id tokens, which refetches on an unknown
`kid` and every hour), remove it with `hydra delete jwk <set> <old kid>`. Run this as a scheduled job. The system
secrets rotate by prepending a new value to `secrets.system`/`secrets.cookie` (Hydra) and
`secrets.cookie`/`secrets.cipher` (Kratos), keeping the old one second until everything it signed
or encrypted has expired. The full runbook is in [ory/README.md](ory/README.md#key-rotation).

**Resetting state.** `mise run ory-down` (`docker compose down -v`) drops the Postgres volume:
every identity, session and Hydra client goes, and a fresh `ory-up` starts empty. The secrets in
`local-prod/.env` belong to that data, so regenerate both together (delete `.env` and rerun
`gen-secrets.sh`).

## Testing

```bash
cargo test            # or: mise run test
mise run test-docker  # needs Docker
```

`cargo test` runs the workspace suite (`testing/*` are standalone fixtures, not members):

- `hooks`: unit tests inline plus `hooks/tests/` — the real router driven in-process against stub
  Kratos, Hydra, bff and webhook servers: the token hook (claims, reserved names, failing closed),
  after-registration (profile APIs, rollback), recovery's purge and revocations, and the API key on
  every route.
- `bff`: unit tests inline plus `bff/tests/` against a stub Hydra — login and callback (state,
  allowlist, PKCE), logout and `/logged-out`, back-channel logout (forged, replayed and malformed
  tokens), internal revoke, refresh (single-flight, rotation, failures), and the proxy.
- `login`: unit tests inline plus `login/tests/` — pages and the CSRF field, script nonces and
  escaping, a deployer template that keeps the scripts, the Kratos proxy and its per-client and
  per-identifier limits, and the Hydra consent and logout chains.

`mise run test-docker` runs `weaveauth-system-tests` with the `docker` feature: real Kratos, Hydra
and Postgres containers driven end to end.

`ory/checks/run_checks.py` re-runs the behaviour checks the Ory configuration rests on against a
compose stack with a stub in place of the WeaveAuth image (see `ory/README.md`).

## Docker

Single multi-stage `Dockerfile` at repo root. The `rust:1.98-slim-trixie` builder compiles
`weaveauth-hooks`, `weaveauth-bff`, `weaveauth-login` and `weaveauth-launcher`. The
`gcr.io/distroless/cc-debian13` runtime (no shell) copies them plus `/app/login/static` and
`/app/templates` (`pages/` for the login pages, `providers/` for the sign-in button logos), and runs `weaveauth-launcher`, which starts all
three and exits when any one of them does. Everything runs as `weaveauth` (1000) with no
capabilities. The image contains no Ory: Kratos and Hydra run as their own containers. The launcher
handles no signals and the services have no graceful shutdown: without `docker run --init`, `docker stop`
waits out its grace period and then `SIGKILL`s; with it the stop is prompt, but in-flight requests are cut.

The image runs the `prod` profile, which won't start on localhost defaults; see the configuration
table for what it needs (https URLs for bff and login, Hydra's and Kratos' addresses, the API keys,
the client secret and the redirect allowlist). Only 8080 (bff) and 8081 (login) are for the proxy;
hooks (1983) and bff's internal listener (8082) listen on every interface of the container and must
stay on an internal network. In Kubernetes give the pod a NetworkPolicy, on a network plugin that
enforces it (pods can otherwise reach each other on any port): allow 8080 and 8081 from the ingress
controller only, 1983 only from Kratos and Hydra, and 8082 only from Hydra and hooks' own container.
Set `WA_TRUSTED_PROXIES` to the ingress controller's pod addresses (or their range), or every client
shares one rate-limit bucket; a range is only safe while that NetworkPolicy lets nothing but the
ingress reach 8080 and 8081, since any pod in it could otherwise send its own `X-Forwarded-For`.

To run it the way production should, under `prod` behind a TLS proxy on a private network, with
Ory and Postgres, see [local-prod/](local-prod/README.md) (`mise run ory-up`).

## License

Apache License 2.0. Copyright 2026 Silvio Sabo.
