# AGENTS.md

Agent guide for the WeaveAuth repo. Follow these conventions.

## Scope
- Applies to the entire repository unless a deeper `AGENTS.md` overrides it.
- Default implementation language is Rust. Use non-Rust services/tools only when the task explicitly targets them.

## Overview

WeaveAuth sits on **Ory Kratos** (identities: password, Google/social, passkeys, recovery,
verification, email) and **Ory Hydra** (OIDC, JWT access tokens, JWKS, refresh), which run as
their own containers from the official images, configured under `ory/`. The Cargo workspace is the
part WeaveAuth owns:

- `bff/` (binary `weaveauth-bff`, public port 8080, internal port 8082): the OAuth/OIDC client of
  Hydra. Owns PKCE, the `wa_session` cookie and the tokens behind it, and proxies configured
  routes upstream with a Bearer JWT.
- `login/` (binary `weaveauth-login`, port 8081): the server-rendered UI for Kratos' flows and
  Hydra's login/consent/logout challenges, and the only way a browser (or anything public) reaches
  Kratos.
- `hooks/` (binary `weaveauth-hooks`, port 1983, **internal only**): the web hooks Kratos and
  Hydra call (claims, registration, recovery purge) and the deployer's webhook
  contracts.
- `common/` + `common/macros/`: shared config loading, error types and the `ErrorResponses`
  derive, request extractors, the rate limiter.
- `launcher/`: `weaveauth-launcher`, the container entrypoint (std-only).
- `system-tests/`: cross-service tests against real Kratos and Hydra containers.

`ory/`, `local-prod/` and `testing/` are not workspace members: `ory/` is Ory's configuration
(plus `ory/checks/`, the driver for the behaviour checks), `local-prod/` a docker compose of the
whole stack behind TLS, `testing/` standalone test doubles.

## Commands

- Workspace tests: `cargo test` (or `mise run test`). Each crate has its own tests: hooks'
  HTTP-level tests in `hooks/tests/`, bff's in `bff/tests/` (login/callback, logout, back-channel
  logout, internal revoke, refresh, proxy), login's in `login/tests/` (pages, the Kratos proxy,
  the Hydra challenge chains). `mise run test-docker` runs the system tests that need a Docker
  daemon (`cargo test -p weaveauth-system-tests --features docker`: real Kratos, Hydra and
  Postgres via testcontainers); `mise run system-tests` runs the rest of that crate.
- Run the services on the host: `mise run services` from the repo root (hooks, bff and login).
  Each crate also has its own `mise.toml` (`dev`/`build`/`test`/`lint` tasks); `mise run dev` from
  inside a crate directory is equivalent to `cargo run` there — **the cwd matters**: `hooks` and
  `bff` look for `config.yaml` as a bare relative path (see below), so `cargo run -p <crate>` from
  the repo root won't find it, and the default `prod` profile then refuses to start (missing settings).
  `services` does not start Ory; hooks, bff and login need a Kratos and a Hydra they can reach.
- Run everything on one machine: `mise run all` (`dev/docker-compose.yml`: Postgres, Kratos, Hydra,
  Mailpit with configs rendered from `ory/` by `dev/render.sh`; plus `services` and the test apps
  on the host). `mise run dev-ory-down` stops the containers and drops their data. A change to
  `ory/kratos/kratos.yml` or `ory/hydra/hydra.yml` needs
  `sh dev/render.sh && docker compose -f dev/docker-compose.yml restart kratos hydra`.
- Run the whole stack in containers, with Ory: `mise run ory-up` (`local-prod/`, which needs
  `./gen-certs.sh` and `./gen-secrets.sh` run once; see `local-prod/README.md`), `mise run ory-down`
  (also drops the Postgres data, `docker compose down -v`).
- Rotate Hydra's signing keys: `mise run rotate-keys` (against the `local-prod` stack; the runbook,
  including removing the old keys, is in `ory/README.md`).
- Full build: `cargo build --workspace --release`
- No linter/formatter is configured beyond `cargo clippy` (each crate's `mise.toml` has
  a `lint` task). Keep `cargo fmt`-style output manually.
- `mise run crap` runs `cargo llvm-cov --workspace` (the whole test suite, instrumented)
  and feeds the LCOV to `cargo crap`, listing functions with CRAP score >= 30 and failing
  (`--fail-above`) if any scores above 30. It is not part of `lint` because of the
  test-suite runtime. Writes `lcov.info` (git-ignored).
- After changing code, run cargo-crap scoped to the touched files, like `cargo-mutants`:
  `cargo llvm-cov -p <package> --lcov --output-path lcov.info`, then
  `cargo crap --path <file> --lcov lcov.info --fail-above`. Fix any function over 30 by
  adding tests or splitting it before finishing. `--path` takes a file or a directory;
  the scoped run overwrites the workspace `lcov.info`.

## Coding Rules
- Formatting: use `rustfmt` with default settings.
- Lint: code must pass `cargo clippy` with default lints.
- Error handling: use `thiserror` to define error types; prefer `Result<T, MyError>` over panics.
  - **Layer separation**: Service/business-logic errors must NOT contain HTTP knowledge. Do NOT use `#[error_response(...)]` or import `StatusCode` in service modules. HTTP error mapping belongs in the controller/handler layer only.
  - **Pattern**: Define two error types per endpoint: (1) `XyzServiceError` in `service` module with only `#[derive(Debug, Error, ...)]`, (2) `XyzError` in `controller` module with `ErrorResponses` and `#[error_response(...)]` attributes. Implement `From<XyzServiceError> for XyzError` in controller to enable automatic conversion via `?` operator.
  - **Item order within a module**: top-down, public-first, types-before-consumers.
    - `controller`: imports, request struct(s), response struct, error enum,
      then the handler fn last (it's the assembly of everything declared above it).
    - `service`: error enum first, then the public entry fn, then private helpers below
      it in call order.
- Model outcomes with different data as an enum with one variant per case, not a struct with `Option` fields that are only set in some cases (applies to response bodies, service outcomes and storage results alike).
- Avoid functions that return `bool` for a success/failure outcome; return `Result<T, MyError>` with an error enum instead, so callers can match on and log the actual failure reason.
- Async: use `async/await` with `tokio` runtime for IO-bound operations.
- Logging: use `tracing` for structured logging; avoid logging sensitive information.
  - **Log an error or return it, never both.** An error is logged exactly once. Code that
    returns an error (service, storage, handler impls) carries the cause in it and does not log
    it; the top level (the controller, or `From<XyzServiceError> for XyzError`) logs it just
    before handing over the response. Code that swallows an error instead of returning it logs
    it at that spot.
  - **Detailed logs, opaque responses.** What the caller sees is fixed and generic: the
    `#[error_response(...)]` status and its static `details` text (or none), never an upstream
    message, status code, URL, hostname, file path, webhook output, or anything derived from a
    cause. The cause lives only in the log, where it should be as detailed as it can be: say
    what failed and against what, and keep the whole chain (`common::error::cause_chain`),
    because `Display` on reqwest/hyper errors drops the source ("error sending request" without
    "connection refused"). Never put secrets, tokens, passwords, codes or personal data in a
    log line either; strip URLs that carry them (`reqwest::Error::without_url`). A service error
    may carry the cause as a `String`, but its controller counterpart must not, and must not
    format it into the response.
- Never use ignore in documentation tests.
- Keep changes minimal and localized; prefer the shortest working change.

## Testing Expectations
- Add/update tests for behavior changes.
- Write tests first before implementing new behavior. Make sure tests fail before implementing the change.
- Prefer fast unit tests first; add integration coverage when behavior crosses IO boundaries.

### Mutation testing

A test that passes proves nothing until it has been shown it can fail. After writing or
changing a test, break the code it covers on purpose, confirm that exact test fails, then
restore the code. This catches the common failure where a test passes whether or not the
feature works at all.

- Mutate the smallest thing that should matter: invert a condition (`==` → `!=`), delete a
  guard clause, short-circuit a branch (`if cond` → `if false && cond`), drop a call, or
  return early.
- Exactly one test should fail, and it should be the one written for that behavior. None
  failing means the test is vacuous. Many failing means they all lean on the same
  assumption and none of them pins this behavior down.
- Cover both directions. A test asserting something does NOT happen (a handler isn't
  called, a route isn't served) needs a companion asserting it DOES on the happy path —
  otherwise deleting the feature outright leaves the suite green.
- Restore the code and re-run the full suite before finishing. Never commit a mutation.
- For security-relevant behavior, record the mutation and the test that caught it in the
  commit body, so a reviewer can see the test was verified rather than assumed.

`cargo-mutants` (already installed) does the same thing exhaustively. **It is not part
of the per-change loop** — a scoped run is minutes and a crate-wide one is far worse, so
it is run deliberately, not by default. The manual check above is what every behavior
change gets; reach for `cargo-mutants` when the extra minutes are worth it:

- before shipping security-relevant behavior (auth, tokens, allowlists, sandbox limits),
- when a piece of logic is dense enough that picking one mutation by hand won't cover it,
- when a reviewer or the author doubts a test is doing anything,
- on request.

- Run via `mise run mutants -- -p weaveauth-hooks` (or `-p weaveauth-bff`/`-p
  weaveauth-login`) from the repo root. Everything after `--` is
  forwarded straight to `cargo mutants`, so scope to one file with `--file
  hooks/src/webhook.rs`, or a function/line with `--file ... --function name` /
  `--line N`, to keep a run fast. Don't try `CARGO_INCREMENTAL=1`: `~/.cargo/config.toml`
  sets `sccache` as the `rustc-wrapper`, which refuses to run incremental at all; forcing
  it off via `RUSTC_WRAPPER=""` to allow incremental was tried and measured *slower* overall
  (loses sccache's cross-crate cache reuse, which mattered more than incremental's
  per-mutant savings) — not worth the complexity.
- It builds each mutant, runs the test suite, and reports mutants that survived (no
  test failed) vs. caught. A surviving mutant means a real gap in coverage.
- **"0 missed" is not "all covered".** A mutant reported *unviable* never had a test run
  against it -- it failed to build. `dead_code` is a warning, not a denied lint, so a body
  replaced by a constant that orphans imports or constants still builds. What stays unviable
  is a mutant whose replacement value doesn't exist (`Ok(Default::default())` for a type
  with no `Default`). Compare the unviable count against the previous run; if a mutant moved
  from missed to unviable rather than to caught, nothing was proven. Force it by hand and
  check the test actually fails.
- Likewise, a package-scoped run only runs **that package's** tests. Mutating
  `common` reports mutants as missed that only a test in `hooks`, `bff` or `login` (or
  `system-tests`) catches -- confirm cross-package coverage by hand before treating one as a
  gap.
- Always scope it to the touched file(s); fix surviving mutants by strengthening the
  test, not the implementation.
- Slow on a full crate (rebuild + test run per mutant) — a workspace-wide run is not
  worth starting without a reason.
- It writes into the same build directory as everything else (`~/.cargo/config.toml`
  sets one shared `target-dir`), so a `cargo test` running alongside it can link against
  a *mutated* artifact and fail for no reason. Don't run the two at once; if you must,
  give the other one `CARGO_TARGET_DIR=/tmp/…`.
- `.cargo/mutants.toml` excludes each crate's `main.rs` (pure startup wiring, no branches
  worth mutating) via `exclude_globs` — cargo-mutants only reads config from
  `.cargo/mutants.toml` by default, not a workspace-root `mutants.toml`.
- A surviving mutant that only changes whether a log line fires (not any return value,
  stored state, or response) is treated as accepted noise, not chased with log-capture
  test infrastructure — e.g. a `!=`/`==` on a revoke outcome that only
  gates a `tracing::warn!`. Record the reasoning in the commit body when leaving one
  unaddressed.
- When a run does happen for security-relevant behavior, record the surviving-then-fixed
  mutant and the test that now catches it in the commit body.

## Documentation
- When a change alters a flow documented under `docs/flows/`, update that doc in the same change — it must describe the current behavior, not what it used to be.

## Comments in code
- Inside function bodies, keep comments short and to the point; prefer a single line, and only go multi-line when truly necessary. Doc comments (`///`) above a function can be longer when needed.
- Keep comments up to date with code changes.
- Comment only when it adds value (explain why, not what).
- Avoid comments that are obvious from the code itself.
- Avoid comments that are likely to become stale or misleading.
- Avoid comments that are too verbose or distract from the code.
- Avoid comments that are too terse or cryptic.
- Avoid comments that are too subjective or opinionated.
- Avoid comments that are referencing external resources that may change or disappear.
- Skip a comment if its content is fully inferable from the function name, signature, or return type (e.g. `Option<T>` returning `None` for "not found" needs no comment).
- Don't restate what a type link already says (`[`Self::foo`]` in a param name already points there).
- A comment earns its place only by stating something a reader could get WRONG without it — a hidden precondition,
  a surprising default, a non-obvious invariant. If removing it changes zero assumptions a competent reader would make, cut it.
- A comment must describe the current code, not its history: never write "X is the single source of truth
  now", "no longer needs Y", "this replaces Z", or similar — those explain past functionality rather than the code in front of the reader,
  and rot the moment something else changes again.

## Architecture

- Root `Cargo.toml` is a workspace: `members = ["hooks", "bff", "common", "common/macros",
  "launcher", "login"]` (plus `system-tests`).
- **Ory, not code, is the authorization server and the user store.** Kratos holds identities and
  credentials (`ory/kratos/identity.schema.json`: `email`, `first_name`, `last_name` required,
  `phone_number` optional); Hydra issues the tokens (`strategies.access_token: jwt`). Both use
  Postgres.
  `ory/README.md` explains every setting and holds the results of the behaviour checks the design
  rests on; read it before changing `ory/`.
- **Login chain.** bff `GET /login?redirect_uri=` (exact-match allowlist, PKCE S256, `state`/`nonce`/
  verifier in the `wa_login` cookie) → Hydra `/oauth2/auth` → login `/login?login_challenge` →
  Kratos flow rendered by login → Kratos accepts Hydra's login request itself
  (`oauth2_provider.url`) → Hydra → login `/consent` (auto-accepts for `WA_BFF_CLIENT_ID` and
  scopes `openid offline_access`) → bff `/callback` (state check, code exchange against Hydra's
  internal URL with `client_secret_basic`, id_token verification) → one 303 to the allowlisted
  `redirect_uri` with `wa_session`. Flows are in `docs/flows/`.
- `bff/src/server/router.rs` — `public_router` (`/login`, `/callback`, `POST /logout`,
  `/logged-out`, `/health`, and the proxy as the fallback) on `port`, and `internal_router`
  (`POST /backchannel-logout`, `POST /internal/revoke`) on `internal_port`. The internal one is never
  routed publicly. `weaveauth_bff::server::apps(config)` builds both for tests (there is no
  `app()`). `bff/src/hydra/` is its side of Hydra: OAuth2 client calls, JWKS cache, id_token and
  `logout_token` verification. One slice per endpoint under `bff/src/server/api/`, see
  `bff/AGENTS.md`.
- `bff` sessions (`InMemorySessionStorage`: session id → access/refresh/id token, `sub`, `sid`)
  and the back-channel `jti` store follow the in-memory idiom below, so a restart ends every
  session. Refresh is single-flight per session (`refresh_lock.rs`): Hydra treats a reused
  rotated refresh token as theft and revokes the chain.
- `bff/src/server/api/proxy.rs` — one `axum-reverse-proxy` service per `Config::routes` entry,
  mounted with `nest_service` at its `path_prefix` (the router strips it once; a `/` route is the
  router's `fallback_service`), behind `authenticate`: a path with a segment of only dots (raw or encoded once or twice) or an encoded
  `/` or `\` is `404`, the session cookie is resolved to an access token (refreshed first if due),
  and the request is forwarded to `upstream_url` with `Authorization: Bearer <token>` plus the
  client headers in `REQUEST_HEADERS` (`Content-Type`, `Accept`, `Accept-Language` and the `If-*`
  conditionals); everything else (`Cookie`, `Upgrade`, any forwarding header) is dropped,
  and bff adds no `X-Forwarded-*` of its own, so WebSocket isn't proxied. Responses keep only
  `RESPONSE_HEADERS` (`Content-Type`, `Content-Disposition`, `Content-Security-Policy`,
  `Cache-Control`, `Location`, `Vary`, `ETag`, `Last-Modified`, `WWW-Authenticate`,
  `Retry-After`), plus bff's `X-Content-Type-Options: nosniff`, a sandboxing CSP when the upstream
  sent none and a `Cache-Control: no-store` default (`private` added when the upstream's leaves
  shared caching open). Non-safe methods need a trusted `Origin` first (`403`). `401` on
  missing/unknown session, `404` on no matching route. Unmatched paths are the router's `404`
  fallback, outside the session check.
  The routes sit inside a `tower-http` `CorsLayer` for the same trusted origins (credentials,
  `REQUEST_HEADERS` only), outermost (above the governor). `tower-http` answers every `OPTIONS`
  itself, so `OPTIONS` needs no session, isn't rate limited and is never proxied.
- `login/src/lib.rs` — `app(Config)`, `app_with_pages`, `app_with_templates` (pages glob plus providers dir, for the logo tests), `serve`. Pages (`/login`,
  `/registration`, `/recovery`, `/verification`, `/settings`, `/error`), Hydra's `/logout` and
  `/consent` (`challenges.rs`), `/ui.js`, `/static/*`, `/providers/*` (logos), and the one proxy to Kratos public
  (`GET`/`POST /self-service/*`, `GET /.well-known/ory/*`; two per-client buckets from
  `common::rate_limit`, plus the per-identifier throttle on password submissions in
  `throttle.rs`). Templates in `templates/pages/*.html` extend the compiled-in
  `login/src/layout.html` and render Kratos' flow nodes through the Tera functions `form` and
  `messages`; deployers supply no script (`login/AGENTS.md`).
- `hooks/src/server/router.rs` — every route but `/health` behind `Authorization: Bearer
  <WA_HOOKS_API_KEY>` and a request timeout: `POST /hydra/token-hook` (claims: `email`,
  `email_verified` from Kratos plus the deployer's `login_claims_handler`; reserved names refused;
  an inactive identity gets none; fails closed), `POST /kratos/after-registration` (profile APIs, the `registration_handler`
  webhook; a failure deletes the identity itself, since Kratos runs the hook after persisting),
  `POST /kratos/after-recovery` (replaces the password with a random one, deletes the passkey/webauthn/
  totp/lookup credentials and every OIDC link, revokes Kratos sessions, Hydra consent and login sessions and bff's sessions
  through `POST /internal/revoke`) and `POST /kratos/after-password-change` (the revocations
  without the purge). See `hooks/AGENTS.md`.
- `launcher/` — `weaveauth-launcher` runs hooks, bff and login in one container and exits when
  one does.
- `Dockerfile` — multi-stage: builds the three services and the launcher, runs them from a
  distroless runtime as `weaveauth` (1000) with no capabilities and no file caps. It contains no
  Ory: Kratos and Hydra are separate containers.
- `local-prod/` — docker compose: the image, Kratos, Hydra (public API on `hydra`, admin API on
  `hydra-admin`, internal network only), Postgres, Mailpit and a Caddy TLS
  proxy. Only Caddy is on the public network; Caddy routes `/oauth2/auth` and
  `/oauth2/sessions/logout` to Hydra and everything else on the login host to login, which alone
  forwards `/self-service/*` and `/.well-known/ory/*` to Kratos (never route those straight to
  Kratos: login applies the rate limits). Throwaway local CA from `gen-certs.sh`.
- `system-tests/` — testcontainers with Kratos and Hydra (the `docker` feature).
- `testing/` — standalone fixtures outside the workspace: `downstream-service` (the bearer-token
  demo upstream) and `user-service` (the webhook target of the registration and login-claims hooks)
  and `user-service`.

## Conventions

- `hooks` and `bff` load an optional YAML overlay (`WA_CONFIG_FILE`, default bare
  `config.yaml` relative to cwd — see the cwd gotcha above) before env vars; env vars
  still win when set. All three services load through `common::config`: defaults, then
  YAML (hooks and bff only; login reads env vars alone), then only the env vars listed
  in the crate's `ENV`/`ENV_LISTS` table (so an unlisted `WA_*` var is never read). A
  YAML key can set any `Config` field; an env var exists only when someone needs it per
  deployment. YAML-only settings: bff's `routes` and `rate_limit_proxy_max_attempts`, hooks'
  webhook handlers, `profile_apis` and timeouts.
- `prod` (the default, in all three services) refuses to start unless the browser-facing URLs
  are https (`require_https_in_prod`) and the internal addresses that have only a localhost
  default are set: bff's `WA_HYDRA_PUBLIC_URL` and `WA_HYDRA_INTERNAL_URL`, hooks'
  `WA_KRATOS_ADMIN_URL`, `WA_HYDRA_ADMIN_URL` and `WA_BFF_INTERNAL_URL`; bff also needs a
  non-empty `redirect_uri_allowlist` and a `WA_BFF_INTERNAL_API_KEY` of 16 or more characters.
  `WA_BFF_CLIENT_SECRET` and `WA_BFF_INTERNAL_API_KEY` (bff) and `WA_HOOKS_API_KEY` (hooks, to
  serve; 16 or more characters in `prod`) are required in every profile, hooks also needs
  `WA_BFF_INTERNAL_API_KEY` to serve, and login needs `WA_KRATOS_PUBLIC_URL` and `WA_HYDRA_ADMIN_URL` in `prod`; an unset key never means an open route. Test and dev
  configs set `profile: dev` (`WA_PROFILE=dev` where login runs too, since it reads no YAML).
  Lifetimes nobody tunes per deployment are a constant in code, not YAML/env. New scalar config →
  a field on `Config` + a row in the crate's `ENV` table (if it needs an env var) + a row in
  `README.md`.
- Where a setting lives is fixed: the redirect allowlist is bff's (`WA_REDIRECT_URI_ALLOWLIST`,
  exact string match, checked at `/login`, `/logout`, `/logged-out` and again at `/callback`);
  Kratos' `allowed_return_urls` and Hydra's URLs live in `ory/`; the claim names Hydra puts at
  the top level of a token live in Hydra's `oauth2.allowed_top_level_claims`, which must match
  what the deployer's claims webhook returns.
- Custom environment variables are prefixed with `WA_`. Ory's own are not (`DSN`,
  `SECRETS_COOKIE`, ...) and are set on the Ory containers only.
- Root `Cargo.toml`'s `[workspace.dependencies]` declares bare version numbers only, no
  features (e.g. `axum = "0.8"`, not `axum = { version = "0.8" }`). Each member crate
  declares the features it needs on its own `{ workspace = true, features = [...] }`
  line. Exception: `default-features = false` is part of the dependency's identity
  shared by every consumer, so it belongs on the root declaration (see `openidconnect`),
  not repeated per member.
- In-memory storage (bff's session store and `logout_token` `jti` store, login's throttle)
  follows the same idiom throughout: `Arc<Mutex<HashMap<...>>>`, "take"/remove-on-read for
  single-use records.
- Webhook handlers (hooks) and the Kratos/Hydra clients follow the error rules above: the cause
  goes in the service error and the log, never in what Kratos, Hydra or a browser sees.

## Gotchas

- Docker must copy `/app/login/static` and `/app/templates` to the same absolute paths the
  binaries were built with: login bakes `<crate>/static`, `<crate>/../templates/pages` and `<crate>/../templates/providers` at
  compile time (`CARGO_MANIFEST_DIR`). Deployer-replaceable page templates and provider logos live in the top-level
  `templates/pages/` and `templates/providers/`; never put them back under a crate directory.
- If a bff route or hooks route is added, update the route table in `README.md`; if a Kratos or
  Hydra setting changes, update `ory/README.md` and the matching `local-prod/` file.
- hooks (1983) and bff's internal listener (8082) must never be publicly reachable: bff's
  (`/backchannel-logout`, `/internal/revoke`) and hooks' routes are authorized only by a token or
  an API key. Kratos and Hydra admin ports are internal too. Only bff's public port and login are
  meant to be internet-exposed, and Hydra's `/oauth2/auth` and `/oauth2/sessions/logout` through
  the proxy.
- Kratos can't read the hooks API key from env: `ory/kratos/start.sh` and `ory/hydra/start.sh`
  substitute `@WA_HOOKS_API_KEY@` into a copy of the config, so use a hex or base64url key. A
  second Kratos `-c` file **replaces** arrays rather than merging them (the session-on-registration overlay
  repeats the web hook for that reason), and a method's own hook list replaces the global one.
- Hydra 26's `skip_consent` does not bypass `urls.consent`, so login has a `/consent`; Hydra's
  admin revocation by subject does not fire back-channel logout, so hooks also calls bff's
  `/internal/revoke`; a JWT access token stays valid until `exp` whatever is revoked, so keep
  `ttl.access_token` short; `WA_HYDRA_REFRESH_TOKEN_TTL_SECS` (bff) must equal Hydra's
  `ttl.refresh_token`.
- Known gaps, documented as current behaviour: a verification started by a *login* ends on Kratos'
  `/error` after the code is entered (the address is verified; the user signs in again), and hooks
  cannot see which scopes the user granted at a provider, so `profile_apis[].scope` cannot be
  enforced.
- `docker compose down -v` resets everything in `local-prod/`, Postgres included; the secrets in
  its `.env` belong to that data (regenerate both together).
- Toggling `RUSTC_WRAPPER`/`CARGO_INCREMENTAL` between builds (e.g. experimenting with
  disabling sccache) can leave `sccache` serving a stale/corrupted cached object for a
  later build with the *same* env — surfaces as unrelated tests failing or passing
  inexplicably, and disappears if you rebuild with `RUSTC_WRAPPER=""`. Fix by clearing
  the cache directory (`sccache --show-stats` prints its `Cache location`, e.g.
  `~/Library/Caches/Mozilla.sccache` on macOS) rather than debugging the "failure" as a
  code issue.
