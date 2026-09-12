# AGENTS.md

Agent guide for the WeaveAuth repo. Follow these conventions.

## Scope
- Applies to the entire repository unless a deeper `AGENTS.md` overrides it.
- Default implementation language is Rust. Use non-Rust services/tools only when the task explicitly targets them.

## Overview

Cargo workspace with three members: Axum backend (`backend/`, binary `weaveauth`, port
1983, **not exposed publicly**), the BFF (`bff/`, binary `weaveauth-bff`, port 8080 —
owns PKCE, the OAuth client role, and the session cookie), and an optional thin static
login page (`login/`, binary `weaveauth-login`, port 8081, just redirects into bff).

## Commands

- Workspace tests: `cargo test` (bff's PKCE/session flow: `bff/tests/pkce_flow.rs`;
  login's redirect: `login/tests/redirect_test.rs`; backend's are unit tests inline)
- Run everything: `mise run services` from the repo root. Each crate also has its own
  `mise.toml` (`dev`/`build`/`test`/`lint` tasks); `mise run dev` from inside a crate
  directory is equivalent to `cargo run` there — **the cwd matters**: `backend` and
  `bff` look for `config.yaml` as a bare relative path (see below), so `cargo run -p
  <crate>` from the repo root won't find it and silently falls back to hardcoded
  defaults instead of erroring.
- Full build: `cargo build --workspace --release`
- No linter/formatter is configured beyond `cargo clippy` (each crate's `mise.toml` has
  a `lint` task). Keep `cargo fmt`-style output manually.

## Coding Rules
- Formatting: use `rustfmt` with default settings.
- Lint: code must pass `cargo clippy` with default lints.
- Error handling: use `thiserror` to define error types; prefer `Result<T, MyError>` over panics.
- Async: use `async/await` with `tokio` runtime for IO-bound operations.
- Logging: use `tracing` for structured logging; avoid logging sensitive information.
- Never use ignore in documentation tests.
- Keep changes minimal and localized; prefer the shortest working change.

## Testing Expectations
- Add/update tests for behavior changes.
- Write tests first before implementing new behavior. Make sure tests fail before implementing the change.
- Prefer fast unit tests first; add integration coverage when behavior crosses IO boundaries.

## Comments in code
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

- Root `Cargo.toml` is a virtual workspace: `members = ["backend", "bff", "login"]`.
- `backend/src/server/mod.rs` — `AppState::new(&Config)` + `router(AppState)`. PKCE
  storage (`InMemoryPkceStorage`) is single-use and TTL'd; `redirect_uri` is
  allowlist-checked in `server/api/authorize.rs`. `model/user.rs` /
  `InMemoryUserStorage` and `model/session.rs` / `InMemorySessionStorage` exist but are
  intentionally unwired (real user auth and session ownership are deferred to bff —
  see README TODO ledger).
- `bff/src/server/mod.rs` — `AppState::new(Config)` + `router(AppState)`, also exposed
  as `app(Config)` for tests. Owns `InMemorySessionStorage` (session_id →
  access/refresh token). The `http_client` has `redirect::Policy::none()` — needed so
  `/login` can read the raw `Location` header off backend's `/oauth/authorize` response
  instead of auto-following it.
- `bff/src/server/api/login.rs` — `start_login` forwards the caller's `redirect_uri`
  (the *final* browser destination; required, `400` if missing) to
  backend's `/oauth/authorize` unchecked; bff keeps no allowlist of its own.
  Backend's `400` (not allowlisted) is distinguished from other backend failures and
  surfaced as `400`, not the generic `502` — see the `reqwest::StatusCode::BAD_REQUEST`
  check before the redirection check. The whole PKCE exchange runs server-to-server
  inside this one request handler: `GET`s backend's `/oauth/authorize` (extracts
  `code` from the un-followed 303's `Location`), `POST`s backend's `/oauth/token`,
  mints a session, sets the `Set-Cookie` header directly (no cookie crate
  dependency), and only then replies to the browser with one 303 to the caller's
  `redirect_uri`. This relies on backend's `/oauth/authorize` having no interactive
  step; see README TODO ledger item 5.
- `bff/src/server/api/proxy.rs` — `.fallback(proxy)` in the router: any request not
  matching `/health` or `/login` is checked against `Config::routes` (longest
  `path_prefix` wins), the session cookie is resolved to an access token via
  `InMemorySessionStorage`, and the request is forwarded to `upstream_url` (prefix
  stripped) with `Cookie` dropped and `Authorization: Bearer <token>` set. `401` on
  missing/unknown session, `404` on no matching route.
- `login/src/lib.rs` — thin `app(Config) -> Router`: one `/login` handler that
  redirects into bff's `/login`, plus `ServeDir` over `login/static/`. No PKCE/reqwest
  logic here — that all lives in `bff`.
- `login/src/main.rs` — axum + tower-http `ServeDir` over `login/static/`. STATIC_DIR
  baked at compile time via `concat!(env!("CARGO_MANIFEST_DIR"), "/static")`; recompile
  needed only because the dir path is baked, not the HTML itself.
- `Dockerfile` — multi-stage: builds all three binaries, runtime runs them all via
  `entrypoint.sh`.

## Conventions

- `backend` and `bff` load an optional YAML overlay (`WA_CONFIG_FILE`, default bare
  `config.yaml` relative to cwd — see the cwd gotcha above) before env vars; env vars
  still win when set. New scalar config → add a field to `Config` + the crate's
  `FileConfig` + a row in `README.md`. Structured config with no sane env shape (bff's
  `routes`) is YAML-only.
- Custom environment variables are prefixed with `WA_`.
- In-memory storage (backend's PKCE store, bff's session store) follows the same idiom
  throughout: `Arc<Mutex<HashMap<...>>>`, "take"/remove-on-read for single-use records.

## Gotchas

- Docker must copy `/app/login/static` to the same absolute path the binary was built
  with (the static-dir root is baked from `CARGO_MANIFEST_DIR` at compile time).
- If a backend or bff route is added, update the route table in `README.md`.
- Backend must never be deployed with a public-facing listener/ingress — only bff and
  login are meant to be internet-exposed; a trusted internal service may reach backend
  directly, but backend itself is never safe to expose.
