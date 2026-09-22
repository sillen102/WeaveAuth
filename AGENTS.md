# AGENTS.md

Agent guide for the WeaveAuth repo. Follow these conventions.

## Scope
- Applies to the entire repository unless a deeper `AGENTS.md` overrides it.
- Default implementation language is Rust. Use non-Rust services/tools only when the task explicitly targets them.

## Overview

Cargo workspace. The services: Axum backend (`backend/`, binary `weaveauth`, port
1983, **not exposed publicly**), the BFF (`bff/`, binary `weaveauth-bff`, port 8080 —
owns PKCE, the OAuth client role, and the session cookie), and an optional thin static
login page (`login/`, binary `weaveauth-login`, port 8081, just redirects into bff).
The rest are support crates: `common/` + `common/macros/` (shared models, the
`ErrorResponses` derive), `plugin-sdk/rust/` (the plugin gRPC contract, generated from
`plugin-sdk/proto/` — backend depends on it for the client side), and `system-tests/`
(cross-service tests, plus the probe plugins as bin targets). `plugin-sdk/go/` is a Go
module outside the Cargo workspace, built by its own mise tasks.

## Commands

- Workspace tests: `cargo test` (bff's PKCE/session flow: `bff/tests/pkce_flow.rs`;
  login's redirect: `login/tests/redirect_test.rs`; backend's are unit tests inline)
- Run everything: `mise run services` from the repo root. Each crate also has its own
  `mise.toml` (`dev`/`build`/`test`/`lint` tasks); `mise run dev` from inside a crate
  directory is equivalent to `cargo run` there — **the cwd matters**: `backend` and
  `bff` look for `config.yaml` as a bare relative path (see below), so `cargo run -p
  <crate>` from the repo root won't find it and silently falls back to hardcoded
  defaults instead of erroring.
- `cargo test` does **not** cover `plugin-sdk/go` (a separate Go module). `mise run
  test` does — use it after touching the plugin contract or the Go SDK.
- Full build: `cargo build --workspace --release`
- No linter/formatter is configured beyond `cargo clippy` (each crate's `mise.toml` has
  a `lint` task). Keep `cargo fmt`-style output manually.

## Coding Rules
- Formatting: use `rustfmt` with default settings.
- Lint: code must pass `cargo clippy` with default lints.
- Error handling: use `thiserror` to define error types; prefer `Result<T, MyError>` over panics.
  - **Layer separation**: Service/business-logic errors must NOT contain HTTP knowledge. Do NOT use `#[error_response(...)]` or import `StatusCode` in service modules. HTTP error mapping belongs in the controller/handler layer only.
  - **Pattern**: Define two error types per endpoint: (1) `XyzServiceError` in `service` module with only `#[derive(Debug, Error, ...)]`, (2) `XyzError` in `controller` module with `ErrorResponses` and `#[error_response(...)]` attributes. Implement `From<XyzServiceError> for XyzError` in controller to enable automatic conversion via `?` operator.
  - **Item order within a module**: top-down, public-first, types-before-consumers.
    - `controller`: imports, request struct(s), response struct, error enum, `_doc()` fn,
      then the handler fn last (it's the assembly of everything declared above it).
    - `service`: error enum first, then the public entry fn, then private helpers below
      it in call order.
- Avoid functions that return `bool` for a success/failure outcome; return `Result<T, MyError>` with an error enum instead, so callers can match on and log the actual failure reason.
- Async: use `async/await` with `tokio` runtime for IO-bound operations.
- Logging: use `tracing` for structured logging; avoid logging sensitive information.
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

- Run via `mise run mutants -- -p weaveauth` (backend's package name; or `-p
  weaveauth-bff`/`-p weaveauth-login`) from the repo root. Everything after `--` is
  forwarded straight to `cargo mutants`, so scope to one file with `--file
  backend/src/crypto.rs`, or a function/line with `--file ... --function name` /
  `--line N`, to keep a run fast. Don't try `CARGO_INCREMENTAL=1`: `~/.cargo/config.toml`
  sets `sccache` as the `rustc-wrapper`, which refuses to run incremental at all (also
  why root `Cargo.toml` has `profile.dev.incremental = false`); forcing it off via
  `RUSTC_WRAPPER=""` to allow incremental was tried and measured *slower* overall
  (loses sccache's cross-crate cache reuse, which mattered more than incremental's
  per-mutant savings) — not worth the complexity.
- It builds each mutant, runs the test suite, and reports mutants that survived (no
  test failed) vs. caught. A surviving mutant means a real gap in coverage.
- **"0 missed" is not "all covered".** A mutant reported *unviable* never had a test run
  against it -- it failed to build. In these crates that is common rather than rare:
  `deny(dead_code)`/`unused` means replacing a function body with a constant orphans the
  imports and constants it used, so the build fails first. Compare the unviable count
  against the previous run; if a mutant moved from missed to unviable rather than to
  caught, nothing was proven. Force it by hand (keep the orphaned bindings alive with a
  `let _ = ...`) and check the test actually fails.
- Likewise, a package-scoped run only runs **that package's** tests. Mutating
  `plugin-sdk/rust` reports its own `serve`/`Debug` mutants as missed even though
  `system-tests/tests/plugin_auth.rs` catches both -- confirm cross-package coverage by
  hand before treating one as a gap.
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
  test infrastructure — e.g. `Config::load`'s `>` vs `>=` at the bcrypt cost clamp
  boundary is a no-op either way (the clamped and unclamped value are identical at the
  boundary); `upgrade_bcrypt_to_argon2`'s `!=`/`==` on the `set_password` outcome only
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
- `backend/src/plugin/mod.rs` — `PluginProcess`: spawns the deployer's plugin binary as
  a child, waits for it to listen, supervises/restarts it, and calls it over gRPC on a
  unix socket. The contract is `plugin-sdk/proto`, generated by `plugin-sdk/rust`'s
  `build.rs` (protoc comes from `protoc-bin-vendored`, so no toolchain install). A
  plugin is **not sandboxed**; what is enforced is that it inherits no environment
  beyond `WA_PLUGIN_<PLUGIN>_ENV_*`/config `env`, and that every call carries a startup-generated
  token its SDK checks. See `backend/src/plugin/README.md`.
- `Dockerfile` — multi-stage: builds all three binaries, runtime runs them all via
  `entrypoint.sh`.

## Conventions

- `backend` and `bff` load an optional YAML overlay (`WA_CONFIG_FILE`, default bare
  `config.yaml` relative to cwd — see the cwd gotcha above) before env vars; env vars
  still win when set. New scalar config → add a field to `Config` + the crate's
  `FileConfig` + a row in `README.md`. Structured config with no sane env shape (bff's
  `routes`) is YAML-only.
- Custom environment variables are prefixed with `WA_`.
- Root `Cargo.toml`'s `[workspace.dependencies]` declares bare version numbers only, no
  features (e.g. `axum = "0.8"`, not `axum = { version = "0.8" }`). Each member crate
  declares the features it needs on its own `{ workspace = true, features = [...] }`
  line. Exception: `default-features = false` is part of the dependency's identity
  shared by every consumer, so it belongs on the root declaration (see `openidconnect`),
  not repeated per member.
- In-memory storage (backend's PKCE store, bff's session store) follows the same idiom
  throughout: `Arc<Mutex<HashMap<...>>>`, "take"/remove-on-read for single-use records.

## Gotchas

- Docker must copy `/app/login/static` to the same absolute path the binary was built
  with (the static-dir root is baked from `CARGO_MANIFEST_DIR` at compile time).
- If a backend or bff route is added, update the route table in `README.md`.
- Backend must never be deployed with a public-facing listener/ingress — only bff and
  login are meant to be internet-exposed; a trusted internal service may reach backend
  directly, but backend itself is never safe to expose.
- A unix socket path is capped near 104 bytes and macOS spends ~50 of them on
  `$TMPDIR`, so the plugin socket directory name is deliberately short
  (`wa-<12 hex>/s`). Lengthening it surfaces as every plugin failing to bind, which
  reads like a permissions or startup bug rather than a path-length one.
- `plugin-sdk/go` ships **no generated code** on purpose: `Serve` takes a
  `func(*grpc.Server)` and the plugin author registers their own stubs. Don't reintroduce
  checked-in `.pb.go` here -- it drifts from the `.proto` with nothing to catch it, and
  `protoc-gen-go` 1.36+ writes `unsafe` into it. The Rust SDK generates in `build.rs`
  instead, so it can't go stale.
- Toggling `RUSTC_WRAPPER`/`CARGO_INCREMENTAL` between builds (e.g. experimenting with
  disabling sccache) can leave `sccache` serving a stale/corrupted cached object for a
  later build with the *same* env — surfaces as unrelated tests failing or passing
  inexplicably, and disappears if you rebuild with `RUSTC_WRAPPER=""`. Fix by clearing
  the cache directory (`sccache --show-stats` prints its `Cache location`, e.g.
  `~/Library/Caches/Mozilla.sccache` on macOS) rather than debugging the "failure" as a
  code issue.
