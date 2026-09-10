# AGENTS.md

Agent guide for the WeaveAuth repo. Follow these conventions.

## Overview

Cargo workspace BFF with three members: Axum backend (`backend/`, binary `weaveauth`),
static login page (`login/`, binary `weaveauth-login`), and Topcoat admin tool
(`frontend/`, binary `weaveauth-frontend`). OAuth2 flow is planned but not yet
implemented — `/oauth/...` routes and the `reqwest`/`jsonwebtoken` deps are reserved for it.

## Commands

- Backend tests: `cargo test` (root workspace; backend tests live in `backend/tests/api_test.rs`)
- Backend run: `cargo run -p weaveauth`
- Login run: `cargo run -p weaveauth-login` — serves static files from `login/static/` on `WA_LOGIN_PORT`, default 8080
- Frontend run: `cargo run -p weaveauth-frontend` (admin tool, default port 1984)
- Full build: `cargo build --workspace --release`
- No linter/formatter is configured for either side yet. Keep `cargo fmt`-style output manually.

## Architecture

- Root `Cargo.toml` is a virtual workspace: `members = ["backend", "frontend", "login"]`.
- `backend/src/lib.rs` — `app()` builder. Router with `TraceLayer`. **Tests hit the
  builder directly via `tower::ServiceExt::oneshot`** — do not test via `main.rs`.
- `backend/src/config.rs` — `Config::load()` reads `WA_PORT`, `WA_CORS_ORIGINS` (comma-separated),
  `WA_CLAIM_ENRICHMENT_URL` from env with defaults. Extend this struct when new config appears.
- `backend/src/main.rs` — startup only: config → tracing → `axum::serve` on `0.0.0.0:WA_PORT`.
- `frontend/src/main.rs` — Topcoat admin tool `#[page("/")]`, served by
  `topcoat::start(Router::builder().discover().build())`. Currently transitional: no
  admin pages yet, the route still renders a login page. The sign-in link is an `<a>`
  redirect to the backend `/oauth/login` (from `WA_OAUTH_LOGIN_URL` env). Topcoat listens
  on `WA_ADMIN_PORT` env (passed through to topcoat's internal `PORT`); default 1984.
- `login/src/main.rs` — axum + tower-http `ServeDir` over `login/static/`. STATIC_DIR
  baked at compile time via `concat!(env!("CARGO_MANIFEST_DIR"), "/static")`. Pure
  HTML/CSS files; the sign-in href is hard-coded to the backend `/oauth/login`. Edit
  `login/static/index.html` + `login/static/style.css` for the login page; recompile is
  only needed because the dir path is baked, the HTML itself is not compiled.
- `Dockerfile` — multi-stage: builds all three binaries, runtime runs them all via `entrypoint.sh`.

## Conventions

- **TDD:** write/adjust `backend/tests/api_test.rs` first for any backend behavior, then
  implement. Tests must pass before committing.
- No comments unless they add non-obvious context.
- Keep changes minimal and localized; prefer the shortest working change.
- Config uses env vars only — no config files. New env vars → add field to
  `Config` (backend) + a row in `README.md`.
- `&str`-typed errors/JSON via `axum::Json<serde_json::Value>` are the current pattern.

## Gotchas

- Topcoat 0.8 is early-stage/experimental; `view!` macro code lives in
  `frontend/src/main.rs` — expect breaking changes on upgrade.
- npm/Vite/Tailwind/React notes are obsolete — Node is gone, do not reintroduce it.
- Three ports: backend 1983, login 8080, admin/frontend 1984.
- Docker must copy `/app/login/static` to the same absolute path the binary was built
  with (the static-dir root is baked from `CARGO_MANIFEST_DIR` at compile time).
- If a backend route is added, update the route table in `README.md`.