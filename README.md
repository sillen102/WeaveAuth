# WeaveAuth

Lightweight Backend-for-Frontend (BFF) with OAuth2 capabilities.

A Cargo workspace with three Rust binaries: an Axum backend, a static login page,
and a Topcoat admin tool.

## Architecture

Cargo workspace (`backend/` + `frontend/` + `login/`), three binaries:

- **`weaveauth`** (Axum, backend) — `:1983`. API + OAuth2 logic. CORS is env-configurable.
- **`weaveauth-login`** (axum + `ServeDir`, static) — `:8080`. Pure HTML/CSS login page.
- **`weaveauth-frontend`** (Topcoat, admin tool) — `:1984`. No admin pages implemented yet; its `#[page("/")]` route still renders a transitional login page.

Login routes:

| Method | Path                | Returns                                |
|--------|---------------------|----------------------------------------|
| GET    | `/`                 | Login page (`login/static/index.html`) |
| GET    | `/static/style.css` | Stylesheet (`login/static/style.css`)  |

Backend routes:

| Method | Path                  | Returns                      |
|--------|-----------------------|------------------------------|
| GET    | `/health`             | `ok`                         |
| GET    | `/api/v1/auth/status` | `{ "authenticated": false }` |

`/oauth/...` routes are reserved for the upcoming OAuth2 flow. The login page's sign-in
link is hard-coded to the backend `/oauth/login` for now (full-page navigation, no
cross-origin fetch).

## Prerequisites

- Rust (stable) — `cargo` on PATH. No Node required.

## Development

Terminal 1 — backend:

```bash
cargo run -p weaveauth
```

Terminal 2 — login (static page, opens http://localhost:8080):

```bash
cargo run -p weaveauth-login
```

Terminal 3 — admin (frontend):

```bash
cargo run -p weaveauth-frontend
```

Open http://localhost:1984 for the transitional login route served by the admin tool.
Open http://localhost:8080 for the real login page.

## Configuration (environment variables)

| Variable               | App      | Default                             | Description                                              |
|------------------------|----------|-------------------------------------|----------------------------------------------------------|
| `PORT`                 | backend  | `1983`                              | Backend listen port                                      |
| `PORT`                 | login    | `8080`                              | Login page listen port                                   |
| `PORT`                 | frontend | `1984`                              | Admin listen port                                        |
| `CORS_ORIGINS`         | backend  | `http://localhost:1984`             | Comma-separated allowed origins                          |
| `CLAIM_ENRICHMENT_URL` | backend  | *(unset)*                           | Optional upstream claim-enrichment endpoint (unused yet) |
| `OAUTH_LOGIN_URL`      | frontend | `http://localhost:1983/oauth/login` | URL the "Sign in" link redirects to                      |

## Testing

```bash
cargo test
```

Runs the workspace tests; backend integration tests live in `backend/tests/api_test.rs`.

## Docker

Single multi-stage `Dockerfile` at repo root. The `rust:1.98-slim` builder compiles all
three binaries (`--release -p weaveauth -p weaveauth-frontend -p weaveauth-login`); the
`debian:bookworm-slim` runtime copies the three binaries plus `/app/login/static` and
`entrypoint.sh`, which launches all three processes.

```bash
docker build -t weaveauth .
docker run -p 1983:1983 -p 8080:8080 -p 1984:1984 weaveauth
```

## License

Apache License 2.0. Copyright 2026 Silvio Sabo.
