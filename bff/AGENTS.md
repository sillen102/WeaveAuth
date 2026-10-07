# AGENTS.md (bff)

Applies to `bff/`. Overrides the repo-root `AGENTS.md` where the two disagree.

## Two listeners

bff serves a **public** router (`public_router`: `/login`, `/callback`, `/logout`, `/logged-out`, `/health` and the proxied
routes) on `port`, and an **internal** router (`internal_router`: `/backchannel-logout`,
`/internal/revoke`) on `internal_port`. The internal one is never routed publicly: Hydra and hooks
reach it directly. Neither route may be added to the public router. `weaveauth_bff::server::apps(config)`
builds both over one state for tests.

`src/hydra/` is bff's side of Hydra: the OAuth2 client calls (token, refresh, revocation, with
`client_secret_basic` against `hydra_internal_url`), the URLs the browser is sent to
(`hydra_public_url`), the JWKS cache (refetched on an unknown `kid` and once an hour, single-flight, at most one fetch
per interval) and the verification of what Hydra signs, RS256 only: the id_token (`openidconnect`) and the
back-channel logout token (`jsonwebtoken`, plus the claim checks of Back-Channel Logout 1.0). Handlers
call it through `AppState::hydra`.

## Vertical slice architecture

Each endpoint lives in its own file under `src/server/api/` (`login.rs`, `callback.rs`, `logout.rs`,
`backchannel_logout.rs`, `internal_revoke.rs`, `proxy.rs`, ...). A file is the full slice for that
endpoint: request/response types, the handler, its service logic and its tests, all in one place.
Nothing about one endpoint's request/response shape or test setup belongs in another endpoint's
file, and none of it belongs in a shared `dtos.rs`/`handlers.rs`/`tests.rs` split by *kind* instead
of by *feature*. What several endpoints share is protocol state or a collaborator, not a slice, and
lives beside `api/`: `hydra/`, `login_cookie.rs` (what `/login` hands `/callback`), `refresh_lock.rs`,
`cookie.rs`, `origin_check.rs`, `secrets.rs`.

Concretely, each endpoint file follows the repo-wide `controller` / `service` split (see the root
`AGENTS.md`), plus a sibling `tests` module:

```rust
pub(crate) use controller::the_handler;

mod controller {
    // extractors, request struct(s), the error enum, then the handler fn last
}

mod service {
    // the service error enum, then the entry fn and its helpers; no HTTP types
}

#[cfg(test)]
mod tests {
    use super::controller::*;
    // unit tests for this endpoint only
}
```

`tests` is a sibling of `controller`, not nested inside it. Request/response struct fields that tests
need to set directly are declared `pub(super)` (visible to the whole file, including `tests`)
instead of `pub(crate)` or public. A slice that has nothing to split (`health.rs`) stays a single
`controller` module.

Handlers call out to Hydra over HTTP, so a colocated unit test can only cheaply cover behavior that
doesn't need a live Hydra (an off-list `redirect_uri` rejected before any call is made, the
constant-time key check). Call the handler or service function directly, constructing `AppState` via
`AppState::new(Config { .. })` by hand, no HTTP parsing involved.

## Error handling

Each handler's fallible path is its own `thiserror`-derived enum (`LoginError`, `LogoutError`,
`ProxyError`, ...), declared in the endpoint's own file. One variant per distinct failure reason, not
one per status code -- `#[error_response(StatusCode::X, details = "...")]` on each variant maps it to an
HTTP status and a fixed, generic `details` string; several variants may share a status code when the
reason (the variant name) is what actually disambiguates them. The cause (Hydra's status, the failing
check) lives in the service error and in the log, never in the response.

Take request input with `common::extract::{ApiJson, ApiForm, ApiQuery, ApiPath}`, never
axum's `Json`/`Form`/`Query`/`Path`: those reject with a plain-text body, while the `Api*`
wrappers reject with the same JSON `ErrorResponse` (`reason: "InvalidRequest"`) as every
other error.

`#[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]` (from `common_macros`) generates
`IntoResponse` (a JSON body via `common::model::error_response::ErrorResponse`). Tests assert against the enum
variant (`result.err()`, `Some(MyError::Whatever)`), never against a bare `StatusCode`, when they
call the handler directly.

## Where HTTP-level tests go

`tests/*.rs` cover the same endpoints end-to-end through the real routers (`weaveauth_bff::server::apps`),
against the stub Hydra in `tests/support/mod.rs`: a real in-process token, revocation and JWKS endpoint
that checks the client's `Authorization: Basic`, the PKCE verifier, single-use codes and refresh-token
rotation (presenting a spent refresh token revokes the chain, as Hydra does). `login_flow.rs`,
`logout.rs`, `logged_out.rs`, `refresh.rs` (single-flight, rotation, failures), `backchannel_logout.rs`,
`internal_revoke.rs` and `proxy.rs` each own one feature. Keep that directory for behavior that only
shows up when the whole stack is wired together -- request parsing, routing, rate limiting, the full
server-to-server exchange; anything that can be exercised by calling a handler or service function
directly belongs in the endpoint file's own `tests` module.

`tests/fixtures/` holds a throwaway RSA key pair standing in for Hydra's signing key (and a second one
Hydra does not publish, for forged tokens). `src/test_support.rs` is the same for the unit tests.
