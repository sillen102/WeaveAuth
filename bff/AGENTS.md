# AGENTS.md (bff)

Applies to `bff/`. Overrides the repo-root `AGENTS.md` where the two disagree.

## Vertical slice architecture

Each endpoint lives in its own file under `src/server/api/` (`health.rs`, `login.rs`,
`register.rs`, `proxy.rs`, ...). A file is the full slice for that endpoint: request/response
types, the handler, and its tests, all in one place. Nothing about one endpoint's
request/response shape or test setup belongs in another endpoint's file, and none of it
belongs in a shared `dtos.rs`/`handlers.rs`/`tests.rs` split by *kind* instead of by
*feature*.

Concretely, each endpoint file follows this shape:

```rust
pub(crate) use controller::the_handler;

mod controller {
    // extractors, request/response structs, the handler fn
    pub(crate) async fn the_handler() -> String {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::controller::*;
    // unit tests for this handler only
}
```

Most bff handlers aren't part of a documented public API surface, so the shape above is
just `controller` + `tests`, with no aide `_doc()` companion function. An endpoint can add
one (like `register.rs`'s `start_register_doc`) when it's worth documenting via
aide/OpenAPI, the same way `backend/` does it -- see "Documented routes" below for how
they get mounted. Add a `service` or `repository` submodule next to `controller` only
once a slice actually grows business logic or storage access beyond what the handler itself
does inline (`login.rs` and `proxy.rs`, for instance, stay a single `controller` module
because there's nothing to split out yet).

`tests` is a sibling of `controller`, not nested inside it, so it can cover the whole file
once it does grow beyond a single module. Request/response struct fields that tests need to
set directly are declared `pub(super)` (visible to the whole file, including `tests`)
instead of `pub(crate)` or public -- no need for public constructors or `#[cfg(test)]`-only
accessors just to be testable. The same goes for private helper functions a sibling `tests`
module needs to reach, like `proxy.rs`'s `is_hop_by_hop` and `extract_cookie`.

This mirrors the pattern already used elsewhere in the crate for non-endpoint code:
`config.rs`, `origin_check.rs`, and `storage/in_memory.rs` each keep their own
`#[cfg(test)] mod tests` colocated with the code under test rather than centralizing tests
by module type.

Most handlers here call out to backend over HTTP via `reqwest`, rather than a swappable
storage trait -- so a colocated unit test can only cheaply cover behavior that doesn't
require a live upstream (e.g. an untrusted `Origin` being rejected before any backend call
is made). Call the handler function directly (`start_login(State(state), headers,
Form(req)).await`), constructing `AppState` via `AppState::new(Config { .. })` by hand, no
HTTP parsing involved.

## Error handling

Same pattern as `backend/`: each handler's fallible path is its own `thiserror`-derived
enum (`LoginError`, `RegisterError`, `ProxyError`, ...), declared in the endpoint's own
file. One variant per distinct failure reason, not one per status code --
`#[error_response(StatusCode::X, details = "...")]` on each variant maps it to an HTTP
status and a human-readable `details` string; several variants may share a status code
when the reason (the variant name) is what actually disambiguates them.

`#[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]` (from `common_macros`) generates
`IntoResponse` (a JSON body via `common::responses::ErrorResponse`). An error enum for an
undocumented endpoint carries `#[error_response_no_openapi]`, which skips the macro's
`aide::OperationOutput` codegen; drop that attribute for an endpoint that has a `_doc()`
function (like `register.rs`'s `RegisterError`). Handlers return `Result<T, MyError>`
directly; map fallible calls
(`require_trusted_origin`, `reqwest` sends, upstream response parsing, ...) to a variant
with `.map_err(|_| MyError::Whatever)` or `.ok_or(...)` at the call site instead of
bubbling up a raw `StatusCode`. Tests assert against the enum variant (`result.err()`,
`Some(MyError::Whatever)`), never against a bare `StatusCode`.

## Documented routes

A documented endpoint needs an `ApiRouter`, not a plain `Router` -- only the former carries
aide's operation metadata. `router.rs` builds those routes separately and runs them through
`common::docs::api_docs::api_docs_router`, the same helper `backend/` uses, which returns
the routes plus a docs router serving `/docs`, `/docs/scalar.js` and `/openapi.json`.

Two things about that docs router are load-bearing:

- It is merged only when `Config::docs_enabled` (`WA_DOCS_ENABLED`) is set, and defaults to
  off. bff is the internet-facing service and these endpoints are an unauthenticated
  description of the auth surface, so a deployment opts in. Gating covers only the
  schema-publishing endpoints -- documented routes stay mounted either way, so the flag
  never changes how the API itself behaves (`bff/tests/docs.rs` pins this down).
- It gets its own governor bucket, separate from the auth and proxy ones. Doc fetches are
  cheap and repeated by tooling, so sharing the auth bucket would let them starve real
  login/register attempts.

Documented routes share the auth governor instance rather than building their own, so
pulling an endpoint into its own `ApiRouter` doesn't hand it a second rate-limit budget.

## Where HTTP-level tests still go

`tests/*.rs` (`pkce_flow.rs`, `register.rs`, `proxy.rs`) cover the same endpoints
end-to-end through the real router (`weaveauth_bff::server::app`), each spinning up an
in-process stub backend/upstream server -- request parsing, routing, rate limiting, and the
full server-to-server login/authorize/token exchange. Keep that directory for behavior that
only shows up when the whole stack (including a real backend round-trip) is wired together;
anything that can be exercised by calling the handler function directly, without a network
call actually completing, belongs in the endpoint file's own `tests` module instead of being
duplicated there.
