# AGENTS.md (backend)

Applies to `backend/`. Overrides the repo-root `AGENTS.md` where the two disagree.

## Vertical slice architecture

Each endpoint lives in its own file under `src/server/api/` (`health.rs`, `authorize.rs`,
`login.rs`, `token.rs`, ...). A file is the full slice for that endpoint: request/response types,
the handler, its OpenAPI `doc()`, and its tests, all in one place. Nothing about one
endpoint's request/response shape or test setup belongs in another endpoint's file, and
none of it belongs in a shared `dtos.rs`/`handlers.rs`/`tests.rs` split by *kind* instead
of by *feature*.

Concretely, each endpoint file follows this shape:

```rust
pub(crate) use controller::the_handler;
pub(crate) use controller::the_handler_doc;

mod controller {
    // extractors, request/response structs, the_handler_doc(), the handler fn
    
    /// OpenAPI documentation for this endpoint.
    pub(crate) fn the_handler_doc() -> String {
        todo!()
    }
    
    /// Handler for this endpoint.
    pub(crate) fn the_handler() -> String {
        todo!()
    }
}

mod service {
    // business logic, calls into storage
}

mod repository {
    // storage logic, calls into database
}

#[cfg(test)]
mod tests {
    use super::controller::*;
    // unit- and integration tests for this handler only
}
```

`tests` is a sibling of `controller`, not nested inside it, because a file's slice will
grow beyond just a controller (e.g. a `service` or `repository` module next to it) and
`tests` covers the whole file, not one module in it. Tests call the handler function
directly (`the_handler(State(state), Query(req)).await`) rather than going through the
router — construct `AppState` and the request struct by hand, no HTTP parsing involved.
Request/response struct fields that tests need to set directly are declared
`pub(super)` (visible to the whole file, including `tests`) instead of `pub(crate)` or
public — no need for public constructors or `#[cfg(test)]`-only accessors just to be
testable.

This mirrors the pattern already used elsewhere in the crate for non-endpoint code:
`config.rs`, `model/pkce.rs`, and `storage/in_memory.rs` each keep their own
`#[cfg(test)] mod tests` colocated with the code under test rather than centralizing
tests by module type.

## Error handling

Each handler's fallible path is its own `thiserror`-derived enum (`AuthorizeError`,
`LoginError`, `TokenError`, ...), declared in the endpoint's own file next to its
request/response types. One variant per distinct failure reason, not one per status code
-- `#[error_response(StatusCode::X, details = "...")]` on each variant maps it to an HTTP
status and a human-readable `details` string; several variants may share a status code
(see `authorize.rs`'s `InvalidLoginSession` / `InvalidRedirectUri`, both 4xx but distinct
reasons) since `reason` (the variant name) is what actually disambiguates them for callers.

`#[derive(Debug, Error, ErrorResponses, Eq, PartialEq)]` (from `common_macros`) generates
both `IntoResponse` (a JSON body via `common::responses::ErrorResponse`, or an overridden
`#[error_response_type(...)]`) and `aide::OperationOutput`, so the handler's `Result<T,
MyError>` return type alone documents every possible error response in the generated
OpenAPI spec -- no separate response-type bookkeeping in `..._doc()`. Handlers return
`Result<T, MyError>` directly; map internal fallible calls (`spawn_blocking`, storage
lookups, ...) to a variant with `.map_err(|_| MyError::Whatever)` or `.ok_or(...)` at the
call site instead of bubbling up raw error types. Tests assert against the enum variant
(`result.err()`, `Some(MyError::Whatever)`), never against a bare `StatusCode`.

## Where HTTP-level tests still go

`tests/api_test.rs` covers the same endpoints end-to-end through the real router
(`weaveauth::server::app`) — request parsing, routing, and cross-endpoint flows (e.g.
issuing a code via `/oauth/authorize` and redeeming it via `/oauth/token`). Keep that
file for behavior that only shows up when the whole stack is wired together; anything
that can be exercised by calling the handler function directly belongs in the endpoint
file's own `tests` module instead of being duplicated there.
