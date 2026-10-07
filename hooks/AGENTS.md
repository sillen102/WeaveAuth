# AGENTS.md (hooks)

Applies to `hooks/`. Overrides the repo-root `AGENTS.md` where the two disagree.

hooks is the small internal service Kratos and Hydra call as web hooks. It is **never**
exposed publicly. Every route but `/health` requires `Authorization: Bearer <WA_HOOKS_API_KEY>`
and has a request timeout; a new route goes behind both (`server/router.rs`).

## Vertical slice architecture

Each route lives in its own file under `src/server/api/`. A file is the full slice: request
type, response type, error enums, handler, and the `service` module with the logic. Shared
pieces sit beside them: `revocation.rs` (what after-recovery and after-password-change have in
common), `clients/` (Kratos admin, Hydra admin, bff), `webhook.rs` (the deployer's webhooks),
`profile_api.rs`.

```rust
pub(crate) use controller::the_handler;

mod controller {
    // request/response structs, the controller error, From<ServiceError>, the handler fn
}

mod service {
    // the service error, the public entry fn, private helpers in call order
}
```

Handlers call `service` and convert its error with `?`. Take input with `common::extract::ApiJson`.
Identity and session ids are `Uuid` in the request type: they end up in upstream URL paths, so
nothing that isn't a UUID may get that far.

## Error handling

- The service error carries the cause (`UpstreamError`, `WebhookError`, a `String`); the
  controller error derives `ErrorResponses` and
  carries nothing. The response's `details` is the variant's `details = "..."` argument, else
  its `#[error("...")]` text, so it is a fixed sentence, never derived from a cause; a controller
  variant that carries data without `details` doesn't compile.
- `From<ServiceError> for ControllerError` logs the cause once and drops it. Code that swallows
  an error instead of returning it (the rollback delete in `after_registration.rs`) logs it there.
- Routes Kratos calls (`after-registration`, `after-recovery`, `after-password-change`) answer
  with `KratosHookError`: Kratos aborts the flow on any non-2xx and shows its own error page (the
  `messages` never reach the browser), retrying 5xx three times. The identity is already stored by
  then, so a refusal also deletes it. Use 4xx for "this registration is refused" or a failure a
  retry can't fix (Kratos doesn't retry 4xx: an identity a failed attempt deleted answers `410`),
  5xx for "something upstream is down". Work that has to finish after a failure (the delete, the
  Hydra and bff revocations) runs inside its own share of `request_timeout`, never after the
  `TimeoutLayer` could cancel it. Hydra aborts the token exchange on any non-2xx and retries
  what isn't a 403, so a deterministic refusal (inactive identity, unverified email, reserved
  claim) is a 403.
- `require_verified_email` (default `true`) makes the token hook refuse an identity whose email
  Kratos hasn't verified, whatever path got it to Hydra. A deployment that lets unverified
  identities sign in on purpose (the `session-on-registration.yml` overlay) sets it `false`.
- A webhook refuses with 400, 403 or 422 only: those are a "no" (a rejected registration). Any
  other status (a 401 from a rotated token, a 404, a 429) is a failure that is logged and answered
  as 5xx; a failed registration webhook also deletes the identity. The claims webhook is told the
  `client_id` and granted `scopes` with every call.
- The registration webhook can be called again for an identity whose first attempt timed out
  or was cancelled (hooks deletes the identity then, but the deployer may already hold a
  record, and a retry can overlap the first attempt). The deployer's endpoint must be
  idempotent per `user_id`, and its `timeout_secs` stays within half of `request_timeout_secs`
  (checked at startup), below the time Kratos waits for the hook.
- Revocation (after-recovery, after-password-change) ends everything even when a step fails:
  Kratos first (credentials, sessions, credentials again, so a session that was still alive
  can't have added one in between; one failing session doesn't stop the others), then Hydra's
  consent and login sessions and bff together, each inside its own share of `request_timeout`.
  `upstream_timeout_secs` must stay under half of `request_timeout_secs`.
- Webhook and provider API answers are read through `webhook::read_limited` (1 MiB). Neither a configured
  URL nor a bearer token goes into a log line or error: name the setting, or log the host and path.
- Fail closed: a claims webhook that errors, a Kratos lookup that fails, a claim named like one
  the token already carries (`RESERVED_CLAIM_NAMES`) -> no token.
- A password only ever lives in a `SecretString`; never format it into a log line or a response.

## Tests

`tests/` is HTTP-level: the real router (`weaveauth_hooks::server::app`) driven in-process
against stub Kratos, Hydra, bff and webhook servers on `127.0.0.1:0` (`tests/support/mod.rs`).
The stubs record every call into one log, so a test can assert what was called and in which
order across services. Unit tests for a single function stay inline in its file.

`tests/password_not_logged.rs` is a binary of its own on purpose: a log-capturing subscriber
misses events when other tests in the process hit the same `tracing` callsites first.
