# `plugin` — the plugin runtime

A deployer mounts an executable; WeaveAuth runs it as a child process and calls
it over gRPC at a point in a flow. This module owns the process, the socket
the two talk over, and the one generic `Invoke` rpc every hook shares. It
knows nothing about what a plugin is *for* — registration and login claims are
just its callers, and the JSON payload each one sends/reads is theirs to
shape, not this module's.

Deployer-facing docs live in [`docs/plugins.md`](../../../docs/plugins.md).
This file is for working on WeaveAuth itself.

| file | holds |
| --- | --- |
| `mod.rs` | `PluginProcess` — spawn, wait for readiness, supervise, call; also `json_to_struct`/`struct_to_json`, the JSON ⇄ `google.protobuf.Struct` conversion every hook's payload goes through |
| [`plugin-sdk/proto`](../../../plugin-sdk/proto/) | the one generic `Invoke` rpc; a new flow is a new `hook` value, not a proto change |

## Calling a plugin from a flow

```rust
let request = PluginRequest { hook: "registration".to_string(), user_id, email, data: Some(data) };
let response = plugin.invoke(request).await?;
```

`Ok` accepts/succeeds; any `tonic::Status` rejects/fails. A flow maps that
status onto its own error type — don't leak it into an HTTP response.
`response.data` (a `google.protobuf.Struct`) carries whatever the hook returns
-- `None` for a hook that only accepts/rejects, like registration.

Wiring a plugin into a second flow is **a new `hook` name**, not a new rpc or a
new runtime: `PluginProcess::invoke` is generic over every hook, so a flow only
needs to build the right `PluginRequest` and interpret the right `data` shape
back. `crate::server::api::register` and `crate::server::api::token` are the
two callers today, each with its own handler trait
(`ExtraDataHandler`/`LoginClaimsHandler`) and `Process`/`Webhook`
implementations living in that endpoint's own file, per the vertical-slice
rule in `backend/AGENTS.md` -- this module only owns the process/gRPC
mechanics shared by every hook.

## Why a process

A plugin is a native binary. That is the whole point: it keeps its own async
runtime, its own connection pools, its own TLS stack and whatever crates it
likes — `deadpool`, `sqlx`, `lapin`, a vendor SDK. WeaveAuth holds none of
that on its behalf, which is what a plugin talking to Postgres needs and what
an in-process sandbox cannot give without reimplementing every protocol as a
host capability.

The price is stated plainly in the deployer docs and again here: **a plugin is
not sandboxed.** It runs with this process's privileges. Mounting one is
equivalent to shipping application code, and isolation is the deployer's
(container, user, seccomp). The one boundary WeaveAuth does enforce is the
environment.

## The process lifecycle

- **Startup is synchronous.** `PluginProcess::start` spawns the command and
  polls the socket until the plugin accepts a connection. A missing binary, a
  plugin that exits immediately, and a plugin that never listens all fail
  `AppState::new`, so the server doesn't boot into a state where every
  registration 502s.
- **The socket path is fixed for the life of the `PluginProcess`.** That's what
  lets the tonic `Channel` be built once and connect lazily: after a restart it
  reconnects to the same path on its own, with no invalidation logic anywhere.
- **A supervisor task restarts the plugin when it dies**, after
  `RESTART_DELAY`. The call in flight fails; later ones recover. Without the
  delay a plugin that fails on startup would be respawned as fast as the OS can
  fork.
- **Concurrency is the plugin's.** One process serves every registration over
  one HTTP/2 connection, so a slow call doesn't block the next — there is no
  pool size to guess and nothing to lock.
- **Teardown.** `Drop` aborts the supervisor, which drops the `Child`
  (`kill_on_drop`), then removes the socket directory.

Invariants worth not breaking:

- **The plugin inherits no environment.** `env_clear()`, then only what the
  deployer named for it: `WA_PLUGIN_<PLUGIN>_ENV_*` from this process's
  environment (prefix stripped by `forwarded_env`, which is scoped to one
  plugin name so a second surface doesn't inherit this one's credentials), the
  config file's `env`, and the two channel variables. This process's environment holds WeaveAuth's signing
  keys, OIDC client secrets and database credentials.
- **Every call presents `WA_PLUGIN_TOKEN`.** Generated per `PluginProcess`,
  handed to the child on every spawn (including restarts, so the client never
  changes), sent as the `x-weaveauth-token` metadata key. The SDK enforces it
  before a call reaches the plugin's own code. It guards against the socket
  directory's permissions being wrong, and it is what would make a future TCP
  transport safe -- it is *not* a boundary against a hostile plugin, which
  runs as this user and can read the token from `/proc`.
- **The socket lives in a `0700` directory.** Anyone who can open it can drive
  the plugin, and through it whatever credentials the deployer gave it. The
  directory name is deliberately short: a unix socket path is capped around 104
  bytes and macOS spends half of that on `$TMPDIR`.
- **Every rpc carries the configured deadline** (`Request::set_timeout`), so a
  plugin that hangs fails the registration instead of holding the HTTP request
  open.

## Capabilities

There are none to grant, and nothing here to allowlist. A plugin reaches the
network, the filesystem and the machine exactly as any other process run by
this user does; WeaveAuth is not in a position to intercept any of it. The
security boundary is the deployer's own isolation, plus the environment rule
above.

## Tests

| where | covers | needs |
| --- | --- | --- |
| `mod.rs` unit tests | startup failure modes, the private socket directory, the `WA_PLUGIN_<PLUGIN>_ENV_` forwarding rule | — |
| `plugin-sdk/rust` unit tests, `plugin-sdk/go/serve_test.go` | the token check, both SDKs | — |
| `system-tests/tests/plugin_auth.rs` | a caller with no/wrong token refused against a real plugin process | — |
| `system-tests/tests/plugin_process_flow.rs` | a real plugin process through backend's real `POST /register` (`hook: "registration"`): accept, reject, timeout, crash-and-restart, concurrency, environment isolation | — |
| `system-tests/tests/login_claims_flow.rs` | a real plugin process through backend's real PKCE flow (`hook: "login_claims"`): accept, reject, timeout, reserved-claim rejection, refresh grant | — |
| `system-tests/tests/plugin_postgres_flow.rs` | a plugin holding a `deadpool-postgres` pool across registrations | Docker, `--features docker` |

The probe plugins are bin targets of the `weaveauth-system-tests` package
(`tests/fixtures/plugins/`), built from
[`plugin-sdk/rust`](../../../plugin-sdk/) — so the SDK is covered too, which
is otherwise the one part of this feature nothing would exercise.

```bash
cargo test                  # unit + the process system tests
mise run test-docker        # adds the real Postgres layer
```

A change to the contract should show up in all three. Both SDKs pick it up on
their own -- Rust regenerates in `build.rs`, and the Go SDK ships no generated
code at all (the plugin author generates from `plugin-sdk/proto`).

## Mutation testing

Not part of the per-change loop — see the repo `AGENTS.md`. When a deeper pass
is warranted here (the environment rule, the token, and the socket directory
mode are the parts worth it):

```bash
mise run mutants -- -p weaveauth --file backend/src/plugin/mod.rs
```

Note it shares `~/.cargo-target-shared` with everything else, so a concurrent
`cargo test` will link against mutated artifacts and fail spuriously — use
`CARGO_TARGET_DIR=/tmp/…` while it runs.
