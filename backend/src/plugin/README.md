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
not sandboxed.** Mounting one is equivalent to shipping application code,
and isolation beyond what's below is the deployer's (container, seccomp,
network policy). What WeaveAuth does enforce is the environment, a user
separate from its own, and the identity of both ends of the socket.

## The process lifecycle

- **Startup is synchronous.** `PluginProcess::start` spawns the command and
  calls the `weaveauth.startup` hook once, with `startup_timeout` as the
  deadline. Any answer the plugin gives, even a refusal, means it is serving.
  A missing binary, a plugin that exits immediately, and a plugin that never
  answers all fail `AppState::new`, so the server doesn't boot into a state
  where every registration 502s.
- **The connection is a socket pair, not an address.** `spawn` creates one,
  writes the token as its first line, and gives one end to the child as stdin.
  The channel's connector takes WeaveAuth's end out of a `PendingConnection`
  slot. The supervisor puts a fresh end there on every restart, so the
  channel is built once and reconnects on its own.
- **A supervisor task restarts the plugin when it dies**, after
  `RESTART_DELAY`. The call in flight fails; later ones recover. Without the
  delay a plugin that fails on startup would be respawned as fast as the OS can
  fork.
- **Concurrency is the plugin's.** One process serves every registration over
  one HTTP/2 connection, so a slow call doesn't block the next — there is no
  pool size to guess and nothing to lock.
- **Teardown.** `Drop` aborts the supervisor, which drops the `Child`
  (`kill_on_drop`).

Invariants worth not breaking:

- **The plugin inherits no environment.** `env_clear()`, then only what the
  deployer named for it: `WA_PLUGIN_<PLUGIN>_ENV_*` from this process's
  environment (prefix stripped by `forwarded_env`, which is scoped to one
  plugin name so a second surface doesn't inherit this one's credentials) and
  the config file's `env`. This process's environment holds WeaveAuth's signing
  keys, OIDC client secrets and database credentials.
- **Only WeaveAuth can reach the plugin.** There is no socket file, port or
  path: the two ends of the pair are held by this process and by the child
  alone, and WeaveAuth's end is close-on-exec, so no other child inherits it.
  That's what makes per-plugin users workable: no group or directory has to
  be shared with anyone.
- **Every call presents the plugin token**, a second layer behind the socket
  pair. It's generated per `PluginProcess` and written as the first line on
  every new connection, including after restarts, so the client never
  changes. It's sent as the `x-weaveauth-token` metadata key, and the SDK
  enforces it before a call reaches the plugin's own code.
- **The plugin runs as its configured `uid`/`gid`, never 0.** `start` refuses
  0, and `spawn` always sets both. Each hook defaults to its own id
  (registration 1001, login claims 1002), so plugins can't read WeaveAuth's
  memory and environment, or each other's. In the image, backend gets
  `CAP_SETUID`/`CAP_SETGID` as file capabilities (see the Dockerfile).
- **Every rpc carries the configured deadline** (`Request::set_timeout`), so a
  plugin that hangs fails the registration instead of holding the HTTP request
  open.

## Capabilities

There are none to grant, and nothing here to allowlist. A plugin reaches the
network, the filesystem and the machine exactly as any other process run by
its user does; WeaveAuth is not in a position to intercept any of it. The
security boundary is the deployer's own isolation, plus the invariants
above.

## Tests

| where | covers | needs |
| --- | --- | --- |
| `mod.rs` unit tests | startup failure modes, refusing uid/gid 0, applying the configured uid, the token's entropy, the `WA_PLUGIN_<PLUGIN>_ENV_` forwarding rule | — |
| `plugin-sdk/rust` unit tests, `plugin-sdk/go/serve_test.go` | the token check (unary and streaming) and reading the token line without consuming gRPC bytes, both SDKs | — |
| `system-tests/tests/plugin_connection.rs` | a real plugin process: served over its socket pair with the token, refused with no/wrong token, refusing to run without a socket on stdin or with an empty token | — |
| `system-tests/tests/plugin_process_flow.rs` | a real plugin process through backend's real `POST /register` (`hook: "registration"`): accept, reject, timeout, crash-and-restart, concurrency, environment isolation | — |
| `system-tests/tests/login_claims_flow.rs` | a real plugin process through backend's real PKCE flow (`hook: "login_claims"`): accept, reject, timeout, reserved-claim rejection, refresh grant | — |
| `system-tests/tests/plugin_postgres_flow.rs` | a plugin holding a `deadpool-postgres` pool across registrations | Docker, `--features docker` |
| `system-tests/tests/plugin_privsep_flow.rs` | the shipped image: the plugin runs as `wa-registration` and can't read backend's `/proc/<pid>/environ` | Docker, `mise run test-docker` (builds `system-tests/docker/Dockerfile.plugin-test` first) |

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
is warranted here (the environment rule, the token, the uid/gid rules and the
connection handover are the parts worth it):

```bash
mise run mutants -- -p weaveauth --file backend/src/plugin/mod.rs
```

Note it shares `~/.cargo-target-shared` with everything else, so a concurrent
`cargo test` will link against mutated artifacts and fail spuriously — use
`CARGO_TARGET_DIR=/tmp/…` while it runs.
