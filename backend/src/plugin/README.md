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
back. `crate::server::api::register`, `crate::server::api::token` and
`crate::server::api::email_verification` are the three callers today, each with its own
handler trait (`ExtraDataHandler`/`LoginClaimsHandler`/`EmailVerificationHandler`) and `Plugin`/`Webhook`
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
  where every registration 502s. Telling the plugin's answer apart from a
  transport failure relies on tonic 0.14 giving only the latter a
  `source()`; `a_status_the_plugin_sent_has_no_source` and
  `a_status_from_this_side_has_a_source` pin that, so a tonic upgrade that
  changes it fails there rather than at startup.
- **The connection is a socket pair, not an address.** `spawn` creates one,
  writes the token as its first line, and gives one end to the child as stdin.
  The channel's connector takes WeaveAuth's end out of a `PendingConnection`
  slot. The supervisor puts a fresh end there on every restart, so the
  channel is built once and reconnects on its own.
- **A supervisor task restarts the plugin when it dies**, after
  `RESTART_DELAY`. The call in flight fails; later ones recover. Without the
  delay a plugin that fails on startup would be respawned as fast as the OS can
  fork. A broken connection counts as dying: the SDKs stop serving when it
  closes, so the process exits and gets a fresh pair.
- **Concurrency is the plugin's.** One process serves every registration over
  one HTTP/2 connection, so a slow call doesn't block the next — there is no
  pool size to guess and nothing to lock.
- **Teardown is the connection closing.** `Drop` aborts the supervisor and
  drops the channel, which closes WeaveAuth's end, and the SDK then stops the
  plugin. The `Child`'s `kill_on_drop` only reaches a plugin running as this
  process's own user: signalling another uid takes `CAP_KILL`, which nothing
  here has.

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
  0 and warns when the uid is this process's own. Each hook defaults to its
  own id (registration 1001, login claims 1002, email 1003), so plugins can't read
  WeaveAuth's memory and environment, or each other's.
- **This process never holds the capabilities that switching takes.** With
  `Config::setuid_helper` set (the image sets `WA_SETUID_HELPER`), `spawn`
  runs `weaveauth-plugin-exec <uid> <gid> <command> <args>`
  (`launcher/src/bin/`). It alone has `CAP_SETUID`/`CAP_SETGID` file caps,
  refuses 0, and execs the plugin in place (std's `uid()` clears the
  supplementary groups), so the plugin's parent is still this process. The
  image installs it `root:weaveauth 0710`: only this process's user can run
  it, never a plugin. Without the helper, `spawn` sets `uid`/`gid` on the
  `Command` itself.
- **Backend is non-dumpable** (`main.rs`, Linux): its `/proc/<pid>/environ`
  and memory are hidden even from processes running as its own user (bff,
  login, a plugin configured as its uid).
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
| `mod.rs` unit tests | startup failure modes, refusing uid/gid 0, applying the configured uid (as root or not), the token's entropy, the tonic `source()` behaviour the startup check relies on, the `WA_PLUGIN_<PLUGIN>_ENV_` forwarding rule | — |
| `plugin-sdk/rust` unit tests, `plugin-sdk/go/serve_test.go` | the token check (unary and streaming), reading the token line without consuming gRPC bytes and refusing an endless one; Go also: `Serve` returning once the connection closes, and fd 0 released | — |
| `system-tests/tests/plugin_connection.rs` | a real plugin process: served over its socket pair with the token, refused with no/wrong token, exiting once the connection closes, refusing to run without a socket on stdin or with an empty token | — |
| `launcher/src/bin/weaveauth-plugin-exec.rs` unit tests | the helper's argument parsing: refusing uid 0, gid 0, a non-numeric id and a missing command | — |
| `system-tests/tests/plugin_process_flow.rs` | a real plugin process through backend's real `POST /register` (`hook: "registration"`): accept, reject, timeout, crash-and-restart, concurrency, environment isolation, stdin released | — |
| `system-tests/tests/login_claims_flow.rs` | a real plugin process through backend's real PKCE flow (`hook: "login_claims"`): accept, reject, timeout, reserved-claim rejection, refresh grant | — |
| `system-tests/tests/plugin_postgres_flow.rs` | a plugin holding a `deadpool-postgres` pool across registrations | Docker, `--features docker` |
| `system-tests/tests/plugin_privsep_flow.rs` | the shipped image and its exec helper: the plugin runs as `wa-registration`, can't read backend's `/proc/<pid>/environ` (not even as backend's own uid) and can't run the helper, with a control for each check | Docker, `mise run test-docker` (builds `system-tests/docker/Dockerfile.plugin-test` first) |

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
