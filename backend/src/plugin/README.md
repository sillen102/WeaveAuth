# `plugin` — the WASM plugin runtime

A deployer mounts a WASM module; WeaveAuth calls one of its exports at a point
in a flow. This module is the runtime and the sandbox. It knows nothing about
what a plugin is *for* — registration is just its first caller.

Deployer-facing docs live in [`docs/plugins.md`](../../../docs/plugins.md).
This file is for working on WeaveAuth itself.

| file | holds |
| --- | --- |
| `mod.rs` | `WasmPlugin` — compile, sandbox, call an export |
| `sockets.rs` | the socket capability: allowlist, host-side pool, per-call handle table |

## Calling a plugin from a flow

A flow declares a `Hook` once and invokes it:

```rust
let hook = Hook::new(plugin, "handle_registration");   // Hook<()> by default
hook.invoke(&payload).await?;
```

`payload` is anything `Serialize`; it arrives as JSON in the plugin's Extism
input. The output type is whatever implements `HookOutput` — only `()` today,
since registration ignores what the plugin returns. A flow that wants data back
adds its own impl; the crate denies `dead_code`, so a decoder can't sit unused
waiting for a caller.

`Hook::invoke` logs the failure and hands the error back for the flow to map
onto its own type. `WasmPlugin::call` is the layer underneath if a flow needs
raw output bytes.

That is the whole integration surface. **Wiring a plugin into a second flow is
a new export name, not a new runtime** — see `extra_data/wasm.rs` for how thin
the adapter ends up.

Errors: `PluginError::Instantiate` (module wouldn't start), `::Call` (trap,
timeout, or missing export), `::Input` (payload wouldn't serialize). A flow
maps these onto its own error type — don't leak them into an HTTP response.

## Instance lifecycle

Compiled once at startup, **fresh instance per call**. Compiling is the
expensive part (~3.5ms); instantiating is ~50µs, noise next to the argon2 hash
a registration already pays for. Two properties come from that, and tests pin
both down:

- **No lock.** A wasm instance owns one linear memory and can't take concurrent
  calls (`Plugin::call` takes `&mut self`), so a shared one would serialize
  every request. Per-call instances have nothing to share.
- **No state bleed.** Each call sees zeroed memory, so one user's fields aren't
  still sitting there for the next call's plugin to read.

Concurrency is bounded by in-flight requests rather than a pool size someone
has to guess. Anything that genuinely must outlive a call — a connection to a
database or a broker — lives host-side in `SocketHost`.

`call` is `async` but the wasm runs synchronously inside `block_in_place`;
wasmtime has no async execution model here. The plugin's `timeout` is also the
socket scope's wall-clock budget, so host IO shares one deadline with wasm
execution rather than extending it.

## Capabilities

Nothing is granted by default: no WASI, no filesystem, no environment, no
network. Each capability is opt-in from config, and a module importing one that
wasn't granted fails to instantiate rather than silently getting nothing.

- **HTTP** — `PluginLimits::allowed_hosts` feeds Extism's built-in client.
- **Sockets** — `Some(Arc<SocketHost>)` registers the four imports below.

### Socket ABI

Four imports in Extism's `extism:host/user` namespace. Each takes a JSON
request and returns a JSON response; byte payloads are base64, so the ABI is
identical from every guest language.

| import | request | response |
| --- | --- | --- |
| `sock_open` | `{"host", "port", "tls"}` | `{"status":"ok", "handle", "fresh"}` |
| `sock_write` | `{"handle", "data": base64}` | `{"status":"ok", "written"}` |
| `sock_read` | `{"handle", "max"}` | `{"status":"ok", "data": base64, "eof"}` |
| `sock_release` | `{"handle", "reuse"}` | `{"status":"ok"}` |

Failures return `{"status":"error","code":…,"message":…}` rather than trapping
— a refused endpoint or a dead peer is the plugin's to handle, not a reason to
kill the flow outright. `code` is the stable part (`not_allowed`, `timeout`,
`unknown_handle`, `too_many_connections`, `bad_request`, `unavailable`, `io`)
so a plugin can branch on the reason; the message is for a log.

Ready-made guest wrappers live in [`plugin-sdk/`](../../../plugin-sdk/).

### How pooling works

Connections are pooled in `SocketHost`, keyed by `host:port:tls`, because a
plugin instance is per-call and can't hold one. `sock_open` returns
`fresh: false` for a pooled connection, which is what lets a plugin skip a
handshake it already performed.

Handles live in a per-call `CallScope`, reached from the host functions through
a **thread-local**: wasmtime runs a host function synchronously on the thread
executing the wasm call, so the scope doesn't have to be threaded through wasm
as something the plugin could forge. `ScopeGuard::drop` clears it when the call
returns, closing (not pooling) whatever the plugin left open.

Invariants worth not breaking:

- A handle from one call is never usable in the next.
- A connection left open at call end is **closed**, not pooled — the plugin
  never declared it clean.
- A pooled connection idle past `idle_timeout` is dropped, not handed back:
  the peer has likely closed it, and a plugin told `fresh: false` would replay
  its session onto a dead socket.
- **One budget for the whole call.** `CallScope` carries the plugin's own
  timeout as a deadline; each operation gets `min(io_timeout, remaining)` and
  is refused outright once it's spent. Without this a plugin could chain an
  unbounded number of `io_timeout`-long operations and outlive its timeout
  however many times over it liked — epoch interruption interrupts *wasm*
  execution and cannot interrupt a host call blocked on a socket.
- **A failed operation poisons its connection.** `Open::dirty` is set on any
  IO error, and a dirty connection is never pooled whatever `reuse` says: a
  failed read or write can leave unread bytes or a half-written frame behind.
- A call may open at most `max_open_per_call` connections.
- A single read allocates at most `MAX_READ_BYTES`, whatever `max` asks for.
- `SocketHost::sweep_idle` runs on the same interval as the TTL'd stores.
  `take_idle` only expires connections for the endpoint being *asked for*, so
  without the sweep an endpoint that stopped being used would hold its sockets
  until the process exits.

## Adding a capability

1. Host functions in a new file here, returning failures as data.
2. Register them in `WasmPlugin::load`, **only when configured** — an
   ungranted import must fail to instantiate.
3. Config struct in `config.rs`, wired in `server/mod.rs`; reject a
   nonsensical grant (e.g. an empty allowlist) at startup, not at first call.
4. Give per-call state a scope with the same teardown guarantee as
   `CallScope`, and bound every allocation the plugin can influence.
5. Document the ABI in `docs/plugins.md`.

## Tests

| where | covers | needs |
| --- | --- | --- |
| `sockets.rs` unit tests | `CallScope` and the pool, driven directly | — |
| `system-tests/tests/plugin_socket_flow.rs` | a real WASM plugin through backend's real `POST /register`, against a stand-in server | the `wasm32-unknown-unknown` target |
| `system-tests/tests/plugin_postgres_flow.rs` | the same plugin against a real Postgres | Docker, `--features docker` |

The plugin is
[`system-tests/tests/fixtures/plugins/pg-probe`](../../../system-tests/tests/fixtures/plugins/), built from
source by the test. It takes its socket wrappers as a path dependency on
[`plugin-sdk/rust`](../../../plugin-sdk/) (crate `weaveauth-plugin-sdk`), so
the SDK is covered too — which is otherwise the one part of this feature
nothing would exercise.

```bash
cargo test                  # unit + the stand-in system tests
mise run test-docker        # adds the real Postgres layer
```

A change to the socket ABI should show up in all three. The stand-in server
only implements what `pg-probe` sends, so teaching the plugin a new message
means teaching the stand-in to answer it.

## Mutation testing

Not part of the per-change loop — see the repo `AGENTS.md`. When a deeper
pass is warranted here (the sandbox limits and the allowlist are the parts
worth it):

```bash
mise run mutants -- -p weaveauth --file backend/src/plugin/sockets.rs
``` Note it shares `~/.cargo-target-shared` with everything else, so a
concurrent `cargo test` will link against mutated artifacts and fail
spuriously — use `CARGO_TARGET_DIR=/tmp/…` while it runs.
