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

```rust
let output = plugin.call("handle_registration", &payload).await?;
```

`payload` is anything `Serialize`; it arrives as JSON in the plugin's Extism
input. `output` is the plugin's raw output bytes — the flow decides what, if
anything, they mean. Registration ignores them.

That is the whole integration surface. **Wiring a plugin into a second flow is
a new export name, not a new runtime.** Give the flow a thin adapter next to
its own code (see `extra_data/wasm.rs`, ~35 lines) holding an
`Arc<WasmPlugin>` and a `const EXPORT: &str`.

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
wasmtime has no async execution model here.

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

Failures return `{"status":"error","message":...}` rather than trapping — a
refused endpoint or a dead peer is the plugin's to handle, not a reason to kill
the flow outright.

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
- `io_timeout` is load-bearing. The plugin timeout is wasmtime epoch
  interruption, which interrupts *wasm* execution and **cannot** interrupt a
  host call blocked on a socket.
- A single read allocates at most `MAX_READ_BYTES`, whatever `max` asks for.

## Adding a capability

1. Host functions in a new file here, returning failures as data.
2. Register them in `WasmPlugin::load`, **only when configured** — an
   ungranted import must fail to instantiate.
3. Config struct in `config.rs`, wired in `server/mod.rs`; reject a
   nonsensical grant (e.g. an empty allowlist) at startup, not at first call.
4. Give per-call state a scope with the same teardown guarantee as
   `CallScope`, and bound every allocation the plugin can influence.
5. Document the ABI in `docs/plugins.md`.

Run `mise run mutants -- -p weaveauth --file backend/src/plugin/<file>.rs`
afterwards. Note it shares `~/.cargo-target-shared` with everything else, so a
concurrent `cargo test` will link against mutated artifacts and fail
spuriously — use `CARGO_TARGET_DIR=/tmp/…` while it runs.
