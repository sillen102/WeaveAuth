# WASM plugins

A deployment can mount a WASM module and have WeaveAuth call it at a point in
a flow. The module is the deployer's; WeaveAuth ships the runtime, the sandbox
and one generic capability, and knows nothing about what the plugin talks to.

Registration is the first flow wired up (see the [registration
flow](flows/register.md#extra-data-handlers)). The runtime itself is
flow-agnostic: a flow picks an export name and a JSON payload, so wiring a
plugin into another flow is a new export, not a new runtime.

Relevant code:
- `backend/src/plugin/mod.rs` -- `WasmPlugin`: compile, sandbox, call an export
- `backend/src/plugin/sockets.rs` -- the socket capability and its pool
- `backend/src/extra_data/wasm.rs` -- the registration flow's adapter

## The call

The module is compiled once at startup and a **fresh instance** is created per
call. Compiling is the expensive part (~3.5ms); instantiating from the compiled
module is ~50us, noise next to the argon2 hash a registration already pays for.
Per-call instances mean no lock (a wasm instance owns one linear memory and
can't take concurrent calls, so a shared one would serialize every request) and
no state bleed (each call sees zeroed memory, so one user's fields aren't still
sitting there for the next call's plugin to read).

- Input is the flow's payload, JSON, in the plugin's standard Extism input.
- Returning normally accepts. Trapping, timing out, or failing to instantiate
  fails the call -- and for registration, no user is created.
- The plugin's output bytes are handed back to the flow. Registration ignores
  them; a flow that wants data back defines its own shape.
- Guest language is free: anything with an Extism PDK. Instantiation cost is
  not -- a TinyGo module carries a GC and runtime init, and a full-Go
  (`GOOS=wasip1`) module is heavier still. Benchmark before assuming per-call
  instantiation stays in the noise.

## Sandbox

Configured under the `wasm` extra-data handler in backend's YAML:

```yaml
extra_data_handler:
  kind: wasm
  path: /plugins/register.wasm
  timeout_secs: 5          # wasmtime epoch interruption; stops an infinite loop
  memory_max_mb: 8         # linear memory cap, converted to 64KiB pages
```

The plugin runs without WASI. It gets no filesystem, no environment, and no
network at all unless a capability below is granted.

## Capability: HTTP

```yaml
  allowed_hosts:
    - api.acme.internal
```

Grants Extism's built-in HTTP client, restricted to these hosts. This covers
more than it looks: SOAP is an HTTP POST with an XML body, SQS/SNS and Azure
Service Bus both have HTTP APIs, and anything REST is already there. Reach for
it before sockets -- the downstream service owns its own connection pool, which
is where that problem belongs.

## Capability: sockets

```yaml
  sockets:
    allowed: ["db:5432", "rabbit:5672"]
    max_idle_per_endpoint: 8      # default 8
    max_open_per_call: 8          # default 8
    idle_timeout_ms: 30000        # default 30s
    io_timeout_ms: 2000           # default 2s
```

Raw TCP, optionally wrapped in TLS host-side so the plugin doesn't have to
carry a crypto stack into wasm. Everything above the byte stream -- Postgres
wire, AMQP, Kafka, SMTP -- lives in the plugin. Omit `sockets` entirely and a
module importing these fails to instantiate rather than silently getting no
network.

Four imports, in Extism's `extism:host/user` namespace. Every one takes a JSON
request and returns a JSON response; byte payloads are base64 so the ABI is the
same in every guest language. Failures come back as `{"status": "error",
"code": ..., "message": ...}` data rather than a trap -- a refused endpoint or a
dead peer is the plugin's to handle. `code` is the stable part
(`not_allowed`, `timeout`, `unknown_handle`, `too_many_connections`,
`bad_request`, `unavailable`, `io`); branch on it, not on the message.

Copy-in wrappers for Rust and Go live in [`plugin-sdk/`](../plugin-sdk/).

| import | request | response on success |
| --- | --- | --- |
| `sock_open` | `{"host": str, "port": int, "tls": bool}` | `{"status": "ok", "handle": int, "fresh": bool}` |
| `sock_write` | `{"handle": int, "data": base64}` | `{"status": "ok", "written": int}` |
| `sock_read` | `{"handle": int, "max": int}` | `{"status": "ok", "data": base64, "eof": bool}` |
| `sock_release` | `{"handle": int, "reuse": bool}` | `{"status": "ok"}` |

### Connections outlive the instance; handles don't

Connections are pooled **host-side**, keyed by `host:port:tls`, because a
plugin instance is per-call and can't hold one. `sock_open` returns
`fresh: false` when it handed back a pooled connection, which is what lets a
plugin skip a protocol handshake it already performed:

```go
handle, fresh := sockOpen("db", 5432, false)
if fresh {
    pgStartup(handle, "plugin", "appdata")  // only on a new connection
}
```

- `sock_release` with `reuse: true` returns the connection to the pool. Only
  release a connection in a clean, reusable state -- mid-protocol, release it
  with `reuse: false` or leave it, and it is closed.
- A connection left open when the call ends is **closed, not pooled**: the
  plugin never declared it clean.
- Handles are allocated per call. A handle from one call is not usable in the
  next.
- A pooled connection idle past `idle_timeout_ms` is dropped rather than handed
  back -- past that the peer has likely closed it, and a plugin told
  `fresh: false` would replay its session onto a dead socket.
- A connection an operation already failed on is **never pooled**, whatever
  `reuse` says: a failed read or write can leave unread bytes or a half-written
  frame behind.
- **`timeout_secs` is one wall-clock budget for the whole call**, wasm
  execution and socket IO together; `io_timeout_ms` caps a single operation
  within it. Both are load-bearing: epoch interruption interrupts *wasm* and
  cannot interrupt a host call blocked on a socket, so without the shared
  budget a plugin could chain operations past its timeout indefinitely.
- A call may open at most `max_open_per_call` connections. Pooled connections
  count.
- A single `sock_read` returns at most 1MB regardless of the `max` requested.
- Idle connections are swept on the same interval as the TTL'd stores, so an
  endpoint that stops being used doesn't hold its sockets open.

## Security

Mounting a `.wasm` is equivalent to shipping application code. Read this before
granting a capability.

- **The allowlists are the whole boundary.** `allowed_hosts` and
  `sockets.allowed` are the only thing between a mounted module and both
  request forgery into the internal network and exfiltration of every
  registering user's email. There is no wildcard, and an empty
  `sockets.allowed` is rejected at startup rather than read as "allow
  everything".
- **Endpoints are exact `host:port`.** A hostname is resolved at dial time, so
  an allowlisted name that resolves into your internal network is reachable --
  choose names you control.
- **Give a plugin its own credentials.** A plugin with a database endpoint has
  whatever that DSN's role has. Point it at a separate database, or at minimum
  a role restricted to its own schema with no access to WeaveAuth's user and
  credential tables.
- **Bound what a plugin can dial.** `max_open_per_call` caps connections per
  call and `max_idle_per_endpoint` caps what is kept afterwards; `timeout_secs`
  bounds the whole call. Size the downstream system's own connection limit
  accordingly.
- **Extra registration fields are bounded before the plugin sees them** -- at
  most 50 fields, each key and value at most 4096 bytes. See the
  [registration flow](flows/register.md).
