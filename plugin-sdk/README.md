# plugin-sdk

The WeaveAuth plugin contract, and the server side of it for Rust and Go.

A plugin is an ordinary executable. WeaveAuth spawns it with one end of a
connected unix socket as its stdin, writes a token as the first line on it, and
calls the `Plugin` service over it with gRPC. Depend on one of these and you
write a service implementation and a `main`, not a transport.

| directory | holds |
| --- | --- |
| `proto/` | `weaveauth/plugin/plugin.proto` — the contract itself |
| `rust/` (crate `weaveauth-plugin-sdk`) | generated client + server, and `serve()` |
| `go/` (package `weaveauth`) | `Serve()` — the connection and the token check, and **no generated code** |

Neither is published — take a path dependency if your plugin lives in this
repo (see `system-tests/tests/fixtures/plugins/`), or a git dependency
otherwise. Writing a plugin, with a worked example in both languages, is
[`docs/plugins.md`](../docs/plugins.md).

## Shape

```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    serve(MyPlugin { pool: build_pool()? }).await?;
    Ok(())
}
```

```go
func main() {
	log.Fatal(weaveauth.Serve(func(server *grpc.Server) {
		weaveauthv1.RegisterPluginServer(server, &plugin{db: db})
	}))
}
```

## What the SDKs do for you

- Take the connection on stdin and serve it, refusing to start if stdin isn't a
  unix socket, then point fd 0 at `/dev/null` so nothing you start inherits it.
- Read the token from the first line on that connection and enforce it on every
  call, unary and streaming, with a constant-time comparison, before it reaches
  your code — and refuse to start if it is missing, so there's no configuration
  in which the check is silently off.
- Return from `serve()` / `Serve()` once WeaveAuth closes the connection, so the
  process ends when you return from `main`. WeaveAuth usually runs as another
  user and can't kill it.
- Give you the generated request/response types and a base implementation, so
  a plugin wired into one flow returns `UNIMPLEMENTED` for the others rather
  than failing to compile.
- Carry WeaveAuth's per-call deadline as the gRPC deadline, so the `ctx` (Go)
  or `Request` (Rust) you're handed already expires when the caller gives up.

## What they can't do for you

- **Sandbox you.** A plugin runs as its own user, but whatever that user can
  reach, it can reach.
- **Own your resources.** A connection pool, a broker channel, a cached token:
  build it in `main` and reuse it. Nothing is created or torn down per call.
- **Survive a panic cheaply.** WeaveAuth restarts a plugin that dies, but the
  registration in flight has already failed.

## Regenerating

The Rust side regenerates from `proto/` on every `cargo build`. The Go stubs
are checked in, and change only when the contract does:

```bash
mise run gen-proto
```

The proto package is `weaveauth.plugin`, unversioned. A breaking change gets a
versioned package then, rather than carrying a `v1` that has never meant
anything.

`protoc-gen-go` is pinned to 1.35.2 there on purpose: 1.36 emits
`unsafe.Slice`/`unsafe.StringData` in the generated file, and the checked-in
code has no `unsafe` in it. (The protobuf and gRPC runtime modules it links
against still do, as they do for every Go gRPC program.)

## Contract changes

A plugin built against an earlier contract needs rebuilding against the current
SDK: the connection is the socket pair on stdin (`WA_PLUGIN_SOCKET` is gone), the
token is the first line on it, and `weaveauth.startup` is called once at boot.
Dispatch on `hook` and answer unknown hooks with `UNIMPLEMENTED`; a plugin that
runs its registration logic for every call runs it once at boot, with empty
data. Details in [`docs/plugins.md`](../docs/plugins.md#contract-changes).
