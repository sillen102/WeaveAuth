# plugin-sdk

The WeaveAuth plugin contract, and the server side of it for Rust and Go.

A plugin is an ordinary executable. WeaveAuth spawns it, hands it a private
unix socket path in `WA_PLUGIN_SOCKET`, and calls the `Plugin` service over
gRPC. Depend on one of these and you write a service implementation and a
`main`, not a transport.

| directory | holds |
| --- | --- |
| `proto/` | `weaveauth/plugin/plugin.proto` — the contract itself |
| `rust/` (crate `weaveauth-plugin-sdk`) | generated client + server, and `serve()` |
| `go/` (package `weaveauth`) | `Serve()` — the socket and the token check, and **no generated code** |

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

- Read `WA_PLUGIN_SOCKET`, clear a socket file left by a previous process,
  listen, and serve.
- Enforce `WA_PLUGIN_TOKEN` on every call, with a constant-time comparison,
  before it reaches your code — and refuse to start if it is missing, so
  there's no configuration in which the check is silently off.
- Give you the generated request/response types and a base implementation, so
  a plugin wired into one flow returns `UNIMPLEMENTED` for the others rather
  than failing to compile.
- Carry WeaveAuth's per-call deadline as the gRPC deadline, so the `ctx` (Go)
  or `Request` (Rust) you're handed already expires when the caller gives up.

## What they can't do for you

- **Sandbox you.** A plugin runs with WeaveAuth's privileges. Whatever your
  process can reach, it can reach.
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
