# plugin-sdk

Wrappers for the socket capability a WeaveAuth plugin is granted. Depend on
one and write protocol instead of base64 and JSON.

| module | for |
| --- | --- |
| `rust/` (crate `weaveauth-plugin-sdk`) | a Rust plugin (`extism-pdk`, `serde`, `serde_json`, `base64`) |
| `go/` (module `github.com/sillen102/WeaveAuth/plugin-sdk/go`, package `weaveauth`) | a TinyGo plugin (`github.com/extism/go-pdk`) |

Neither is published — take a path dependency if your plugin lives in this
repo (see `system-tests/tests/fixtures/plugins/pg-probe` for the Rust
example), or a git dependency/`replace` directive otherwise. The ABI they
wrap is in
[`backend/src/plugin/README.md`](../backend/src/plugin/README.md#socket-abi);
writing a registration plugin is in
[`backend/src/extra_data/README.md`](../backend/src/extra_data/README.md).

## Shape

```rust
let db = Socket::open("db", 5432, false)?;
if db.fresh {
    pg_startup(&db, "plugin", "appdata")?;   // pooled connections skip this
}
db.write(&insert_profile(&reg))?;
let reply = db.read_exact(5)?;
db.release(true)?;                            // true only if it's clean
```

```go
db, err := weaveauth.Open("db", 5432, false)
if err != nil { return err }
if db.Fresh {
    if err := pgStartup(db, "plugin", "appdata"); err != nil { return err }
}
if _, err := db.Write(insertProfile(reg)); err != nil { return err }
reply, err := db.ReadExact(5)
if err != nil { return err }
return db.Release(true)
```

## What the wrappers do for you

- Frame every call as JSON and base64 the payloads.
- Turn `{"status":"error"}` responses into real errors carrying a stable
  `code` (`not_allowed`, `timeout`, `unknown_handle`, `too_many_connections`,
  `bad_request`, `unavailable`, `io`) — match on that, not on the message.
- `read_exact` / `ReadExact`, since one read returns only what had arrived.
- Surface `fresh`, which is how you skip a handshake the pooled connection
  already went through.

## What they can't do for you

- **Release honestly.** `reuse: true` means "this connection is back in a
  clean protocol state". The host refuses to pool a connection an operation
  already failed on, but it can't tell whether you stopped mid-frame.
- **Beat the clock.** Every plugin call has one wall-clock budget covering
  wasm execution *and* host IO. A `timeout` error means the call is over —
  retrying in the same call cannot succeed.
- **Open without limit.** A call may open at most `max_open_per_call`
  connections (default 8), pooled or not.
