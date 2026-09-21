# `extra_data` — writing a registration plugin

A register request may carry fields beyond `email`/`password`. WeaveAuth never
stores them; it forwards them to whatever the deployer configured. Two kinds:
`webhook` (POST to a URL) and `wasm` (call a mounted module).

This file is about writing the `wasm` one. The runtime it runs on is described
in [`../plugin/README.md`](../plugin/README.md); the flow around it is in
[`docs/flows/register.md`](../../../docs/flows/register.md).

## Contract

Export **`handle_registration`**. Input is JSON:

```json
{"user_id": "0f8c…", "email": "alice@example.com", "fields": {"company": "Acme"}}
```

- **Return normally to accept.** The user is then created with that `user_id`.
- **Trap or set an error to reject.** No user is created; the request gets
  `502`. Timing out or failing to instantiate rejects the same way.
- Output bytes are ignored here.
- `fields` is bounded before your plugin sees it: at most 50 entries, each key
  and value at most 4096 bytes.
- Your plugin runs *before* the user exists. Registration is only committed
  once you accept, which is what makes it atomic.

## Rust

```toml
[lib]
crate-type = ["cdylib"]

[dependencies]
extism-pdk = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

```rust
use extism_pdk::*;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize)]
struct Registration {
    user_id: String,
    email: String,
    fields: HashMap<String, String>,
}

#[plugin_fn]
pub fn handle_registration(input: String) -> FnResult<()> {
    let reg: Registration = serde_json::from_str(&input)?;

    // Returning an error rejects the registration; no user is created.
    let Some(company) = reg.fields.get("company").filter(|value| !value.is_empty()) else {
        return Err(Error::msg("company is required").into());
    };

    info!("registering {} for {}", reg.email, company);
    Ok(())
}
```

```bash
cargo build --release --target wasm32-unknown-unknown
# target/wasm32-unknown-unknown/release/register.wasm
```

## Go (TinyGo)

```go
package main

import (
	"encoding/json"
	"errors"

	"github.com/extism/go-pdk"
)

type registration struct {
	UserID string            `json:"user_id"`
	Email  string            `json:"email"`
	Fields map[string]string `json:"fields"`
}

//go:wasmexport handle_registration
func handleRegistration() int32 {
	var reg registration
	if err := json.Unmarshal(pdk.Input(), &reg); err != nil {
		pdk.SetError(err)
		return 1
	}

	if reg.Fields["company"] == "" {
		pdk.SetError(errors.New("company is required"))
		return 1
	}

	pdk.Log(pdk.LogInfo, "registering "+reg.Email)
	return 0
}

func main() {}
```

```bash
tinygo build -o register.wasm -target wasip1 -buildmode=c-shared .
```

On TinyGo < 0.34 use `//export handle_registration` instead of
`//go:wasmexport`.

## Deploying

```yaml
extra_data_handler:
  kind: wasm
  path: /plugins/register.wasm
  timeout_secs: 5      # default 5
  memory_max_mb: 8     # default 8
```

```bash
docker run -v ./register.wasm:/plugins/register.wasm \
           -v ./config.yaml:/app/config.yaml weaveauth
```

## Talking to something

By default the plugin reaches nothing: no filesystem, no environment, no
network. Grant what it needs.

### HTTP — for REST, SOAP, SQS/SNS, Azure Service Bus

```yaml
  allowed_hosts: ["api.acme.internal"]
```

```go
req := pdk.NewHTTPRequest(pdk.MethodPost, "https://api.acme.internal/profiles")
req.SetHeader("content-type", "application/json")
req.SetBody(body)
if resp := req.Send(); resp.Status() >= 300 {
	pdk.SetError(errors.New("upstream rejected the registration"))
	return 1
}
```

Prefer this. The downstream service owns its own connection pool, which is
where that problem belongs.

### Sockets — for Postgres wire, AMQP, Kafka, SMTP

```yaml
  sockets:
    allowed: ["db:5432"]
    max_open_per_call: 8    # default 8
```

Raw TCP (TLS is done host-side, so you don't carry a crypto stack into wasm).
The protocol is yours. Four imports; see
[`../plugin/README.md`](../plugin/README.md#socket-abi) for the full ABI, and
[`plugin-sdk/`](../../../plugin-sdk/) for ready-made Rust and Go wrappers you
can copy instead of writing the marshalling below by hand.

**Connections are pooled host-side and outlive your instance** — your instance
is created per call and can't hold one. `sock_open` tells you whether you got a
fresh connection, which is how you skip a handshake you already did:

```go
//go:wasmimport extism:host/user sock_open
func _sockOpen(offset uint64) uint64

func sockOpen(host string, port int, tls bool) (handle uint64, fresh bool, err error) {
	req, _ := json.Marshal(map[string]any{"host": host, "port": port, "tls": tls})
	mem := pdk.AllocateBytes(req)
	defer mem.Free()
	out := pdk.FindMemory(_sockOpen(mem.Offset()))
	defer out.Free()

	var resp struct {
		Status  string `json:"status"`
		Handle  uint64 `json:"handle"`
		Fresh   bool   `json:"fresh"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(out.ReadBytes(), &resp); err != nil {
		return 0, false, err
	}
	if resp.Status != "ok" {
		return 0, false, errors.New(resp.Message)
	}
	return resp.Handle, resp.Fresh, nil
}

// sockWrite, sockRead and sockRelease follow the same shape.

//go:wasmexport handle_registration
func handleRegistration() int32 {
	var reg registration
	if err := json.Unmarshal(pdk.Input(), &reg); err != nil {
		pdk.SetError(err)
		return 1
	}

	handle, fresh, err := sockOpen("db", 5432, false)
	if err != nil {
		pdk.SetError(err)
		return 1
	}

	clean := false
	defer func() { sockRelease(handle, clean) }() // only pool a reusable connection

	if fresh {
		if err := pgStartup(handle, "plugin", "appdata"); err != nil {
			pdk.SetError(err)
			return 1
		}
	}
	if err := pgInsertProfile(handle, reg); err != nil {
		pdk.SetError(err)
		return 1
	}

	clean = true
	return 0
}
```

Rules that bite if ignored:

- `sock_release` with `reuse: true` only if the connection is back in a clean,
  reusable state. Mid-protocol, pass `false`. A connection an operation already
  failed on is never pooled whatever you pass.
- A connection you leave open is closed at call end, never pooled.
- A handle does not survive into the next call.
- A socket op returns `{"status":"error","code":…}` as data, not a trap —
  check it, and branch on `code`, not on the message.
- **`timeout_secs` is one budget for the whole call**, wasm and socket IO
  together. `io_timeout_ms` (default 2s) caps a single operation within it.
  A `timeout` code means the call is over — retrying cannot succeed.
- A call may open at most `max_open_per_call` connections (default 8).

## Before you ship

- **Mounting a `.wasm` is equivalent to shipping application code.** Its
  allowlists are the whole network boundary: no wildcards, and an empty socket
  allowlist is rejected at startup rather than read as "allow everything".
- **Give the plugin its own credentials.** A database endpoint grants whatever
  that DSN's role has. Use a separate database, or a role with no access to
  WeaveAuth's user and credential tables.
- **Rejecting is a real outcome.** A trap fails the whole registration and the
  user never exists — make sure that's what you meant.
- **Benchmark instantiation in your language.** A TinyGo module carries a GC
  and runtime init; a full-Go (`GOOS=wasip1`) module is heavier still. The
  ~50µs figure is Rust.
