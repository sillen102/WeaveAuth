# Plugins

A plugin extends WeaveAuth at a point in a flow without a fork. It is an
**ordinary executable** you mount: WeaveAuth starts it as a child process,
hands it a private unix socket, and calls it over gRPC.

Because it is an ordinary process, it is an ordinary program. It keeps its own
runtime, its own connection pools and whatever libraries it likes — `sqlx`,
`deadpool`, `database/sql`, an AMQP client, a vendor SDK. Nothing about the
plugin mechanism constrains how you talk to your own systems.

> **A plugin is not sandboxed.** It runs as a child of WeaveAuth with the same
> privileges. Mounting one is equivalent to shipping application code into this
> deployment — see [Before you ship](#before-you-ship).

## The contract

One gRPC service, in
[`plugin-sdk/proto/weaveauth/plugin/plugin.proto`](../plugin-sdk/proto/weaveauth/plugin/plugin.proto):

```proto
service Plugin {
  rpc HandleRegistration(HandleRegistrationRequest) returns (HandleRegistrationResponse);
}

message HandleRegistrationRequest {
  string user_id = 1;
  string email = 2;
  map<string, string> fields = 3;
}
```

- **Return `OK` to accept.** The user is then created with that `user_id`.
- **Return any other status to reject.** No user is created; the request gets
  `502`. A timeout, a crash or a plugin that isn't running rejects the same
  way.
- `fields` is bounded before your plugin sees it: at most 50 entries, each key
  and value at most 4096 bytes.
- Your plugin runs *before* the user exists. Registration is only committed
  once you accept, which is what makes it atomic.

A plugin only has to implement the rpcs for the flows it is wired into; both
SDKs give you `UNIMPLEMENTED` for the rest.

## Running

WeaveAuth sets two variables and the SDKs do the rest:

| variable | is |
| --- | --- |
| `WA_PLUGIN_SOCKET` | the unix socket to listen on, in a private (`0700`) directory WeaveAuth owns |
| `WA_PLUGIN_TOKEN` | a secret WeaveAuth generates at startup and presents on every call |

A plugin never reads either directly — `serve()` / `Serve()` take them, listen,
and reject any call that doesn't present the token before it reaches your
code. A plugin started without them refuses to run rather than serving
everyone.

The token is regenerated every time WeaveAuth starts, and a plugin WeaveAuth
restarts is handed the same one, so there is nothing to configure or rotate.
It is defence in depth rather than a boundary: a process able to open the
socket is running as the same user, and could read the token out of
`/proc` anyway.

## Rust

```toml
[dependencies]
weaveauth-plugin-sdk = { git = "https://github.com/sillen102/WeaveAuth" }
tokio = { version = "1", features = ["full"] }
```

```rust
use weaveauth_plugin_sdk::{
    HandleRegistrationRequest, HandleRegistrationResponse, Plugin, Request, Response, Status, serve,
};

struct Register {
    pool: deadpool_postgres::Pool,
}

#[weaveauth_plugin_sdk::async_trait]
impl Plugin for Register {
    async fn handle_registration(
        &self,
        request: Request<HandleRegistrationRequest>,
    ) -> Result<Response<HandleRegistrationResponse>, Status> {
        let registration = request.into_inner();

        let Some(company) = registration.fields.get("company").filter(|value| !value.is_empty()) else {
            // Rejecting fails the whole registration; no user is created.
            return Err(Status::invalid_argument("company is required"));
        };

        let client = self.pool.get().await.map_err(|e| Status::unavailable(e.to_string()))?;
        client
            .execute(
                "insert into profile (user_id, email, company) values ($1, $2, $3)",
                &[&registration.user_id, &registration.email, company],
            )
            .await
            .map_err(|e| Status::unavailable(e.to_string()))?;

        Ok(Response::new(HandleRegistrationResponse {}))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let pool = build_pool()?;   // yours, built once, reused by every call
    serve(Register { pool }).await?;
    Ok(())
}
```

```bash
cargo build --release
# target/release/register
```

## Go

Generate the stubs from the contract first, the way you would for any other
gRPC service — this SDK deliberately ships none, so nothing can drift from the
`.proto`:

```bash
protoc -I path/to/weaveauth/plugin-sdk/proto \
  --go_out=. --go-grpc_out=. weaveauth/plugin/plugin.proto
```

```go
package main

import (
	"context"
	"database/sql"
	"log"
	"os"

	weaveauth "github.com/sillen102/WeaveAuth/plugin-sdk/go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	weaveauthv1 "example.com/myplugin/gen/weaveauth/plugin"
)

type plugin struct {
	weaveauthv1.UnimplementedPluginServer
	db *sql.DB
}

func (p *plugin) HandleRegistration(
	ctx context.Context,
	req *weaveauthv1.HandleRegistrationRequest,
) (*weaveauthv1.HandleRegistrationResponse, error) {
	company := req.Fields["company"]
	if company == "" {
		return nil, status.Error(codes.InvalidArgument, "company is required")
	}

	_, err := p.db.ExecContext(ctx,
		"insert into profile (user_id, email, company) values ($1, $2, $3)",
		req.UserId, req.Email, company)
	if err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	return &weaveauthv1.HandleRegistrationResponse{}, nil
}

func main() {
	db, err := sql.Open("pgx", os.Getenv("DATABASE_URL")) // pooled, reused by every call
	if err != nil {
		log.Fatal(err)
	}
	// Serve owns the socket and the token check; the callback owns the service.
	err = weaveauth.Serve(func(server *grpc.Server) {
		weaveauthv1.RegisterPluginServer(server, &plugin{db: db})
	})
	if err != nil {
		log.Fatal(err)
	}
}
```

```bash
go build -o register .
```

## Deploying

```yaml
extra_data_handler:
  kind: process
  command: /plugins/register
  args: []                 # optional
  env:                     # the plugin's ENTIRE environment
    DATABASE_URL: postgres://plugin:secret@db/appdata
  timeout_secs: 5          # default 5, deadline on one call
  startup_timeout_secs: 10 # default 10, how long it has to start listening
```

```bash
docker run -v ./register:/plugins/register \
           -v ./config.yaml:/app/config.yaml weaveauth
```

**The plugin inherits nothing.** WeaveAuth's own environment holds signing
keys, OIDC client secrets and database credentials, and none of it is passed
on. If your plugin needs `PATH`, a `TZ` or CA bundle variables, say so. There
are two ways to, and you can use both:

### `env:` in the config file

Exact names, written down where the rest of the deployment is described. Good
for anything that isn't secret.

### `WA_PLUGIN_<PLUGIN>_ENV_*` in WeaveAuth's environment

Any variable in **WeaveAuth's own environment** named
`WA_PLUGIN_<PLUGIN>_ENV_<NAME>` is forwarded to that plugin as `<NAME>`, with
the prefix stripped. The plugin behind `extra_data_handler` is `REGISTRATION`:

```bash
WA_PLUGIN_REGISTRATION_ENV_DATABASE_URL=postgres://plugin:secret@db/appdata
WA_PLUGIN_REGISTRATION_ENV_AWS_ACCESS_KEY_ID=AKIA...
WA_PLUGIN_REGISTRATION_ENV_STRIPE_API_KEY=sk_live_...
```

`<PLUGIN>` scopes the variables to one surface. As further plugin surfaces are
added they get their own name, so a plugin only ever sees the credentials
meant for it — a registration plugin can't read another plugin's database
password just by running alongside it.

The plugin sees `DATABASE_URL`, `AWS_ACCESS_KEY_ID` and `STRIPE_API_KEY` — the
names its libraries already look for, so an AWS or Postgres client picks them
up with no wiring. This is the way to give a plugin credentials: they stay in
your orchestrator's secret mechanism (Docker/K8s secrets, a vault sidecar) and
never touch `config.yaml`.

Nothing else crosses over. A variable that doesn't carry this plugin's prefix
— anything of WeaveAuth's own, another plugin's, `PATH`, `HOME` — is not
forwarded, and `config.yaml`'s `env:` wins if both set the same name.

A plugin needing several databases or services is exactly the case this is
for: add as many `WA_PLUGIN_REGISTRATION_ENV_*` variables as it wants, no
schema on our side.

## Failure and lifecycle

- **One process serves every call**, concurrently, over one HTTP/2 connection.
  A slow call does not block the next one.
- **It is started before the server serves traffic.** A missing binary, a
  plugin that exits immediately, or one that doesn't listen within
  `startup_timeout_secs` stops WeaveAuth from booting rather than turning into
  failed registrations later.
- **If it dies, WeaveAuth restarts it** after about a second. The call in
  flight fails; later ones recover on their own.
- **`timeout_secs` is the deadline on one call.** It arrives as the gRPC
  deadline, so an SDK-provided `ctx`/`Request` already carries it — honour it
  and your own downstream calls get cancelled with it.
- **Your long-lived resources are yours.** A pool, a channel, a cached token:
  build it in `main`, use it from every call. WeaveAuth neither knows nor
  manages it.

## A worked example

[`system-tests/tests/fixtures/plugins/pg_probe.rs`](../system-tests/tests/fixtures/plugins/pg_probe.rs)
is a complete plugin that holds a `deadpool-postgres` pool across
registrations and recovers from a terminated database backend without
WeaveAuth being involved. It is built and driven by the system tests, so it
can't rot.

## Before you ship

- **A plugin is not sandboxed.** It is a process with WeaveAuth's privileges:
  it can read the filesystem, open any connection and exhaust any resource the
  host allows. There are no allowlists to configure because there is nothing
  here that could enforce one. If you need isolation, it comes from the
  platform — a separate container or user, a seccomp profile, a network policy
  — not from WeaveAuth.
- **Mounting a plugin is shipping application code.** Review it the same way.
- **Give the plugin its own credentials.** The `DATABASE_URL` you put in `env`
  grants whatever that role has. Use a separate database, or a role with no
  access to WeaveAuth's user and credential tables.
- **Rejecting is a real outcome.** A non-`OK` status fails the whole
  registration and the user never exists — make sure that's what you meant.
- **Crashing is survivable but not free.** The registration in flight fails.
  Handle your own errors rather than panicking into a restart.
