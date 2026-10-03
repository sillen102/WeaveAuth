# Plugins

A plugin extends WeaveAuth at a point in a flow without a fork. It is an
**ordinary executable** you mount: WeaveAuth starts it as a child process,
hands it a private unix socket, and calls it over gRPC.

Because it is an ordinary process, it is an ordinary program. It keeps its own
runtime, its own connection pools and whatever libraries it likes — `sqlx`,
`deadpool`, `database/sql`, an AMQP client, a vendor SDK. Nothing about the
plugin mechanism constrains how you talk to your own systems.

> **A plugin is not sandboxed.** It runs as a child of WeaveAuth, as its own
> user (`uid`/`gid`, see [Deploying](#deploying)), with whatever that user can
> reach. Mounting one is equivalent to shipping application code into this
> deployment — see [Before you ship](#before-you-ship).

## The contract

One gRPC service, one rpc, in
[`plugin-sdk/proto/weaveauth/plugin/plugin.proto`](../plugin-sdk/proto/weaveauth/plugin/plugin.proto):

```proto
service Plugin {
  rpc Invoke(PluginRequest) returns (PluginResponse);
}

message PluginRequest {
  string hook = 1;
  string user_id = 2;
  string email = 3;
  google.protobuf.Struct data = 4;
}

message PluginResponse {
  google.protobuf.Struct data = 1;
}
```

A new flow is a new `hook` value your plugin recognizes, not a new rpc: adding
one (an email notification, say) never needs a proto change or a WeaveAuth
release. A plugin only has to handle the hooks it's wired into; return
`UNIMPLEMENTED` (or any other error) for the rest.

### `hook: "registration"`

- **Return `OK` to accept.** The user is then created with that `user_id`.
  `data` in the response is ignored -- this hook only accepts/rejects.
- **Return any other status to reject.** No user is created; the request gets
  `502`. A timeout, a crash or a plugin that isn't running rejects the same
  way.
- `data`'s fields are bounded before your plugin sees it: at most 50 entries,
  each key and value at most 4096 bytes.
- Your plugin runs *before* the user exists. Registration is only committed
  once you accept, which is what makes it atomic.

### `hook: "login_claims"`

- Called on **every token mint** — both the initial `authorization_code`
  exchange and every `refresh_token` grant. The request's `data` is unset;
  there's nothing beyond `user_id`/`email` to send.
- **Return `OK` with `data` set to add extra JWT claims.** `data` is a
  `google.protobuf.Struct`, so values can nest (e.g.
  `{"roles": {"admin": ["user-1", "user-2"]}}`), not just flat strings.
- **Return any other status, or a claim name that collides with a reserved
  one** (`sub`, `email`, `email_verified`, `iat`, `exp`) **to fail the
  request.** No token is issued; the request gets `502`. This is
  fail-closed by design: a token must not be minted without the claims it
  was configured to carry, and a plugin can't spoof identity claims by
  returning a reserved name.
- An unset `data` field in the response is treated as no extra claims, not an
  error.

### `hook: "email_verification"`

- Called after a user registers, and again on every resend request, when
  `email_handler` is `kind: plugin`. `user_id` and `email` identify the
  account; `data` carries `code` (the 9-digit code to put in the mail),
  `verify_page_url` (login's `/verify-email.html`, where it is entered) and
  `expires_at` (RFC 3339, UTC). The call runs in a background task, so a slow
  plugin never delays the user's request.
- **Return `OK` once the email is sent or queued.** Any other status is logged
  as a failed delivery; it does not fail the registration, and the user can ask
  for a new code.
- The plugin's user defaults to `1003` (`wa-email`) and its environment comes
  from `WA_PLUGIN_EMAIL_ENV_<NAME>`.

## Running

WeaveAuth spawns the plugin with one end of a connected unix socket as its
**stdin**, and writes a secret token as the first line on it before any gRPC
traffic. The SDKs do the rest: `serve()` / `Serve()` read the token, serve gRPC
on that connection, and reject any call that doesn't present the token before
it reaches your code. A plugin started any other way (stdin a terminal, a pipe,
`/dev/null`, or no token) refuses to run rather than serving everyone.

There is no socket file, port or path: the connection exists only between
WeaveAuth and the process it spawned, so nothing else on the machine can call
your plugin. The token is a second layer on top of that. It's regenerated
every time WeaveAuth starts, and a plugin WeaveAuth restarts is handed the
same one, so there is nothing to configure or rotate.

What follows from this:

- **`serve()` / `Serve()` return once WeaveAuth closes the connection**: when it
  stops, drops the plugin or restarts it. Return from `main` then. WeaveAuth
  usually runs as another user and can't kill your process, so a plugin that
  keeps running after that is left behind.
- **Stdin is pointed at `/dev/null`** once the SDK has taken the connection, so
  subprocesses you start can't inherit it.
- **Answer the `weaveauth.startup` hook with anything.** WeaveAuth calls it once
  at startup to learn the plugin is serving, and any response counts, including
  `UNIMPLEMENTED` for a hook you don't know. Dispatch on `hook`: a plugin that
  runs its registration logic for every call will run it once at boot, with
  empty data.

Every plugin runs as a user of its own, not WeaveAuth's and not another
plugin's, so it can't read their memory or environment. Files are protected
only by their permissions, as for any other user: mount WeaveAuth's config
(it holds client secrets) `0640` owned by `root:weaveauth`, not
world-readable.

### Contract changes

A plugin built against an earlier contract needs rebuilding against the
current SDK:

- The connection is the socket pair on stdin. `WA_PLUGIN_SOCKET` is gone.
- The token is the first line on that connection, not an environment
  variable or a separate stdin line.
- `weaveauth.startup` is called once at boot (see above).

## Rust

```toml
[dependencies]
weaveauth-plugin-sdk = { git = "https://github.com/sillen102/WeaveAuth" }
tokio = { version = "1", features = ["full"] }
prost-types = "0.14" # for reading/building `data`'s google.protobuf.Struct
```

```rust
use weaveauth_plugin_sdk::{Plugin, PluginRequest, PluginResponse, Request, Response, Status, serve};

struct Register {
    pool: deadpool_postgres::Pool,
}

#[weaveauth_plugin_sdk::async_trait]
impl Plugin for Register {
    async fn invoke(&self, request: Request<PluginRequest>) -> Result<Response<PluginResponse>, Status> {
        let request = request.into_inner();
        match request.hook.as_str() {
            "registration" => self.handle_registration(request).await,
            "login_claims" => self.handle_login_claims(request).await,
            other => Err(Status::unimplemented(format!("unhandled hook {other:?}"))),
        }
    }
}

impl Register {
    async fn handle_registration(&self, request: PluginRequest) -> Result<Response<PluginResponse>, Status> {
        let company = match request.data.as_ref().and_then(|data| data.fields.get("company")) {
            Some(prost_types::Value { kind: Some(prost_types::value::Kind::StringValue(company)) })
                if !company.is_empty() =>
            {
                company
            }
            // Rejecting fails the whole registration; no user is created.
            _ => return Err(Status::invalid_argument("company is required")),
        };

        let client = self.pool.get().await.map_err(|e| Status::unavailable(e.to_string()))?;
        client
            .execute(
                "insert into profile (user_id, email, company) values ($1, $2, $3)",
                &[&request.user_id, &request.email, company],
            )
            .await
            .map_err(|e| Status::unavailable(e.to_string()))?;

        Ok(Response::new(PluginResponse { data: None }))
    }

    async fn handle_login_claims(&self, request: PluginRequest) -> Result<Response<PluginResponse>, Status> {
        let client = self.pool.get().await.map_err(|e| Status::unavailable(e.to_string()))?;
        let row = client
            .query_opt("select roles from profile where user_id = $1", &[&request.user_id])
            .await
            .map_err(|e| Status::unavailable(e.to_string()))?;
        let roles: Vec<String> = row.map(|row| row.get("roles")).unwrap_or_default();

        let data = prost_types::Struct {
            fields: [(
                "roles".to_string(),
                prost_types::Value {
                    kind: Some(prost_types::value::Kind::ListValue(prost_types::ListValue {
                        values: roles
                            .into_iter()
                            .map(|role| prost_types::Value { kind: Some(prost_types::value::Kind::StringValue(role)) })
                            .collect(),
                    })),
                },
            )]
            .into(),
        };
        Ok(Response::new(PluginResponse { data: Some(data) }))
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

	"github.com/lib/pq"
	weaveauth "github.com/sillen102/WeaveAuth/plugin-sdk/go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	weaveauthv1 "example.com/myplugin/gen/weaveauth/plugin"
)

type plugin struct {
	weaveauthv1.UnimplementedPluginServer
	db *sql.DB
}

func (p *plugin) Invoke(ctx context.Context, req *weaveauthv1.PluginRequest) (*weaveauthv1.PluginResponse, error) {
	switch req.Hook {
	case "registration":
		return p.handleRegistration(ctx, req)
	case "login_claims":
		return p.handleLoginClaims(ctx, req)
	default:
		return nil, status.Error(codes.Unimplemented, "unhandled hook "+req.Hook)
	}
}

func (p *plugin) handleRegistration(ctx context.Context, req *weaveauthv1.PluginRequest) (*weaveauthv1.PluginResponse, error) {
	company := req.Data.GetFields()["company"].GetStringValue()
	if company == "" {
		return nil, status.Error(codes.InvalidArgument, "company is required")
	}

	_, err := p.db.ExecContext(ctx,
		"insert into profile (user_id, email, company) values ($1, $2, $3)",
		req.UserId, req.Email, company)
	if err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	return &weaveauthv1.PluginResponse{}, nil
}

func (p *plugin) handleLoginClaims(ctx context.Context, req *weaveauthv1.PluginRequest) (*weaveauthv1.PluginResponse, error) {
	var roles []string
	err := p.db.QueryRowContext(ctx, "select roles from profile where user_id = $1", req.UserId).Scan(pq.Array(&roles))
	if err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}

	data, err := structpb.NewStruct(map[string]any{"roles": roles})
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &weaveauthv1.PluginResponse{Data: data}, nil
}

func main() {
	db, err := sql.Open("pgx", os.Getenv("DATABASE_URL")) // pooled, reused by every call
	if err != nil {
		log.Fatal(err)
	}
	// Serve owns the connection and the token check; the callback owns the service.
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
  kind: plugin
  command: /plugins/register
  args: []                 # optional
  env:                     # the plugin's ENTIRE environment
    DATABASE_URL: postgres://plugin:secret@db/appdata
  timeout_secs: 5          # default 5, deadline on one call
  startup_timeout_secs: 10 # default 10, how long it has to answer weaveauth.startup
  uid: 1001                # default 1001 (the image's wa-registration), never 0
  gid: 1001                # default 1001, never 0

login_claims_handler:
  kind: plugin
  command: /plugins/login-claims
  timeout_secs: 5
  startup_timeout_secs: 10
  uid: 1002                # default 1002 (the image's wa-login-claims)
  gid: 1002

email_handler:
  kind: plugin
  command: /plugins/mailer
  uid: 1003                # default 1003 (the image's wa-email)
  gid: 1003
```

The plugin is always spawned as `uid`/`gid`, and each hook defaults to its own
id. Any other numeric id works too, and needs no entry in `/etc/passwd`. Give
every plugin its own: a plugin configured as WeaveAuth's own uid can read the
environment of every process running as that user, and WeaveAuth logs a
warning when it sees one.

In the image, switching users is done by `weaveauth-plugin-exec`
(`WA_SETUID_HELPER`), the only binary with capabilities (`CAP_SETUID`/
`CAP_SETGID`, as file capabilities). Backend holds none, so a deployment
without plugins needs no capabilities at all. With plugins, these settings
stop the plugin from starting, and backend then refuses to boot:

- `capabilities.drop: [ALL]`, which the Kubernetes **restricted** Pod Security
  Standard requires. Plugins need `SETUID` and `SETGID` kept, so they run under
  the **baseline** standard, not restricted.
- `--cap-drop SETUID` / `SETGID`.
- `--security-opt no-new-privileges`, which makes the kernel ignore file
  capabilities.
- Running the container under a group other than 1000. The helper is
  `root:weaveauth 0710`, so backend's process needs group 1000, either as its
  primary group or as a supplementary one. OpenShift's default policy (a
  random uid with gid 0) and a Kubernetes `runAsGroup` both change it, so add
  1000 as a supplementary group there (`supplementalGroups: [1000]`).

The helper refuses uid and gid 0, and is installed `root:weaveauth 0710`, so
only WeaveAuth's own user can run it; a plugin can't use it to become
WeaveAuth's user or another plugin's. The residual risk: a compromised
backend, bff or login (all `weaveauth`) can run code as a plugin's user,
never as root. Backend also marks itself non-dumpable, so its environment
and memory stay hidden even from bff, login, or a plugin configured as
WeaveAuth's uid.

Running backend outside the image without that helper (local development)
means setting `uid`/`gid` to your own (`id -u` / `id -g`).

The image is distroless (`gcr.io/distroless/cc-debian13`): there is no shell,
and none is involved in starting a plugin. Ship a binary that runs on
the image's glibc, or a static one (Go with `CGO_ENABLED=0`).

A single binary can implement both the `"registration"` and `"login_claims"`
hooks -- pointing both `command:`s at it spawns two separate processes of it,
each only ever called for its own hook.

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
the prefix stripped. The plugin behind `extra_data_handler` is `REGISTRATION`,
the one behind `login_claims_handler` is `LOGIN_CLAIMS` and the one behind
`email_handler` is `EMAIL`:

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
  plugin that exits immediately, or one that doesn't answer `weaveauth.startup` within
  `startup_timeout_secs` stops WeaveAuth from booting rather than turning into
  failed registrations later.
- **If it dies, WeaveAuth restarts it** after about a second. The call in
  flight fails; later ones recover on their own. A broken connection counts as
  dying: the SDK returns from `serve()`/`Serve()`, your `main` returns, and the
  replacement gets a fresh connection.
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

- **A plugin is not sandboxed.** It runs as its own user, not as WeaveAuth,
  but it can still read anything that user can, open any connection and
  exhaust any resource the host allows. There are no allowlists to configure because there is nothing
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
