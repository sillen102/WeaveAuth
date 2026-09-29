# system-tests/tests/fixtures/plugins

The plugins the plugin system tests drive. They are **bin targets of the
`weaveauth-system-tests` package** (declared in its `Cargo.toml`), not crates
of their own: `cargo test` builds them along with everything else, and a test
finds one through `CARGO_BIN_EXE_<name>` instead of shelling out to a nested
`cargo` that would contend for the outer build's lock.

Both take [`plugin-sdk/rust`](../../../../plugin-sdk/) (crate
`weaveauth-plugin-sdk`) as a path dependency, so the tests exercise the SDK
itself rather than a parallel implementation.

| plugin | used by | needs |
| --- | --- | --- |
| `probe.rs` → `probe-plugin` | `tests/plugin_process_flow.rs`, `tests/login_claims_flow.rs` | — |
| `pg_probe.rs` → `pg-probe-plugin` | `tests/plugin_postgres_flow.rs` | the `docker` feature |

## `probe`

Implements the generic `Invoke` rpc for two hooks, dispatched on
`request.hook` -- one per flow a system test can reach.

### `hook: "registration"`

Driven by `tests/plugin_process_flow.rs`'s real `POST /register`. Which
behaviour to run is selected by a `probe` extra field — itself just an extra
registration field, i.e. the mechanism under test:

| `probe` | does |
| --- | --- |
| `accept` (default) | return `OK` |
| `reject` | return `INVALID_ARGUMENT` |
| `stall` | sleep past any configured timeout, so only WeaveAuth's deadline can end the call |
| `crash` | `exit(1)` without answering, so the next call only works if the supervisor restarted it |
| `sleep` | sleep `sleep_ms` (default 500), so two concurrent calls show they overlap |
| `env` | accept only if the environment is exactly the configured one — reject if `PATH` or `HOME` leaked through |

### `hook: "login_claims"`

`FetchLoginClaimsRequest`'s equivalent carries no extra field to select a
probe with, so this hook is driven by the email's local part instead:

| email local part | does |
| --- | --- |
| (anything else, default) | return `{"roles": ["admin"]}` as `data` |
| `reject` | return `INVALID_ARGUMENT` |
| `stall` | sleep past any configured timeout |
| `reserved` | return `{"sub": "attacker-controlled"}`, a claim name that collides with a reserved one |

## `pg-probe`

The same shape, but it holds a `deadpool-postgres` pool built once in `main`
and reused by every registration. Its `DATABASE_URL` comes from the `env` the
test configures, which is also how a real deployment gives a plugin its
credentials.

It is the demonstration that the process model does what it was chosen for: a
plugin using a normal high-level database library, pooling across calls, and
recovering from a terminated backend without WeaveAuth knowing the connection
existed.

```bash
cargo test                  # probe
mise run test-docker        # adds pg-probe against a real Postgres
```
