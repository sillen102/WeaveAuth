# system-tests/tests/fixtures/plugins

WASM plugins built from source by the plugin system tests. Not workspace
members — they target `wasm32-unknown-unknown` with their own dependency set,
so each carries an empty `[workspace]` table to detach itself.

| plugin | used by |
| --- | --- |
| `pg-probe` | `tests/plugin_socket_flow.rs`, `tests/plugin_postgres_flow.rs` |

## `pg-probe`

A real plugin that speaks the Postgres wire protocol over the socket
capability, taking [`plugin-sdk/rust`](../../../../plugin-sdk/) (crate
`weaveauth-plugin-sdk`) as a path dependency — so the tests exercise the SDK
itself, not a parallel implementation.

It exports only `handle_registration`, because that is all a system test can
reach: the tests drive backend's real `POST /register`. Which behaviour to run
is selected by a `probe` extra field, which is itself just an extra
registration field — the mechanism under test:

| `probe` | does |
| --- | --- |
| `insert` (default) | start or resume a session, insert, release cleanly, retrying once if a pooled connection turned out to be dead |
| `no_retry` | the same insert with no retry — the positive control for the retry |
| `slow_query` | `pg_sleep(30)`, to outlive the socket timeouts |
| `open_limit` | open connections until the host refuses |

The database target is passed the same way (`db_host`, `db_port`, `db_user`,
`db_name`), so a test can point it at whatever port it got.

`src/postgres.rs` is a deliberately minimal client: startup, simple query,
command tags. No TLS, no password authentication, no typed rows — the point is
that the protocol lives in the plugin and WeaveAuth only moved bytes.

Building is automatic; `cargo` is invoked by the test with an explicit
`--target-dir` (see the comment there for why). It needs the target:

```bash
rustup target add wasm32-unknown-unknown
```
