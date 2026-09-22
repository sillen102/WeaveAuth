# `extra_data` — where extra registration fields go

A register request may carry fields beyond `email`/`password`. WeaveAuth never
stores them; it forwards them to whatever the deployer configured. Two kinds:
`webhook` (POST to a URL) and `process` (call a mounted plugin binary).

Writing a plugin is
[`docs/plugins.md`](../../../docs/plugins.md) — that's the deployer-facing
document, with the contract and a worked example in both SDK languages. The
runtime underneath it is [`../plugin/README.md`](../plugin/README.md), and the
flow around it is [`docs/flows/register.md`](../../../docs/flows/register.md).

This file is only about how the two handlers sit behind one trait.

| file | holds |
| --- | --- |
| `mod.rs` | `ExtraDataHandler`, and the opaque `ExtraDataError` a flow sees |
| `webhook.rs` | `kind: webhook` — POSTs the fields as JSON |
| `process.rs` | `kind: process` — one rpc onto `plugin::PluginProcess` |

`ExtraDataError` carries nothing. Both handlers log why they refused at the
point they learned it, because that's where the detail is (a gRPC status, an
HTTP response); registration only needs to know it was refused. A failure
fails the whole registration and no user is created.

`process.rs` is the entire adapter — it builds a `HandleRegistrationRequest`
and hands it to the runtime. That is what "wiring a plugin into a new flow is
a new rpc, not a new runtime" means in practice.
