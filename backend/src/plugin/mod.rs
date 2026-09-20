//! The generic plugin mechanism: a deployer mounts a WASM module and
//! WeaveAuth calls one of its exports at a point in a flow.
//!
//! Nothing here knows what a plugin is *for*. A flow picks an export name
//! and a JSON payload, hands both to [`WasmPlugin::call`], and gets the
//! plugin's output bytes back -- so wiring a plugin into a new flow is a new
//! export name, not a new runtime. Registration is the first caller (see
//! `crate::extra_data`).

pub(crate) mod sockets;

use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use thiserror::Error;

pub(crate) use sockets::{SocketHost, parse_endpoint};

/// Wasm linear memory is addressed in 64KiB pages, but a deployer thinks in
/// megabytes -- so the config takes MB and this converts.
const PAGES_PER_MB: u32 = 16;

/// Converts a deployer-facing memory cap in MB to the wasm pages extism
/// wants. Saturates rather than overflowing on an absurd value, and a cap
/// below 1MB still gets a page so the plugin can hold its own input.
fn memory_max_pages(memory_max_mb: u32) -> u32 {
    memory_max_mb.saturating_mul(PAGES_PER_MB).max(1)
}

#[derive(Debug, Error)]
pub(crate) enum PluginError {
    #[error("plugin input could not be serialized: {0}")]
    Input(#[from] serde_json::Error),
    #[error("plugin failed to instantiate: {0}")]
    Instantiate(String),
    #[error("plugin export {export} failed: {message}")]
    Call { export: String, message: String },
}

/// The sandbox a plugin runs in, all of it deployer-configured.
pub(crate) struct PluginLimits {
    /// How long a single call may run before wasmtime interrupts it.
    pub(crate) timeout: Duration,
    /// Cap on linear memory, in MB.
    pub(crate) memory_max_mb: u32,
    /// Hosts reachable through extism's built-in HTTP. Empty means none.
    pub(crate) allowed_hosts: Vec<String>,
}

/// A compiled deployer-supplied module plus the capabilities it was granted.
///
/// The module is compiled once at startup and a *fresh instance* is created
/// per call. Compiling is the expensive part (~3.5ms); instantiating from
/// the compiled module is ~50us, which is noise next to the argon2 hash a
/// registration already pays for. That buys two things a shared instance
/// can't give:
///
/// - No lock. A wasm instance owns one linear memory and cannot take
///   concurrent calls (hence `Plugin::call`'s `&mut self`), so sharing one
///   means serializing every call behind whichever one is in flight.
///   Per-call instances have nothing to share.
/// - No state bleed. Each call gets zeroed linear memory, so one user's
///   email and form fields aren't still sitting in memory for the next
///   call's plugin to read.
///
/// Concurrency is therefore bounded by in-flight requests rather than by a
/// pool size that has to be guessed and kept in step with traffic. Anything
/// that genuinely must outlive a single call -- a connection to a database
/// or a broker -- lives host-side in [`SocketHost`] instead.
pub(crate) struct WasmPlugin {
    compiled: extism::CompiledPlugin,
    sockets: Option<Arc<SocketHost>>,
}

impl WasmPlugin {
    pub(crate) fn load(
        wasm_bytes: Vec<u8>,
        limits: &PluginLimits,
        sockets: Option<Arc<SocketHost>>,
    ) -> Result<Self, extism::Error> {
        // `with_timeout` is enforced by wasmtime epoch interruption, so it
        // covers a plugin that loops forever as well as one that merely
        // blocks -- without it, a runaway plugin burns a blocking-pool
        // thread until the process dies.
        let mut manifest = extism::Manifest::new([extism::Wasm::data(wasm_bytes)])
            .with_timeout(limits.timeout)
            .with_memory_max(memory_max_pages(limits.memory_max_mb));
        for host in &limits.allowed_hosts {
            manifest = manifest.with_allowed_host(host);
        }

        let mut builder = extism::PluginBuilder::new(manifest).with_wasi(false);
        if sockets.is_some() {
            builder = builder.with_functions(sockets::host_functions());
        }
        Ok(Self { compiled: builder.compile()?, sockets })
    }

    /// Calls `export` with `input` serialized as JSON and returns the
    /// plugin's raw output. A trap, a timeout or a failure to instantiate is
    /// an error; interpreting the output bytes is the caller's job, since
    /// what a plugin returns depends on the flow it was called from.
    pub(crate) async fn call<I: Serialize>(&self, export: &str, input: &I) -> Result<Vec<u8>, PluginError> {
        let input = serde_json::to_vec(input)?;

        // `Plugin::call` runs the wasm module synchronously (wasmtime has no
        // async execution model here) -- `block_in_place` keeps it from
        // starving other tasks on this worker thread while it runs.
        tokio::task::block_in_place(|| {
            let mut plugin = extism::Plugin::new_from_compiled(&self.compiled)
                .map_err(|error| PluginError::Instantiate(error.to_string()))?;

            // Host functions run on this same thread, so the socket scope is
            // installed thread-locally for the duration of the call. Dropping
            // the guard closes whatever the plugin left open.
            let _scope = self.sockets.as_ref().map(sockets::CallScope::enter);

            plugin
                .call::<&[u8], &[u8]>(export, &input)
                .map(<[u8]>::to_vec)
                .map_err(|error| PluginError::Call { export: export.to_string(), message: error.to_string() })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Accepts every call.
    pub(crate) const ACCEPTS: &str = r#"
        (module
          (memory (export "memory") 1)
          (func (export "handle_registration") (result i32) (i32.const 0)))
    "#;

    /// Traps, the way a plugin rejecting a registration does.
    const REJECTS: &str = r#"
        (module
          (memory (export "memory") 1)
          (func (export "handle_registration") (result i32) (unreachable)))
    "#;

    /// Loops forever -- only the manifest timeout can stop it.
    const HANGS: &str = r#"
        (module
          (memory (export "memory") 1)
          (func (export "handle_registration") (result i32)
            (loop $spin (br $spin))
            (i32.const 0)))
    "#;

    /// Traps if linear memory isn't zeroed on entry, then dirties it. A
    /// second call on a reused instance would trap; on a fresh one it won't.
    const FAILS_IF_MEMORY_IS_REUSED: &str = r#"
        (module
          (memory (export "memory") 1)
          (func (export "handle_registration") (result i32)
            (if (i32.load (i32.const 0)) (then (unreachable)))
            (i32.store (i32.const 0) (i32.const 1))
            (i32.const 0)))
    "#;

    /// Grows linear memory by 32 pages (2MB) on every call.
    const GROWS_MEMORY: &str = r#"
        (module
          (memory (export "memory") 1)
          (func (export "handle_registration") (result i32)
            (if (i32.eq (memory.grow (i32.const 32)) (i32.const -1)) (then (unreachable)))
            (i32.const 0)))
    "#;

    /// Imports the socket capability, so it only instantiates where the
    /// deployer granted it.
    const IMPORTS_A_SOCKET: &str = r#"
        (module
          (import "extism:host/user" "sock_open" (func $sock_open (param i64) (result i64)))
          (memory (export "memory") 1)
          (func (export "handle_registration") (result i32) (i32.const 0)))
    "#;

    fn limits(timeout: Duration, memory_max_mb: u32) -> PluginLimits {
        PluginLimits { timeout, memory_max_mb, allowed_hosts: vec![] }
    }

    pub(crate) fn plugin(wat: &str, timeout: Duration) -> WasmPlugin {
        WasmPlugin::load(wat::parse_str(wat).expect("valid wat"), &limits(timeout, 8), None)
            .expect("module compiles")
    }

    async fn call(plugin: &WasmPlugin) -> Result<Vec<u8>, PluginError> {
        plugin.call("handle_registration", &serde_json::json!({"hello": "world"})).await
    }

    #[test]
    fn converts_a_memory_cap_from_mb_to_wasm_pages() {
        assert_eq!(memory_max_pages(1), 16);
        assert_eq!(memory_max_pages(8), 128);
        assert_eq!(memory_max_pages(64), 1_024);
        // A sub-1MB cap (i.e. 0) still leaves one page, so the plugin can at
        // least hold its own input rather than failing to instantiate.
        assert_eq!(memory_max_pages(0), 1);
        // An absurd cap saturates instead of wrapping to a tiny one.
        assert_eq!(memory_max_pages(u32::MAX), u32::MAX);
    }

    // `block_in_place` (used by the real call path) only works on the
    // multi-threaded runtime -- matches how the app itself runs it.
    #[tokio::test(flavor = "multi_thread")]
    async fn succeeds_when_the_plugin_returns() {
        assert!(call(&plugin(ACCEPTS, Duration::from_secs(5))).await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fails_when_the_plugin_traps() {
        assert!(call(&plugin(REJECTS, Duration::from_secs(5))).await.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fails_when_the_export_is_missing() {
        let plugin = plugin(ACCEPTS, Duration::from_secs(5));

        let result = plugin.call("handle_login", &serde_json::json!({})).await;

        assert!(result.is_err(), "a flow calling an export the plugin doesn't implement must fail loudly");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn kills_a_plugin_that_runs_past_its_timeout() {
        let hanging = plugin(HANGS, Duration::from_millis(250));

        let started = std::time::Instant::now();
        let result = call(&hanging).await;

        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(5), "timeout didn't fire: {:?}", started.elapsed());
    }

    // A hung call must not wedge later ones -- the failure mode a single
    // shared instance behind a lock would have.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_timed_out_call_does_not_block_the_next_one() {
        let healthy = plugin(ACCEPTS, Duration::from_secs(5));
        let hanging = plugin(HANGS, Duration::from_millis(500));

        let (hung, ok) = tokio::join!(call(&hanging), call(&healthy));

        assert!(hung.is_err());
        assert!(ok.is_ok(), "a healthy plugin call was blocked by an unrelated hung one");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn each_call_gets_fresh_linear_memory() {
        let stateful = plugin(FAILS_IF_MEMORY_IS_REUSED, Duration::from_secs(5));

        for _ in 0..5 {
            assert!(call(&stateful).await.is_ok(), "plugin saw a previous call's memory");
        }
    }

    // Pins down that `each_call_gets_fresh_linear_memory` isn't vacuous: the
    // same module on a *reused* instance does trap on the second call, so
    // that test would fail if this ever went back to sharing one.
    #[test]
    fn the_memory_probe_module_traps_when_an_instance_is_reused() {
        let plugin = plugin(FAILS_IF_MEMORY_IS_REUSED, Duration::from_secs(5));
        let mut instance = extism::Plugin::new_from_compiled(&plugin.compiled).expect("instantiates");

        assert!(instance.call::<&str, &str>("handle_registration", "{}").is_ok());
        assert!(
            instance.call::<&str, &str>("handle_registration", "{}").is_err(),
            "probe module didn't trap on reuse -- the isolation test proves nothing"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn enforces_the_configured_memory_cap() {
        let wasm = wat::parse_str(GROWS_MEMORY).expect("valid wat");

        // 1MB cap = 16 pages: growing by 32 must fail.
        let tight = WasmPlugin::load(wasm.clone(), &limits(Duration::from_secs(5), 1), None).expect("compiles");
        assert!(call(&tight).await.is_err(), "plugin grew past its configured cap");

        // 8MB cap = 128 pages: the same growth fits.
        let roomy = WasmPlugin::load(wasm, &limits(Duration::from_secs(5), 8), None).expect("compiles");
        assert!(call(&roomy).await.is_ok(), "plugin was capped below its configured limit");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_plugin_importing_a_socket_fails_without_the_capability() {
        let plugin = plugin(IMPORTS_A_SOCKET, Duration::from_secs(5));

        assert!(call(&plugin).await.is_err(), "a plugin got a socket import the deployer never granted");
    }

    // Positive control for the test above: with the capability configured,
    // the same module runs -- so dropping the imports entirely would not
    // leave the suite green.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_plugin_importing_a_socket_runs_with_the_capability() {
        let sockets = Arc::new(SocketHost::new(vec![], 8, Duration::from_secs(30), Duration::from_secs(2)));
        let plugin = WasmPlugin::load(
            wat::parse_str(IMPORTS_A_SOCKET).expect("valid wat"),
            &limits(Duration::from_secs(5), 8),
            Some(sockets),
        )
        .expect("compiles");

        assert!(call(&plugin).await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn handles_concurrent_calls_without_a_lock() {
        let shared = Arc::new(plugin(ACCEPTS, Duration::from_secs(5)));

        let mut set = tokio::task::JoinSet::new();
        for _ in 0..16 {
            let shared = shared.clone();
            set.spawn(async move { call(&shared).await.is_ok() });
        }

        while let Some(result) = set.join_next().await {
            assert!(result.expect("task completes"));
        }
    }
}
