use std::collections::HashMap;
use std::time::Duration;

use uuid::Uuid;

use super::{ExtraDataError, ExtraDataHandler, ExtraDataPayload};

/// Wasm linear memory is addressed in 64KiB pages, but a deployer thinks in
/// megabytes -- so the config takes MB and this converts.
const PAGES_PER_MB: u32 = 16;

/// Converts a deployer-facing memory cap in MB to the wasm pages extism
/// wants. Saturates rather than overflowing on an absurd value, and a cap
/// below 1MB still gets a page so the plugin can hold its own input.
fn memory_max_pages(memory_max_mb: u32) -> u32 {
    memory_max_mb.saturating_mul(PAGES_PER_MB).max(1)
}

/// Runs the exported `handle_registration` function of a deployer-supplied
/// WASM plugin. The deployer can write the plugin in any language with an
/// Extism PDK; WeaveAuth only needs the contract in `ExtraDataPayload` on
/// the way in and a plain success/error result on the way out.
///
/// The module is compiled once at startup and a *fresh instance* is created
/// per call. Compiling is the expensive part (~3.5ms); instantiating from
/// the compiled module is ~50us, which is noise next to the argon2 hash the
/// same registration already pays for. That buys two things a shared
/// instance can't give:
///
/// - No lock. A wasm instance owns one linear memory and cannot take
///   concurrent calls (hence `Plugin::call`'s `&mut self`), so sharing one
///   means serializing every registration behind whichever call is in
///   flight. Per-call instances have nothing to share.
/// - No state bleed. Each registration gets zeroed linear memory, so one
///   user's email and form fields aren't still sitting in memory for the
///   next registration's plugin to read.
///
/// Concurrency is therefore bounded by in-flight registrations (already
/// capped upstream by the bff's rate limiter) rather than by a pool size
/// that has to be guessed and kept in step with traffic.
pub(crate) struct WasmHandler {
    compiled: extism::CompiledPlugin,
}

impl WasmHandler {
    pub(crate) fn load(wasm_bytes: Vec<u8>, timeout: Duration, memory_max_mb: u32) -> Result<Self, extism::Error> {
        // `with_timeout` is enforced by wasmtime epoch interruption, so it
        // covers a plugin that loops forever as well as one that merely
        // blocks -- without it, a runaway plugin burns a blocking-pool
        // thread until the process dies.
        let manifest = extism::Manifest::new([extism::Wasm::data(wasm_bytes)])
            .with_timeout(timeout)
            .with_memory_max(memory_max_pages(memory_max_mb));
        let compiled = extism::PluginBuilder::new(manifest).with_wasi(false).compile()?;
        Ok(Self { compiled })
    }
}

#[async_trait::async_trait]
impl ExtraDataHandler for WasmHandler {
    async fn handle(&self, user_id: Uuid, email: &str, fields: &HashMap<String, String>) -> Result<(), ExtraDataError> {
        let payload = ExtraDataPayload { user_id, email, fields };
        let input = serde_json::to_string(&payload).map_err(|_| ExtraDataError)?;

        // `Plugin::call` runs the wasm module synchronously (wasmtime has no
        // async execution model here) -- `block_in_place` keeps it from
        // starving other tasks on this worker thread while it runs.
        tokio::task::block_in_place(|| {
            let mut plugin = extism::Plugin::new_from_compiled(&self.compiled).map_err(|error| {
                tracing::warn!(%error, "extra-data wasm plugin failed to instantiate");
                ExtraDataError
            })?;
            plugin
                .call::<&str, &str>("handle_registration", &input)
                .map(|_| ())
                .map_err(|error| {
                    tracing::warn!(%error, "extra-data wasm plugin call failed");
                    ExtraDataError
                })
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Accepts every registration.
    const ACCEPTS: &str = r#"
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

    fn handler(wat: &str, timeout: Duration) -> WasmHandler {
        WasmHandler::load(wat::parse_str(wat).expect("valid wat"), timeout, 8).expect("module compiles")
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

    /// Grows linear memory by 32 pages (2MB) on every call.
    const GROWS_MEMORY: &str = r#"
        (module
          (memory (export "memory") 1)
          (func (export "handle_registration") (result i32)
            (if (i32.eq (memory.grow (i32.const 32)) (i32.const -1)) (then (unreachable)))
            (i32.const 0)))
    "#;

    #[tokio::test(flavor = "multi_thread")]
    async fn enforces_the_configured_memory_cap() {
        // 1MB cap = 16 pages: growing by 32 must fail.
        let tight = WasmHandler::load(wat::parse_str(GROWS_MEMORY).expect("valid wat"), Duration::from_secs(5), 1)
            .expect("module compiles");
        assert!(call(&tight).await.is_err(), "plugin grew past its configured cap");

        // 8MB cap = 128 pages: the same growth fits.
        let roomy = WasmHandler::load(wat::parse_str(GROWS_MEMORY).expect("valid wat"), Duration::from_secs(5), 8)
            .expect("module compiles");
        assert!(call(&roomy).await.is_ok(), "plugin was capped below its configured limit");
    }

    fn fields() -> HashMap<String, String> {
        HashMap::from([("company".to_string(), "Acme".to_string())])
    }

    async fn call(handler: &WasmHandler) -> Result<(), ExtraDataError> {
        handler.handle(Uuid::new_v4(), "alice@example.com", &fields()).await
    }

    // `block_in_place` (used by the real handler) only works on the
    // multi-threaded runtime -- matches how the app itself runs it.
    #[tokio::test(flavor = "multi_thread")]
    async fn succeeds_when_the_plugin_returns_ok() {
        assert!(call(&handler(ACCEPTS, Duration::from_secs(5))).await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fails_when_the_plugin_traps() {
        assert!(call(&handler(REJECTS, Duration::from_secs(5))).await.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn kills_a_plugin_that_runs_past_its_timeout() {
        let hanging = handler(HANGS, Duration::from_millis(250));

        let started = std::time::Instant::now();
        let result = call(&hanging).await;

        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(5), "timeout didn't fire: {:?}", started.elapsed());
    }

    // A hung call must not wedge later ones -- the failure mode a single
    // shared instance behind a lock would have.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_timed_out_call_does_not_block_the_next_one() {
        let healthy = handler(ACCEPTS, Duration::from_secs(5));
        let hanging = handler(HANGS, Duration::from_millis(500));

        let (hung, ok) = tokio::join!(call(&hanging), call(&healthy));

        assert!(hung.is_err());
        assert!(ok.is_ok(), "a healthy plugin call was blocked by an unrelated hung one");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn each_call_gets_fresh_linear_memory() {
        let stateful = handler(FAILS_IF_MEMORY_IS_REUSED, Duration::from_secs(5));

        for _ in 0..5 {
            assert!(call(&stateful).await.is_ok(), "plugin saw a previous call's memory");
        }
    }

    // Pins down that `each_call_gets_fresh_linear_memory` isn't vacuous: the
    // same module on a *reused* instance does trap on the second call, so
    // that test would fail if this handler ever went back to sharing one.
    #[test]
    fn the_memory_probe_module_traps_when_an_instance_is_reused() {
        let handler = handler(FAILS_IF_MEMORY_IS_REUSED, Duration::from_secs(5));
        let mut plugin = extism::Plugin::new_from_compiled(&handler.compiled).expect("instantiates");

        assert!(plugin.call::<&str, &str>("handle_registration", "{}").is_ok());
        assert!(
            plugin.call::<&str, &str>("handle_registration", "{}").is_err(),
            "probe module didn't trap on reuse -- the isolation test proves nothing"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn handles_concurrent_calls_without_a_lock() {
        let shared = std::sync::Arc::new(handler(ACCEPTS, Duration::from_secs(5)));

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
