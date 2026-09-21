use std::collections::HashMap;
use std::sync::Arc;

use uuid::Uuid;

use super::{ExtraDataError, ExtraDataHandler, ExtraDataPayload};
use crate::plugin::{Hook, WasmPlugin};

/// The export a registration plugin has to provide. Other flows call other
/// exports on the same module -- the runtime itself is flow-agnostic, see
/// `crate::plugin`.
const REGISTER_EXPORT: &str = "handle_registration";

/// Forwards extra registration fields to a deployer-supplied WASM plugin.
/// The deployer can write it in any language with an Extism PDK; WeaveAuth
/// only needs the contract in `ExtraDataPayload` on the way in and a
/// returning (rather than trapping) call on the way out.
pub(crate) struct WasmHandler {
    hook: Hook,
}

impl WasmHandler {
    pub(crate) fn new(plugin: Arc<WasmPlugin>) -> Self {
        Self { hook: Hook::new(plugin, REGISTER_EXPORT) }
    }
}

#[async_trait::async_trait]
impl ExtraDataHandler for WasmHandler {
    async fn handle(&self, user_id: Uuid, email: &str, fields: &HashMap<String, String>) -> Result<(), ExtraDataError> {
        let payload = ExtraDataPayload { user_id, email, fields };
        // `Hook::invoke` already logged why; registration only needs to know
        // the handler rejected it.
        self.hook.invoke(&payload).await.map_err(|_| ExtraDataError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::PluginLimits;
    use std::time::Duration;

    const ACCEPTS: &str = r#"
        (module
          (memory (export "memory") 1)
          (func (export "handle_registration") (result i32) (i32.const 0)))
    "#;

    const REJECTS: &str = r#"
        (module
          (memory (export "memory") 1)
          (func (export "handle_registration") (result i32) (unreachable)))
    "#;

    /// Exports something other than `handle_registration`, so registration
    /// has no entry point to call.
    const EXPORTS_ANOTHER_HOOK: &str = r#"
        (module
          (memory (export "memory") 1)
          (func (export "handle_login") (result i32) (i32.const 0)))
    "#;

    fn handler(wat: &str) -> WasmHandler {
        let limits = PluginLimits {
            timeout: Duration::from_secs(5),
            memory_max_mb: 8,
            allowed_hosts: vec![],
        };
        let plugin = WasmPlugin::load(wat::parse_str(wat).expect("valid wat"), &limits, None).expect("compiles");
        WasmHandler::new(Arc::new(plugin))
    }

    async fn handle(handler: &WasmHandler) -> Result<(), ExtraDataError> {
        let fields = HashMap::from([("company".to_string(), "Acme".to_string())]);
        handler.handle(Uuid::new_v4(), "alice@example.com", &fields).await
    }

    // `block_in_place` (used by the plugin call path) only works on the
    // multi-threaded runtime -- matches how the app itself runs it.
    #[tokio::test(flavor = "multi_thread")]
    async fn accepts_the_registration_when_the_plugin_returns() {
        assert!(handle(&handler(ACCEPTS)).await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rejects_the_registration_when_the_plugin_traps() {
        assert!(handle(&handler(REJECTS)).await.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rejects_the_registration_when_the_plugin_has_no_registration_export() {
        assert!(handle(&handler(EXPORTS_ANOTHER_HOOK)).await.is_err());
    }
}
