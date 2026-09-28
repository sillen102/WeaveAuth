use std::collections::HashMap;

use uuid::Uuid;
use weaveauth_plugin_sdk::HandleRegistrationRequest;

use super::{ExtraDataError, ExtraDataHandler};
use crate::plugin::PluginProcess;

/// Names this plugin surface in the `WA_PLUGIN_<PLUGIN>_ENV_*` variables a
/// deployer sets. Upper case because environment variables are.
pub(crate) const PLUGIN_NAME: &str = "REGISTRATION";

/// Forwards extra registration fields to a deployer-supplied plugin process.
/// The deployer can write it in any language with a gRPC server; WeaveAuth
/// only needs the contract in `plugin-sdk/proto` on the way in and an `OK`
/// on the way out.
pub(crate) struct ProcessHandler {
    plugin: PluginProcess,
}

impl ProcessHandler {
    pub(crate) fn new(plugin: PluginProcess) -> Self {
        Self { plugin }
    }
}

#[async_trait::async_trait]
impl ExtraDataHandler for ProcessHandler {
    async fn handle(&self, user_id: Uuid, email: &str, fields: &HashMap<String, String>) -> Result<(), ExtraDataError> {
        let request = HandleRegistrationRequest {
            user_id: user_id.to_string(),
            email: email.to_string(),
            fields: fields.clone(),
        };

        self.plugin.handle_registration(request).await.map_err(|status| {
            // Registration only needs to know the plugin rejected it; the
            // reason is the deployer's to read here.
            tracing::warn!(code = ?status.code(), message = status.message(), "plugin rejected the registration");
            ExtraDataError
        })
    }
}
