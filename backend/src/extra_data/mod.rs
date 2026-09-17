pub(crate) mod wasm;
pub(crate) mod webhook;

use std::collections::HashMap;

use serde::Serialize;
use uuid::Uuid;

pub(crate) use wasm::WasmHandler;
pub(crate) use webhook::WebhookHandler;

/// Opaque failure signal -- callers only need to know the handler rejected
/// the registration, not why (the deployer's own handler is responsible for
/// its own error reporting/logging).
#[derive(Debug)]
pub(crate) struct ExtraDataError;

/// Implemented by whatever a deployer configures to receive the fields a
/// register request carries beyond `email`/`password` (see
/// `config::ExtraDataHandlerConfig`). An error fails the whole registration
/// -- no user is created.
#[async_trait::async_trait]
pub(crate) trait ExtraDataHandler: Send + Sync {
    async fn handle(&self, user_id: Uuid, email: &str, fields: &HashMap<String, String>) -> Result<(), ExtraDataError>;
}

/// The JSON payload sent to a webhook or a WASM plugin -- the one contract
/// shared by every `ExtraDataHandler` implementation.
#[derive(Serialize)]
pub(crate) struct ExtraDataPayload<'a> {
    pub(crate) user_id: Uuid,
    pub(crate) email: &'a str,
    pub(crate) fields: &'a HashMap<String, String>,
}
