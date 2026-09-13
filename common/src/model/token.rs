use std::fmt::Display;
use schemars::JsonSchema;
use serde::Serialize;

#[derive(Serialize, JsonSchema, Debug)]
#[serde(rename_all = "PascalCase")]
pub enum TokenType {
    Bearer,
}

impl Display for TokenType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
