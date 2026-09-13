use std::fmt::Display;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use strum::{AsRefStr, Display as StrumDisplay};

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

/// `/oauth/token`'s `grant_type` (RFC 6749 4.1.3 / 6): which flow a token
/// request is redeeming -- an authorization code (fresh login) or a refresh
/// token (silently renewing an expired access token without one).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, Eq, PartialEq, AsRefStr, StrumDisplay)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum GrantType {
    AuthorizationCode,
    RefreshToken,
}
