use std::str::FromStr;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) enum CodeChallengeMethod {
    S256,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct UnsupportedCodeChallengeMethod;

impl FromStr for CodeChallengeMethod {
    type Err = UnsupportedCodeChallengeMethod;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "S256" => Ok(Self::S256),
            _ => Err(UnsupportedCodeChallengeMethod),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parses_supported_method() {
        assert_eq!("S256".parse::<CodeChallengeMethod>(), Ok(CodeChallengeMethod::S256));
    }

    #[test]
    fn test_rejects_plain() {
        assert!("plain".parse::<CodeChallengeMethod>().is_err());
    }

    #[test]
    fn test_rejects_unknown_input() {
        assert!("garbage".parse::<CodeChallengeMethod>().is_err());
    }
}
