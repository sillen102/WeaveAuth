//! The short-lived cookie that carries one login from `/login` to `/callback`.

use crate::server::secrets::{pkce_challenge, random_token};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

pub(crate) const LOGIN_COOKIE: &str = "wa_login";

/// How long a login may take, from `/login` to `/callback`.
pub(crate) const LOGIN_COOKIE_MAX_AGE_SECS: i64 = 600;

/// What `/callback` needs to finish the login `/login` started. It lives in the browser's
/// cookie, which the user could edit, so every field is checked against something the
/// callback or Hydra knows: `state` against the query, `redirect_uri` against the allowlist,
/// and the `verifier` and `nonce` by Hydra and the id_token themselves.
#[derive(Serialize, Deserialize)]
pub(crate) struct PendingLogin {
    pub(crate) state: String,
    pub(crate) verifier: String,
    pub(crate) nonce: String,
    /// Where the browser goes once logged in.
    pub(crate) redirect_uri: String,
}

impl PendingLogin {
    pub(crate) fn new(redirect_uri: String) -> Self {
        Self {
            state: random_token(),
            verifier: random_token(),
            nonce: random_token(),
            redirect_uri,
        }
    }

    pub(crate) fn code_challenge(&self) -> String {
        pkce_challenge(&self.verifier)
    }

    pub(crate) fn to_cookie_value(&self) -> String {
        // Serializing plain strings cannot fail.
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(self).unwrap_or_default())
    }

    pub(crate) fn from_cookie_value(value: &str) -> Option<Self> {
        let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
        serde_json::from_slice(&bytes).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pending_login_round_trips_through_its_cookie_value() {
        let pending = PendingLogin::new("https://app.test/?a=b;c".into());

        let back = PendingLogin::from_cookie_value(&pending.to_cookie_value()).unwrap();

        assert_eq!(back.state, pending.state);
        assert_eq!(back.verifier, pending.verifier);
        assert_eq!(back.nonce, pending.nonce);
        assert_eq!(back.redirect_uri, "https://app.test/?a=b;c");
    }

    #[test]
    fn the_secrets_of_one_login_differ_from_each_other_and_from_the_next() {
        let (a, b) = (PendingLogin::new("x".into()), PendingLogin::new("x".into()));

        assert_ne!(a.state, a.verifier);
        assert_ne!(a.verifier, a.nonce);
        assert_ne!(a.state, b.state);
        assert_eq!(a.code_challenge(), pkce_challenge(&a.verifier));
    }

    #[test]
    fn a_cookie_value_that_is_not_a_pending_login_is_none() {
        for value in [
            "",
            "abc",
            "!!!",
            &URL_SAFE_NO_PAD.encode("{}"),
            &URL_SAFE_NO_PAD.encode("[1]"),
        ] {
            assert!(PendingLogin::from_cookie_value(value).is_none(), "{value}");
        }
    }
}
