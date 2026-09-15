pub(crate) mod in_memory;

use crate::crypto::JwtKeys;
use crate::model::pkce::CodeChallengeMethod;
use crate::model::user::User;
use std::sync::Arc;
use uuid::Uuid;

pub(crate) trait JwkStorage {
    /// The key `/oauth/token` should sign new access tokens with.
    async fn active_key(&self) -> Arc<JwtKeys>;
    /// The public keys to publish at `/.well-known/jwks.json`.
    async fn jwk_set(&self) -> serde_json::Value;
}

/// An email address, paired with proof it was actually confirmed by whoever
/// is asserting it -- not just claimed. The only way to get one is
/// [`VerifiedEmail::new`], which takes the raw email *and* the caller's own
/// verification result as separate arguments, so the call site has to name
/// what it's asserting (`claims.email_verified() == Some(true)`, a password
/// check, ...) rather than silently handing over a bare `&str`.
///
/// This exists specifically so `UserStorage::resolve_oidc_login` can't be
/// called with an unverified email by *accident* -- its signature simply
/// won't accept anything else. A caller can still construct one with `false`
/// and get `None` back, but it can no longer forget to check at all.
pub(crate) struct VerifiedEmail(String);

impl VerifiedEmail {
    /// `provider_verified` is whatever the caller independently confirmed
    /// ownership with -- an OIDC id_token's `email_verified` claim, a
    /// password check, etc. `None` if that's not `true`.
    ///
    /// Normalizes `email` (case-folds it and strips any `+tag`) so a
    /// provider's casing or tagging can never mismatch what was stored at
    /// registration (storage compares emails as plain strings).
    pub(crate) fn new(email: String, provider_verified: bool) -> Option<Self> {
        provider_verified.then_some(Self(crate::model::email::normalize_email(&email)))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum OidcLinkOutcome {
    /// Either a brand-new user, an already-linked identity, or a link into an
    /// account whose email was *already* verified -- no further proof needed.
    Resolved(User),
    /// An account with this email exists but isn't verified yet -- it could
    /// belong to someone who merely typed this address into a registration
    /// form with no proof of ownership (possibly an attacker squatting a
    /// victim's address ahead of time). Linking this OIDC identity to it
    /// requires the caller to first prove control of *that* account (its
    /// password) via `UserStorage::link_verified_oidc_identity`.
    RequiresPasswordConfirmation { existing_user_id: Uuid },
}

pub(crate) trait UserStorage {
    /// Saves `user` unless its `email` is already taken, in which case
    /// nothing is saved and `false` is returned. The check and the insert must
    /// happen atomically (one lock acquisition) so two concurrent registrations
    /// for the same email can't both pass the check before either inserts.
    async fn create_user(&mut self, user: User) -> bool;
    async fn get_user_by_email(&self, email: &str) -> Option<User>;
    async fn get_user_by_id(&self, id: Uuid) -> Option<User>;
    /// Resolves an OIDC login to a user, without ever silently merging into
    /// an unverified account:
    ///
    /// 1. If `(provider, subject)` is already linked to a user, returns it.
    /// 2. Otherwise, if a user with `email` already exists and is
    ///    `email_verified`, links `(provider, subject)` to that user and
    ///    returns it -- this is what lets the same person sign in via Google
    ///    today and LinkedIn tomorrow and land on one account.
    /// 3. Otherwise, if a user with `email` exists but *isn't* verified,
    ///    returns `RequiresPasswordConfirmation` instead of linking --
    ///    nothing is mutated.
    /// 4. Otherwise, creates a new, `email_verified: true` user with `email`
    ///    and links `(provider, subject)` to it.
    ///
    /// The whole resolution happens under one lock acquisition, so two
    /// concurrent logins for the same new identity can't create two separate
    /// accounts.
    ///
    /// `email` is a [`VerifiedEmail`], not a bare string, specifically so
    /// case 2 above -- merging into an *already-verified* account -- can't
    /// be reached with an unconfirmed claim by accident: an attacker who can
    /// produce any identity with a name-matching email would otherwise be
    /// able to attach themselves to a victim's verified account. Constructing
    /// a `VerifiedEmail` forces the call site to name its actual proof (see
    /// `VerifiedEmail::new`).
    async fn resolve_oidc_login(&mut self, provider: &str, subject: &str, email: &VerifiedEmail) -> OidcLinkOutcome;
    /// Links `(provider, subject)` to `user_id` and marks it `email_verified`.
    /// `None` if `user_id` no longer exists.
    ///
    /// CALLER MUST have already independently proven the OIDC-authenticated
    /// person controls this specific account -- e.g. by checking its
    /// password -- before calling this for a `user_id` that came out of
    /// `OidcLinkOutcome::RequiresPasswordConfirmation`. This is the only
    /// path that turns an *unverified* account's email into a verified one,
    /// so skipping that proof is exactly the account-takeover vector
    /// `resolve_oidc_login` refuses to do on its own.
    async fn link_verified_oidc_identity(&mut self, user_id: Uuid, provider: &str, subject: &str) -> Option<User>;
}

/// A short-lived, single-use proof that `/oauth/login` already authenticated
/// this user -- `/oauth/authorize` requires one of these before it will issue
/// a code, which is what makes "authenticate before authorize" a real,
/// server-enforced ordering rather than something callers have to get right
/// themselves (RFC 6749 4.1.1: the authorization server authenticates the
/// resource owner before issuing a code).
pub(crate) trait LoginSessionStorage {
    async fn create_session(&mut self, user_id: Uuid) -> String;
    /// Consumes the session token; returns the user id if it existed and
    /// hasn't expired.
    async fn take_session(&mut self, token: &str) -> Option<Uuid>;
}

pub(crate) trait PkceStorage {
    async fn save_code_challenge(
        &mut self,
        auth_code: String,
        code_challenge: String,
        code_challenge_method: CodeChallengeMethod,
        redirect_uri: String,
        user_id: Uuid,
    );
    /// Removes and returns the (challenge, method, redirect_uri, user_id) bound to
    /// this code -- the caller must additionally check that `redirect_uri` matches
    /// the one presented at token-exchange time (RFC 6749 4.1.3). `user_id` is who
    /// `/oauth/login` authenticated before this code was issued (see
    /// `LoginSessionStorage`); `/oauth/token` carries it into the token response so
    /// the authenticated identity survives the exchange instead of being dropped.
    async fn take_code_challenge(
        &mut self,
        code: &str,
    ) -> Option<(String, CodeChallengeMethod, String, Uuid)>;
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum RefreshTokenOutcome {
    /// Token was valid and unused; now consumed. Carries the user and the
    /// token family so the caller can mint the next token in the same chain.
    Valid { user_id: Uuid, family_id: Uuid },
    /// Token was already used once before. This is either the legitimate
    /// client re-sending a stale token, or an attacker replaying a stolen
    /// one -- either way the chain is no longer trustworthy, so the storage
    /// impl revokes every other token in the family as a side effect of
    /// returning this variant.
    Reused,
    /// Unknown, already-revoked, or expired.
    NotFound,
}

/// A single-use, rotating credential that redeems a fresh access token
/// without re-authenticating (RFC 6749 6). Each refresh mints a new token in
/// the same `family_id`; presenting an already-used token is treated as a
/// signal the family is compromised (see `RefreshTokenOutcome::Reused`).
pub(crate) trait RefreshTokenStorage {
    async fn save_refresh_token(&mut self, token: String, user_id: Uuid, family_id: Uuid);
    async fn take_refresh_token(&mut self, token: &str) -> RefreshTokenOutcome;
}

/// What `/oauth/oidc/{provider}/login` stashed for a single in-flight
/// redirect, so `/oauth/oidc/{provider}/callback` can complete the exchange
/// once the user comes back from the provider.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct OidcLoginState {
    pub(crate) provider: String,
    pub(crate) pkce_verifier: String,
    pub(crate) nonce: String,
}

/// A short-lived, single-use record of an in-flight `/oauth/oidc/{provider}/login`
/// redirect: the PKCE verifier and nonce this server generated, so the
/// `/oauth/oidc/{provider}/callback` handler can complete the exchange and
/// verify the ID token once the user comes back from the provider. Keyed by
/// the CSRF state token round-tripped through the provider's redirect.
pub(crate) trait OidcStateStorage {
    async fn save_state(&mut self, csrf_state: String, provider: String, pkce_verifier: String, nonce: String);
    /// Consumes the entry; returns it if it existed and hasn't expired.
    async fn take_state(&mut self, csrf_state: &str) -> Option<OidcLoginState>;
}

/// The provider identity waiting to be linked, and which existing
/// (unverified) account it's asking to link to -- see `PendingOidcLinkStorage`.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct PendingOidcLink {
    pub(crate) provider: String,
    pub(crate) subject: String,
    pub(crate) existing_user_id: Uuid,
}

/// A short-lived, single-use record of an OIDC identity waiting on password
/// confirmation (see `UserStorage::resolve_oidc_login`'s
/// `RequiresPasswordConfirmation` case): the provider identity that was just
/// authenticated, and which existing (unverified) account it's asking to
/// link to. `/oauth/oidc/confirm-link` consumes it once the caller has
/// supplied that account's correct password.
pub(crate) trait PendingOidcLinkStorage {
    async fn save_pending_link(&mut self, provider: String, subject: String, existing_user_id: Uuid) -> String;
    /// Consumes the entry; returns it if it existed and hasn't expired.
    /// Single-use deliberately -- a wrong password burns the token and
    /// forces the whole OIDC flow to restart, which is an acceptable, simple
    /// bound on guessing given each attempt already costs a full provider
    /// round-trip to obtain a new token.
    async fn take_pending_link(&mut self, token: &str) -> Option<PendingOidcLink>;
}

#[cfg(test)]
mod tests {
    use super::VerifiedEmail;

    #[test]
    fn verified_email_requires_provider_verified_true() {
        assert!(VerifiedEmail::new("alice@example.com".to_string(), false).is_none());
        assert!(VerifiedEmail::new("alice@example.com".to_string(), true).is_some());
    }

    #[test]
    fn verified_email_preserves_the_address() {
        let email = VerifiedEmail::new("alice@example.com".to_string(), true).unwrap();
        assert_eq!(email.as_str(), "alice@example.com");
    }
}
