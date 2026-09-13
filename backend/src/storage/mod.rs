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

pub(crate) trait UserStorage {
    /// Saves `user` unless its `identifier` is already taken, in which case
    /// nothing is saved and `false` is returned. The check and the insert must
    /// happen atomically (one lock acquisition) so two concurrent registrations
    /// for the same identifier can't both pass the check before either inserts.
    async fn create_user(&mut self, user: User) -> bool;
    async fn get_user_by_identifier(&self, identifier: &str) -> Option<User>;
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
