pub(crate) mod in_memory;

use crate::model::pkce::CodeChallengeMethod;
use crate::model::user::User;
use uuid::Uuid;

pub(crate) trait UserStorage {
    async fn save_user(&mut self, user: User);
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
