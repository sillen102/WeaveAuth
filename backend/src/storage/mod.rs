use uuid::Uuid;
use crate::model::pkce::CodeChallengeMethod;
use crate::model::session::Session;
use crate::model::user::User;

pub(crate) mod in_memory;

pub(crate) trait SessionStorage {
    async fn save_session(&mut self, session: Session);
    async fn get_session(&self, cookie: &str) -> Option<&Session>;
}

pub(crate) trait UserStorage {
    async fn save_user(&mut self, user: User);
    async fn get_user(&self, user_id: Uuid) -> Option<&User>;
}

pub(crate) trait PkceStorage {
    async fn save_code_challenge(
        &mut self,
        auth_code: String,
        code_challenge: String,
        code_challenge_method: CodeChallengeMethod,
        redirect_uri: String,
    );
    /// Removes and returns the (challenge, method, redirect_uri) bound to this
    /// code -- the caller must additionally check that `redirect_uri` matches
    /// the one presented at token-exchange time (RFC 6749 4.1.3).
    async fn take_code_challenge(&mut self, code: &str) -> Option<(String, CodeChallengeMethod, String)>;
}
