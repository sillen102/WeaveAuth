use chrono::{DateTime, Duration, Utc};
use secrecy::SecretString;
use uuid::Uuid;

/// The longest a session lives from its login, however often its tokens are refreshed. It also
/// caps the `Max-Age` of its cookie.
pub(crate) const MAX_SESSION_LIFETIME: Duration = Duration::days(30);

#[derive(Clone)]
pub(crate) struct SessionData {
    pub access_token: SecretString,
    pub refresh_token: SecretString,
    /// Hydra's `id_token` for the login, kept to hand back as `id_token_hint` on logout.
    pub id_token: SecretString,
    pub expires_at: DateTime<Utc>,
    /// When the login happened; unchanged by refreshes.
    pub created_at: DateTime<Utc>,
    /// When `refresh_token` itself dies -- once this passes, the proxy can no
    /// longer silently redeem a fresh access token and forces a full re-login.
    pub refresh_expires_at: DateTime<Utc>,
    /// The `sub` of the id_token: Hydra's subject, the Kratos identity id.
    pub user_id: Uuid,
    /// Hydra's login session id (the id_token's `sid`), which a back-channel
    /// logout may name instead of the user.
    pub sid: Option<String>,
}

impl SessionData {
    /// When the session ends for good: with its refresh token, or [`MAX_SESSION_LIFETIME`] after
    /// the login, whichever comes first.
    pub(crate) fn ends_at(&self) -> DateTime<Utc> {
        self.refresh_expires_at
            .min(self.created_at + MAX_SESSION_LIFETIME)
    }
}

/// Which sessions a logout ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SessionSelector {
    /// Every session of the user.
    User(Uuid),
    /// One login session of the user, named by its `sid`. A session of the user
    /// with no recorded `sid` can't be told apart from it, so it goes too.
    UserSession { user_id: Uuid, sid: String },
    /// One login session, named by its `sid` alone.
    Session { sid: String },
}

impl SessionSelector {
    pub(crate) fn matches(&self, session: &SessionData) -> bool {
        match self {
            Self::User(user_id) => session.user_id == *user_id,
            Self::UserSession { user_id, sid } => {
                session.user_id == *user_id && session.sid.as_ref().is_none_or(|own| own == sid)
            }
            Self::Session { sid } => session.sid.as_ref() == Some(sid),
        }
    }
}
