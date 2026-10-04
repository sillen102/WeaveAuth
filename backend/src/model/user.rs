use chrono::{DateTime, Utc};
#[cfg(test)]
use secrecy::ExposeSecret;
use secrecy::SecretString;
use uuid::Uuid;

/// A stored password hash, tagged by scheme. Only `Argon2` is ever written; `Bcrypt` exists so an imported legacy user can unlock and get upgraded.
///
/// Wrapped in `SecretString` so `#[derive(Debug)]` here (and on `User`, which
/// embeds it) prints `[REDACTED]` instead of the real hash.
#[derive(Debug, Clone)]
pub(crate) enum PasswordHash {
    Argon2(SecretString),
    #[allow(dead_code)]
    Bcrypt(SecretString),
}

#[cfg(test)]
impl PasswordHash {
    /// `secrecy` deliberately doesn't derive `PartialEq` (discourages easy
    /// secret comparisons); tests use this to check the underlying value.
    pub(crate) fn expose(&self) -> (&'static str, &str) {
        match self {
            Self::Argon2(s) => ("argon2", s.expose_secret()),
            Self::Bcrypt(s) => ("bcrypt", s.expose_secret()),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct User {
    pub id: Uuid,
    pub email: String,
    /// `None` for a user who only ever registered via a third-party OIDC
    /// provider -- they have no local password to check. A user can hold
    /// both a password and one or more linked OIDC identities (see
    /// `storage::UserStorage::link_or_create_oidc_user`) at the same time.
    pub password: Option<PasswordHash>,
    /// Whether `email` is known to be owned by this user -- `true` once an
    /// OIDC provider has confirmed it (see `link_or_create_oidc_user`) or
    /// the user entered the verification email's code; `false` for a plain
    /// password registration until then.
    pub email_verified: bool,
    /// Bumped by `UserStorage::set_password`. Every credential is stamped with
    /// the version it was issued under and refused once it no longer matches
    /// (see `server::api::current_user`), so a password reset ends every
    /// session, code and refresh token issued before it -- including one still
    /// being issued while the reset runs.
    pub credential_version: u64,
    #[allow(dead_code)]
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    pub(crate) fn stamp(&self) -> CredentialStamp {
        CredentialStamp {
            user_id: self.id,
            version: self.credential_version,
        }
    }
}

/// Who a credential (login session, authorization code, refresh token,
/// verification session) was issued to, and under which
/// `User::credential_version`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct CredentialStamp {
    pub user_id: Uuid,
    pub version: u64,
}

#[cfg(test)]
impl CredentialStamp {
    /// The stamp of a user whose password was never reset.
    pub(crate) fn initial(user_id: Uuid) -> Self {
        Self {
            user_id,
            version: 0,
        }
    }
}

#[cfg(test)]
impl User {
    pub(crate) fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            email: String::new(),
            password: None,
            email_verified: false,
            credential_version: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_has_empty_email_and_no_password() {
        let user = User::default();
        assert_eq!(user.email, "");
        assert!(user.password.is_none());
    }

    #[test]
    fn default_generates_a_fresh_id_each_time() {
        assert_ne!(User::default().id, User::default().id);
    }
}
