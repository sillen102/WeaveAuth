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
    /// `email_verified` was set by redeeming an emailed code, which proves
    /// mailbox access to whoever chose the password, not that an OIDC provider
    /// vouches for the address. Such an account is never auto-linked to an
    /// OIDC login (see `UserStorage::resolve_oidc_login`).
    pub email_verified_by_code: bool,
    #[allow(dead_code)]
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
impl User {
    pub(crate) fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            email: String::new(),
            password: None,
            email_verified: false,
            email_verified_by_code: false,
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
