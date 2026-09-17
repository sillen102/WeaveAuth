use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A stored password hash, tagged by scheme. Only `Argon2` is ever written; `Bcrypt` exists so an imported legacy user can unlock and get upgraded.
/// Only in-memory storage exists today, so this isn't exercised, but a future durable `UserStorage` must account for this type's serde shape when reading pre-existing rows.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum PasswordHash {
    Argon2(String),
    Bcrypt(String),
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct User {
    pub id: Uuid,
    pub email: String,
    /// `None` for a user who only ever registered via a third-party OIDC
    /// provider -- they have no local password to check. A user can hold
    /// both a password and one or more linked OIDC identities (see
    /// `storage::UserStorage::link_or_create_oidc_user`) at the same time.
    pub password: Option<PasswordHash>,
    /// Whether `email` is known to be owned by this user -- `true` once an
    /// OIDC provider has confirmed it (see `link_or_create_oidc_user`),
    /// `false` for a plain password registration (this app has no
    /// verification-email flow of its own).
    pub email_verified: bool,
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
        assert_eq!(user.password, None);
    }

    #[test]
    fn default_generates_a_fresh_id_each_time() {
        assert_ne!(User::default().id, User::default().id);
    }
}
