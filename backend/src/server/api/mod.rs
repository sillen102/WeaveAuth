pub(crate) mod health;
pub(crate) mod jwks;
pub(crate) mod login;
pub(crate) mod authorize;
pub(crate) mod oidc;
pub(crate) mod password_reset;
pub(crate) mod register;
pub(crate) mod token;

use secrecy::SecretString;
use uuid::Uuid;

use crate::crypto;
use crate::model::user::PasswordHash;
use crate::storage::{SetPasswordOutcome, UserStorage};

/// A bcrypt hash only ever exists on an imported legacy account; once it
/// verifies (see `login.rs`, `oidc.rs`), upgrade it to argon2 so it never
/// gets checked against bcrypt again. A failure here must not fail the
/// caller's flow -- the password was already confirmed correct, and the
/// bcrypt hash still verifies it next time too. Still worth surfacing, not
/// swallowing.
pub(crate) async fn upgrade_bcrypt_to_argon2(users: &mut impl UserStorage, user_id: Uuid, password: SecretString) {
    match crypto::hash_password(password).await {
        Ok(new_hash) => {
            if users.set_password(user_id, PasswordHash::Argon2(new_hash.into())).await != SetPasswordOutcome::Ok {
                tracing::warn!(user_id = %user_id, "bcrypt-to-argon2 upgrade failed: user not found");
            }
        }
        Err(e) => {
            tracing::warn!(user_id = %user_id, error = %e, "bcrypt-to-argon2 upgrade failed: re-hashing errored");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::user::User;
    use crate::storage::in_memory::InMemoryUserStorage;

    #[tokio::test]
    async fn upgrade_bcrypt_to_argon2_replaces_the_stored_hash() {
        let mut users = InMemoryUserStorage::new();
        let mut user = User {
            password: Some(PasswordHash::Bcrypt("old-bcrypt-hash".into())),
            ..User::default()
        };
        user.email = "alice@example.com".to_string();
        let user_id = user.id;
        let _ = users.create_user(user).await;

        upgrade_bcrypt_to_argon2(&mut users, user_id, "hunter2".into()).await;

        let updated = users.get_user_by_id(user_id).await.expect("user still exists");
        assert!(matches!(updated.password, Some(PasswordHash::Argon2(_))));
    }
}
