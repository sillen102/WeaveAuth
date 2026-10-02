pub(crate) mod authorize;
pub(crate) mod email_verification;
pub(crate) mod health;
pub(crate) mod jwks;
pub(crate) mod login;
pub(crate) mod oidc;
pub(crate) mod password_reset;
pub(crate) mod register;
pub(crate) mod token;

use secrecy::SecretString;
use thiserror::Error;
use uuid::Uuid;

use crate::crypto;
use crate::model::email::normalize_email;
use crate::model::user::{PasswordHash, User};
use crate::server::AppState;
use crate::storage::{SetPasswordOutcome, UserStorage};

/// A valid Argon2 hash of a fixed, made-up password -- verified against on the
/// "unknown email" path so it costs the same as the real hash-and-compare
/// below, instead of returning instantly. Without this, an attacker can
/// enumerate registered emails purely from response timing (a known email
/// with a wrong password pays for a full Argon2 hash before failing; an
/// unknown one previously failed immediately).
///
/// A fixed literal, not computed at startup: hashing is fallible in
/// principle (clippy denies the `expect()` that would be needed to unwrap
/// it), and there's no benefit to hashing a constant input at runtime --
/// it always produces a hash with the same cost, whether computed once
/// at build time or once at first request.
const DUMMY_PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$+asaoNd4judQBozzpttaCQ$WFrspw+VJ+HAPOXqRwravZFYap0GT3yyfgRf5ZVv6qc";

#[derive(Debug, Error, Eq, PartialEq)]
pub(crate) enum AuthenticateError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("internal error: {0}")]
    Unexpected(String),
}

/// Checks `email`/`password` and returns the user. Only `/oauth/login` takes a
/// password; the email-verification endpoints authenticate with the
/// verification session it hands out.
pub(crate) async fn authenticate_password(
    state: &mut AppState,
    email: &str,
    password: SecretString,
) -> Result<User, AuthenticateError> {
    let user = state.users.get_user_by_email(&normalize_email(email)).await;

    // Hash even for an unknown email (DUMMY_PASSWORD_HASH) so timing can't enumerate registered emails.
    let hash = user
        .as_ref()
        .and_then(|u| u.password.clone())
        .unwrap_or_else(|| PasswordHash::Argon2(DUMMY_PASSWORD_HASH.into()));
    match crypto::verify_password(hash, password.clone(), state.max_bcrypt_cost).await {
        Ok(crypto::PasswordVerifyOutcome::Verified) => {}
        Ok(crypto::PasswordVerifyOutcome::NotVerified) => {
            return Err(AuthenticateError::InvalidCredentials);
        }
        Err(error) => return Err(AuthenticateError::Unexpected(error.to_string())),
    }

    let user = user.ok_or(AuthenticateError::InvalidCredentials)?;

    if matches!(user.password, Some(PasswordHash::Bcrypt(_))) {
        upgrade_bcrypt_to_argon2(&mut state.users, user.id, password).await;
    }
    Ok(user)
}

/// A bcrypt hash only ever exists on an imported legacy account; once it
/// verifies (see `login.rs`, `oidc.rs`), upgrade it to argon2 so it never
/// gets checked against bcrypt again. A failure here must not fail the
/// caller's flow -- the password was already confirmed correct, and the
/// bcrypt hash still verifies it next time too. Still worth surfacing, not
/// swallowing.
pub(crate) async fn upgrade_bcrypt_to_argon2(
    users: &mut impl UserStorage,
    user_id: Uuid,
    password: SecretString,
) {
    match crypto::hash_password(password).await {
        Ok(new_hash) => {
            if users
                .set_password(user_id, PasswordHash::Argon2(new_hash.into()))
                .await
                != SetPasswordOutcome::Ok
            {
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

        let updated = users
            .get_user_by_id(user_id)
            .await
            .expect("user still exists");
        assert!(matches!(updated.password, Some(PasswordHash::Argon2(_))));
    }
}
