use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

// The `WeakPassword` details text in register.rs and password_reset.rs and the
// message on templates/pages/reset-password.html spell these two out; keep them
// in step.

/// Counted in characters, so a non-ASCII password isn't held to a stricter
/// effective minimum than an ASCII one.
pub(crate) const MIN_PASSWORD_CHARS: usize = 8;
/// Counted in bytes: it bounds the work handed to Argon2, not what a user can type.
pub(crate) const MAX_PASSWORD_BYTES: usize = 1024;

#[derive(Debug, Error, Eq, PartialEq)]
pub(crate) enum PasswordPolicyError {
    #[error("password is shorter than {MIN_PASSWORD_CHARS} characters")]
    TooShort,
    #[error("password is longer than {MAX_PASSWORD_BYTES} bytes")]
    TooLong,
}

pub(crate) fn validate_new_password(password: &SecretString) -> Result<(), PasswordPolicyError> {
    let password = password.expose_secret();
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(PasswordPolicyError::TooLong);
    }
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(PasswordPolicyError::TooShort);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validate(password: &str) -> Result<(), PasswordPolicyError> {
        validate_new_password(&password.to_owned().into())
    }

    #[test]
    fn rejects_an_empty_password() {
        assert_eq!(validate(""), Err(PasswordPolicyError::TooShort));
    }

    #[test]
    fn accepts_exactly_the_minimum_length_and_rejects_one_less() {
        assert_eq!(validate("1234567"), Err(PasswordPolicyError::TooShort));
        assert_eq!(validate("12345678"), Ok(()));
    }

    #[test]
    fn counts_characters_not_bytes_for_the_minimum() {
        // 7 characters, 14 bytes.
        assert_eq!(validate("ééééééé"), Err(PasswordPolicyError::TooShort));
    }

    #[test]
    fn accepts_exactly_the_maximum_length_and_rejects_one_more() {
        assert_eq!(validate(&"a".repeat(MAX_PASSWORD_BYTES)), Ok(()));
        assert_eq!(
            validate(&"a".repeat(MAX_PASSWORD_BYTES + 1)),
            Err(PasswordPolicyError::TooLong)
        );
    }
}
