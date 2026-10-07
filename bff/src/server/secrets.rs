use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngExt;
use sha2::{Digest, Sha256};

/// 256 random bits, base64url: a PKCE verifier, an OAuth `state` or an OIDC `nonce`.
pub(crate) fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The `S256` PKCE challenge of a verifier (RFC 7636 4.2).
pub(crate) fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Equality that takes the same time wherever the inputs differ. Both sides are hashed
/// first, so the length of the secret does not show either.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let (a, b) = (Sha256::digest(a), Sha256::digest(b));
    a.iter()
        .zip(b.iter())
        .fold(0u8, |diff, (x, y)| diff | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_tokens_are_long_and_never_repeat() {
        let (a, b) = (random_token(), random_token());

        assert_eq!(a.len(), 43);
        assert_ne!(a, b);
        assert!(
            a.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        );
    }

    #[test]
    fn the_pkce_challenge_matches_the_rfc_7636_example() {
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn constant_time_eq_compares_whole_values() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(constant_time_eq(b"", b""));
        for other in [&b"secreT"[..], b"secre", b"secrets", b"", b"\0"] {
            assert!(!constant_time_eq(b"secret", other));
        }
    }
}
