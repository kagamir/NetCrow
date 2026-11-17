//! Exact UTF-8 token derivation and constant-time wire credential comparison.
use sha2::{Digest, Sha256};
use subtle::{Choice, ConstantTimeEq};

/// Derive the lowercase SHA-256 hex credential without altering the raw token.
pub fn token_digest(raw: &str) -> String {
    format!("{:x}", Sha256::digest(raw.as_bytes()))
}

/// Compare canonical wire credentials. The received value is never hashed.
pub fn digest_matches(expected_digest: &str, received: &str) -> bool {
    let expected = expected_digest.as_bytes();
    let received = received.as_bytes();
    if expected.len() != 64 || received.len() != 64 {
        return false;
    }
    // Validate only the public received bytes, without early exits. The cached
    // secret is examined exclusively by subtle's fixed-size equality comparison.
    let canonical = received.iter().fold(1_u8, |valid, byte| {
        valid & u8::from(byte.is_ascii_digit() | (b'a'..=b'f').contains(byte))
    });
    bool::from(expected.ct_eq(received) & Choice::from(canonical))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_exact_utf8_known_vectors() {
        let vectors = [
            (
                "",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                "abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                "令牌🔐",
                "401f35346cd69ec29cf7acd086a7924a743eb7224b063ba49a3c7186ff76f7d1",
            ),
            (
                "\0\t\n\r\u{1f}\u{7f}",
                "a7847a0679c2773378648fb2461acd32938c507f75a3a4d0f150b05e651c3f48",
            ),
            (
                " abc \n",
                "20219c9f2404f1fc5e7409c891b95caacb6c4bf6153a08df7f4730f876681cfe",
            ),
            (
                "\u{e9}",
                "4a99557e4033c3539de2eb65472017cad5f9557f7a0625a09f1c3f6e2ba69c4c",
            ),
            (
                "e\u{301}",
                "bf12767b0f2a56b2190075bae8169f656e3ce8d6357d4aff184bc6c7ea48f9f6",
            ),
        ];
        for (raw, expected) in vectors {
            let actual = token_digest(raw);
            assert_eq!(actual, expected);
            assert!(digest_matches(expected, &actual));
        }
    }

    #[test]
    fn neither_trims_whitespace_nor_normalizes_unicode() {
        assert_ne!(token_digest(" abc \n"), token_digest("abc"));
        assert_ne!(token_digest("\u{e9}"), token_digest("e\u{301}"));
        assert_ne!(token_digest("abc\0"), token_digest("abc"));
    }

    #[test]
    fn accepts_raw_tokens_longer_than_a_protocol_frame() {
        let raw = "a".repeat(1024 * 1024);
        let actual = token_digest(&raw);
        assert_eq!(
            actual,
            "9bc1b2a288b26af7257a36277ae3816a7d4f16e89c1e7e77d0a5c48bad62b360"
        );
        assert!(digest_matches(&actual, &actual));
    }

    #[test]
    fn rejects_raw_double_hashed_and_noncanonical_credentials() {
        let expected = token_digest("abc");
        for received in [
            "abc".to_owned(),
            token_digest(&expected),
            expected.to_uppercase(),
            "g".repeat(64),
            "0".repeat(63),
            format!("{expected}\n"),
        ] {
            assert!(!digest_matches(&expected, &received));
        }
        assert!(!digest_matches(&token_digest(""), ""));
        let raw_hex = "0".repeat(64);
        assert!(!digest_matches(&token_digest(&raw_hex), &raw_hex));
        assert!(!digest_matches(&"g".repeat(64), &"g".repeat(64)));
        assert!(!digest_matches("abc", "abc"));
    }
}
