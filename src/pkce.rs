//! PKCE (RFC 7636) challenge and the anti-CSRF `state`, matching the Claude
//! Code CLI: the verifier and state are each `base64url(32 random bytes)`, and
//! the challenge is `base64url(SHA-256(ascii verifier))` with method `S256`.

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// The PKCE challenge method Anthropic requires.
pub const CODE_CHALLENGE_METHOD: &str = "S256";

/// The secret PKCE verifier. Its `Debug` is redacted so it cannot leak into
/// logs; call [`PkceVerifier::expose`] to read the secret deliberately.
#[derive(Clone, PartialEq, Eq)]
pub struct PkceVerifier(String);

impl PkceVerifier {
    /// Wrap a caller-supplied verifier string.
    pub fn new(verifier: impl Into<String>) -> Self {
        Self(verifier.into())
    }

    /// Read the raw verifier. The name makes secret access grep-able.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PkceVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PkceVerifier(***)")
    }
}

/// A verifier together with its derived challenge, ready to drive an authorize
/// URL and the later code exchange.
#[derive(Clone)]
pub struct PkcePair {
    /// The secret verifier, sent only on the token exchange.
    pub verifier: PkceVerifier,
    /// The public challenge, embedded in the authorize URL.
    pub challenge: String,
}

impl PkcePair {
    /// Derive the challenge for a caller-supplied verifier. Pure and
    /// deterministic — this is the unit-testable core (RFC 7636 vectors).
    pub fn from_verifier(verifier: PkceVerifier) -> Self {
        let digest = Sha256::digest(verifier.expose().as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(digest);
        Self {
            verifier,
            challenge,
        }
    }

    /// Generate a fresh verifier (32 random bytes → base64url) and its
    /// challenge.
    pub fn generate() -> Result<Self> {
        Ok(Self::from_verifier(PkceVerifier(
            URL_SAFE_NO_PAD.encode(random_32()?),
        )))
    }
}

impl fmt::Debug for PkcePair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PkcePair")
            .field("verifier", &self.verifier)
            .field("challenge", &self.challenge)
            .finish()
    }
}

/// Generate a fresh anti-CSRF `state`: `base64url(32 random bytes)`.
pub fn generate_state() -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(random_32()?))
}

/// Constant-time byte comparison — avoids leaking a secret via timing.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Exactly 32 unconstrained bytes from the operating-system CSPRNG, matching
/// native `crypto.randomBytes(32)` byte-for-byte rather than embedding UUID
/// version/variant bits.
fn random_32() -> Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|error| Error::Random(error.to_string()))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical RFC 7636 Appendix B test vector.
    #[test]
    fn challenge_matches_rfc7636_vector() {
        let verifier = PkceVerifier::new("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        let pair = PkcePair::from_verifier(verifier);
        assert_eq!(
            pair.challenge,
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn generated_verifier_is_43_chars_base64url() {
        let pair = PkcePair::generate().unwrap();
        // 32 bytes → 43 unpadded base64url chars.
        assert_eq!(pair.verifier.expose().len(), 43);
        assert!(
            pair.verifier
                .expose()
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
    }

    #[test]
    fn debug_redacts_the_verifier() {
        let pair = PkcePair::generate().unwrap();
        assert_eq!(format!("{:?}", pair.verifier), "PkceVerifier(***)");
    }

    #[test]
    fn state_is_unique_and_url_safe() {
        let a = generate_state().unwrap();
        let b = generate_state().unwrap();
        assert_ne!(a, b);
        assert!(
            a.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        );
    }

    #[test]
    fn constant_time_eq_matches_semantics_of_eq() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }
}
