//! Anthropic credential domain types: secret newtypes, the credential-kind
//! enum, the OAuth token set with expiry logic, and token-format validators.

use std::fmt;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::endpoints;
use crate::error::{Error, Result};

/// Refresh proactively when the access token is within this window of expiry.
/// Matches the Claude Code CLI's 5-minute buffer.
pub const REFRESH_LEEWAY_SECS: i64 = 300;

/// Maximum accepted length of any `sk-ant-*` token.
pub const MAX_TOKEN_LEN: usize = 500;

const ACCESS_TOKEN_PREFIX: &str = "sk-ant-oat";
const REFRESH_TOKEN_PREFIX: &str = "sk-ant-ort";
const API_KEY_PREFIX: &str = "sk-ant-api";

/// A short-lived OAuth access token (`sk-ant-oat…`). Redacted from `Debug`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AccessToken(String);

/// A long-lived OAuth refresh token (`sk-ant-ort…`). Redacted from `Debug`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RefreshToken(String);

/// A static Anthropic API key (`sk-ant-api…`). Redacted from `Debug`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ApiKey(String);

macro_rules! secret_newtype {
    ($ty:ident) => {
        impl $ty {
            /// Wrap a raw secret string.
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            /// Read the raw secret. The explicit name keeps deliberate secret
            /// access grep-able across the codebase.
            pub fn expose(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}(***)", stringify!($ty))
            }
        }
    };
}

// One declarative macro for three byte-identical secret wrappers keeps the
// redaction guarantee in a single place.
secret_newtype!(AccessToken);
secret_newtype!(RefreshToken);
secret_newtype!(ApiKey);

/// Whether a string is a well-formed OAuth access token.
pub fn is_valid_access_token(s: &str) -> bool {
    is_valid_sk_ant_token(s, ACCESS_TOKEN_PREFIX)
}

/// Whether a string is a well-formed OAuth refresh token.
pub fn is_valid_refresh_token(s: &str) -> bool {
    is_valid_sk_ant_token(s, REFRESH_TOKEN_PREFIX)
}

/// Whether a string is a well-formed static API key.
pub fn is_valid_api_key(s: &str) -> bool {
    is_valid_sk_ant_token(s, API_KEY_PREFIX)
}

/// Shared shape: `<prefix><version-digits>-<>=20 base64url-ish chars>`, capped
/// at [`MAX_TOKEN_LEN`]. Mirrors the CLI's `sk-ant-oat\d+-[A-Za-z0-9_-]{20,}`.
fn is_valid_sk_ant_token(s: &str, prefix: &str) -> bool {
    if s.len() > MAX_TOKEN_LEN {
        return false;
    }
    let Some(rest) = s.strip_prefix(prefix) else {
        return false;
    };
    let Some((version, body)) = rest.split_once('-') else {
        return false;
    };
    if version.is_empty() || !version.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    body.len() >= 20
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// The last four characters of a secret, for display next to a masked key.
/// Never more than four, so a short value is not echoed whole unless it is
/// four characters or fewer.
pub fn key_suffix(key: &str) -> String {
    let chars: Vec<char> = key.chars().collect();
    chars[chars.len().saturating_sub(4)..].iter().collect()
}

/// Replace any `sk-ant-…` token run with a placeholder so error bodies and log
/// lines are safe to emit. Char-boundary safe.
pub fn redact_secrets(input: &str) -> String {
    const MARKER: &str = "sk-ant-";
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(pos) = rest.find(MARKER) {
        out.push_str(&rest[..pos]);
        out.push_str("sk-ant-***REDACTED***");
        let after = &rest[pos + MARKER.len()..];
        let end = after
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
            .unwrap_or(after.len());
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

/// A stable, non-secret handle for a token: the first 16 hex characters of
/// its SHA-256. Logs, leases, and dead-token records carry this, never the
/// token itself. Matches the fork's `tokenFingerprint`.
pub fn token_fingerprint(token: &str) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(token.as_bytes());
    digest.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// Prefix of a vault-custody tombstone: the non-secret marker a custody
/// setup writes into a host credential slot in place of a real OAuth pair
/// (`{"access": "", "refresh": "claustrum-tombstone:v1:anthropic"}`).
///
/// Recognition is provider-scoped ([`custody_tombstone_key`]) but refusal is
/// deliberately wider: every irreversible boundary (token exchange, bearer
/// header) rejects *any* value with this prefix, including a foreign
/// provider's tombstone.
pub const CUSTODY_TOMBSTONE_PREFIX: &str = "claustrum-tombstone:v1:";

/// The exact tombstone value for `provider` (e.g. `anthropic`).
pub fn custody_tombstone_key(provider: &str) -> String {
    format!("{CUSTODY_TOMBSTONE_PREFIX}{provider}")
}

/// Whether `value` is a custody tombstone for any provider.
pub fn is_custody_tombstone(value: &str) -> bool {
    value.starts_with(CUSTODY_TOMBSTONE_PREFIX)
}

/// Refuse a tombstone at an irreversible boundary (refresh, bearer header).
pub fn ensure_not_custody_tombstone(value: &str, provider: &str) -> Result<()> {
    if is_custody_tombstone(value) {
        return Err(Error::CustodyTombstone {
            provider: provider.to_owned(),
        });
    }
    Ok(())
}

/// The account descriptor returned alongside a token grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenAccount {
    /// Account UUID.
    pub uuid: String,
    /// Account email, when the grant included it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_address: Option<String>,
}

/// The organization descriptor returned alongside a token grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenOrganization {
    /// Organization UUID.
    pub uuid: String,
}

/// A complete OAuth session: the token pair, its absolute expiry, the granted
/// scopes, and the account/org it belongs to.
#[derive(Clone, Serialize, Deserialize)]
pub struct OAuthTokens {
    /// Current access token.
    pub access: AccessToken,
    /// Refresh token used to renew [`OAuthTokens::access`].
    pub refresh: RefreshToken,
    /// Absolute access-token expiry, persisted as epoch milliseconds.
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub expires_at: DateTime<Utc>,
    /// Absolute refresh-token expiry when the grant reports one.
    #[serde(
        default,
        with = "chrono::serde::ts_milliseconds_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub refresh_expires_at: Option<DateTime<Utc>>,
    /// Granted scopes (space-split from the token response).
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Account descriptor, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<TokenAccount>,
    /// Organization descriptor, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<TokenOrganization>,
}

impl OAuthTokens {
    /// Whether the access token is already past its expiry at `now`.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }

    /// Whether the access token is expired or within [`REFRESH_LEEWAY_SECS`] of
    /// expiry — i.e. it should be refreshed proactively.
    pub fn needs_refresh(&self, now: DateTime<Utc>) -> bool {
        now + Duration::seconds(REFRESH_LEEWAY_SECS) >= self.expires_at
    }

    /// Whether the refresh token can no longer renew this session.
    pub fn is_refresh_expired(&self, now: DateTime<Utc>) -> bool {
        self.refresh_expires_at
            .is_some_and(|expires_at| now >= expires_at)
    }

    /// Whether the granted scopes permit inference. A session without
    /// `user:inference` cannot be used to sample and should be treated as
    /// unusable.
    pub fn grants_inference(&self) -> bool {
        endpoints::grants_inference(&self.scopes)
    }
}

impl fmt::Debug for OAuthTokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthTokens")
            .field("access", &self.access)
            .field("refresh", &self.refresh)
            .field("expires_at", &self.expires_at)
            .field("refresh_expires_at", &self.refresh_expires_at)
            .field("scopes", &self.scopes)
            .field("account", &self.account)
            .field("organization", &self.organization)
            .finish()
    }
}

/// The kind of credential backing a request: an OAuth session or a static API
/// key. Serialized with an internal `type` tag, matching the on-disk shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Credential {
    /// A Claude.ai / Console subscription OAuth session.
    Oauth(OAuthTokens),
    /// A static `sk-ant-api…` key.
    ///
    /// A struct variant, not a newtype: serde's internally-tagged
    /// representation cannot serialize a newtype variant wrapping a primitive,
    /// so `ApiKey(ApiKey)` fails at runtime the moment such a credential is
    /// persisted.
    ApiKey {
        /// The static key.
        key: ApiKey,
    },
}

/// The HTTP header a credential contributes to an outgoing Anthropic request.
/// OAuth and API-key auth are mutually exclusive: an OAuth request carries a
/// bearer token (and the OAuth beta) and never an `x-api-key`, and vice versa.
#[derive(Clone, PartialEq, Eq)]
pub enum AuthHeader {
    /// `Authorization: Bearer <access token>`, paired with the OAuth beta.
    Bearer(String),
    /// `x-api-key: <api key>`.
    ApiKey(String),
}

impl fmt::Debug for AuthHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bearer(_) => formatter.write_str("AuthHeader::Bearer(***)"),
            Self::ApiKey(_) => formatter.write_str("AuthHeader::ApiKey(***)"),
        }
    }
}

impl Credential {
    /// The auth header this credential contributes.
    pub fn auth_header(&self) -> AuthHeader {
        match self {
            Credential::Oauth(tokens) => AuthHeader::Bearer(tokens.access.expose().to_owned()),
            Credential::ApiKey { key } => AuthHeader::ApiKey(key.expose().to_owned()),
        }
    }

    /// Whether this credential authenticates via OAuth (and therefore needs the
    /// `anthropic-beta: oauth-2025-04-20` header).
    pub fn is_oauth(&self) -> bool {
        matches!(self, Credential::Oauth(_))
    }

    /// Whether this credential should be renewed before use at `now`.
    pub fn needs_refresh(&self, now: DateTime<Utc>) -> bool {
        match self {
            Credential::Oauth(tokens) => tokens.needs_refresh(now),
            Credential::ApiKey { .. } => false,
        }
    }

    /// Refuse request dispatch when the credential is known unusable and should
    /// first be refreshed or re-authenticated.
    pub fn validate_for_request(&self, now: DateTime<Utc>) -> Result<()> {
        match self {
            Credential::ApiKey { .. } => Ok(()),
            Credential::Oauth(tokens) => {
                ensure_not_custody_tombstone(tokens.access.expose(), "anthropic")?;
                ensure_not_custody_tombstone(tokens.refresh.expose(), "anthropic")?;
                if !tokens.grants_inference() {
                    return Err(Error::Protocol(
                        "oauth credential lacks user:inference".into(),
                    ));
                }
                if tokens.needs_refresh(now) {
                    if tokens.is_refresh_expired(now) {
                        return Err(Error::RefreshTokenExpired);
                    }
                    return Err(Error::ExpiredNoRefresh);
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0).unwrap()
    }

    #[test]
    fn token_validators_accept_real_shapes_reject_junk() {
        assert!(is_valid_access_token(
            "sk-ant-oat01-abcdefghijklmnopqrstuvwxyz012345"
        ));
        assert!(is_valid_refresh_token(
            "sk-ant-ort01-abcdefghijklmnopqrstuvwxyz012345"
        ));
        assert!(is_valid_api_key(
            "sk-ant-api01-abcdefghijklmnopqrstuvwxyz012345"
        ));
        // Wrong family.
        assert!(!is_valid_access_token(
            "sk-ant-ort01-abcdefghijklmnopqrstuvwxyz012345"
        ));
        // Body too short.
        assert!(!is_valid_access_token("sk-ant-oat01-tooshort"));
        // Missing version digits.
        assert!(!is_valid_access_token(
            "sk-ant-oat-abcdefghijklmnopqrstuvwxyz012345"
        ));
        // Over the length cap.
        assert!(!is_valid_access_token(&format!(
            "sk-ant-oat01-{}",
            "a".repeat(MAX_TOKEN_LEN)
        )));
    }

    #[test]
    fn expiry_and_refresh_window() {
        let tokens = OAuthTokens {
            access: AccessToken::new("a"),
            refresh: RefreshToken::new("r"),
            expires_at: at(1_000),
            refresh_expires_at: None,
            scopes: vec!["user:inference".into()],
            account: None,
            organization: None,
        };
        assert!(!tokens.is_expired(at(900)));
        assert!(tokens.is_expired(at(1_000)));
        // Inside the 5-minute (300s) leeway → needs refresh though not expired.
        assert!(!tokens.is_expired(at(800)));
        assert!(tokens.needs_refresh(at(800)));
        assert!(!tokens.needs_refresh(at(699)));
    }

    #[test]
    fn grants_inference_reflects_scopes() {
        let mut tokens = OAuthTokens {
            access: AccessToken::new("a"),
            refresh: RefreshToken::new("r"),
            expires_at: at(1_000),
            refresh_expires_at: None,
            scopes: vec!["user:profile".into()],
            account: None,
            organization: None,
        };
        assert!(!tokens.grants_inference());
        tokens.scopes.push("user:inference".into());
        assert!(tokens.grants_inference());
    }

    #[test]
    fn oauth_request_validation_requires_refresh_before_send() {
        let credential = Credential::Oauth(OAuthTokens {
            access: AccessToken::new("a"),
            refresh: RefreshToken::new("r"),
            expires_at: at(1_000),
            refresh_expires_at: Some(at(2_000)),
            scopes: vec!["user:inference".into()],
            account: None,
            organization: None,
        });
        assert!(matches!(
            credential.validate_for_request(at(800)),
            Err(Error::ExpiredNoRefresh)
        ));
        assert!(credential.validate_for_request(at(600)).is_ok());
    }

    #[test]
    fn oauth_request_validation_rejects_missing_inference_or_expired_refresh() {
        let missing_scope = Credential::Oauth(OAuthTokens {
            access: AccessToken::new("a"),
            refresh: RefreshToken::new("r"),
            expires_at: at(1_000),
            refresh_expires_at: Some(at(2_000)),
            scopes: vec!["user:profile".into()],
            account: None,
            organization: None,
        });
        assert!(matches!(
            missing_scope.validate_for_request(at(0)),
            Err(Error::Protocol(_))
        ));

        let expired_refresh = Credential::Oauth(OAuthTokens {
            access: AccessToken::new("a"),
            refresh: RefreshToken::new("r"),
            expires_at: at(1_000),
            refresh_expires_at: Some(at(700)),
            scopes: vec!["user:inference".into()],
            account: None,
            organization: None,
        });
        assert!(matches!(
            expired_refresh.validate_for_request(at(800)),
            Err(Error::RefreshTokenExpired)
        ));
    }

    #[test]
    fn credential_auth_header_is_mutually_exclusive() {
        let oauth = Credential::Oauth(OAuthTokens {
            access: AccessToken::new("secret-access"),
            refresh: RefreshToken::new("secret-refresh"),
            expires_at: at(1_000),
            refresh_expires_at: None,
            scopes: vec![],
            account: None,
            organization: None,
        });
        assert_eq!(
            oauth.auth_header(),
            AuthHeader::Bearer("secret-access".into())
        );
        assert!(oauth.is_oauth());
        assert!(!format!("{:?}", oauth.auth_header()).contains("secret-access"));

        let key = Credential::ApiKey {
            key: ApiKey::new("sk-ant-api01-xyz"),
        };
        assert_eq!(
            key.auth_header(),
            AuthHeader::ApiKey("sk-ant-api01-xyz".into())
        );
        assert!(!key.is_oauth());
        // A static key never expires, so it never needs a refresh.
        assert!(!key.needs_refresh(at(i64::from(u32::MAX))));
    }

    #[test]
    fn debug_redacts_secrets() {
        let t = AccessToken::new("sk-ant-oat01-supersecret");
        assert_eq!(format!("{t:?}"), "AccessToken(***)");
        let r = RefreshToken::new("sk-ant-ort01-supersecret");
        assert_eq!(format!("{r:?}"), "RefreshToken(***)");
        let k = ApiKey::new("sk-ant-api01-supersecret");
        assert_eq!(format!("{k:?}"), "ApiKey(***)");
    }

    #[test]
    fn redact_secrets_hides_tokens_but_keeps_context() {
        let msg = "grant failed for sk-ant-ort01-supersecretvalue123 at endpoint";
        let redacted = redact_secrets(msg);
        assert!(!redacted.contains("supersecret"));
        assert!(redacted.contains("sk-ant-***REDACTED***"));
        assert!(redacted.contains("at endpoint"));
    }

    #[test]
    fn redact_secrets_handles_multibyte_and_no_match() {
        assert_eq!(redact_secrets("héllo wörld"), "héllo wörld");
        let out = redact_secrets("é sk-ant-oat01-aaaaaaaaaaaaaaaaaaaa é");
        assert!(out.starts_with("é sk-ant-***REDACTED***"));
        assert!(out.ends_with("é"));
    }

    #[test]
    fn oauth_tokens_roundtrip_epoch_millis() {
        let tokens = OAuthTokens {
            access: AccessToken::new("a"),
            refresh: RefreshToken::new("r"),
            expires_at: at(1_700_000_000),
            refresh_expires_at: Some(at(1_800_000_000)),
            scopes: vec!["user:inference".into()],
            account: Some(TokenAccount {
                uuid: "u".into(),
                email_address: Some("e@example.com".into()),
            }),
            organization: Some(TokenOrganization { uuid: "o".into() }),
        };
        let json = serde_json::to_string(&tokens).unwrap();
        assert!(
            json.contains("1700000000000"),
            "expires_at as epoch ms: {json}"
        );
        assert!(json.contains("1800000000000"), "refresh expiry: {json}");
        let back: OAuthTokens = serde_json::from_str(&json).unwrap();
        assert_eq!(back.expires_at, tokens.expires_at);
        assert_eq!(back.refresh_expires_at, tokens.refresh_expires_at);
        assert_eq!(back.access.expose(), "a");
    }
}

#[cfg(test)]
mod custody_tombstone_tests {
    use super::*;

    fn session(access: &str, refresh: &str) -> Credential {
        Credential::Oauth(OAuthTokens {
            access: AccessToken::new(access),
            refresh: RefreshToken::new(refresh),
            expires_at: Utc::now() + Duration::hours(1),
            refresh_expires_at: None,
            scopes: vec!["user:inference".into()],
            account: None,
            organization: None,
        })
    }

    #[test]
    fn tombstones_are_recognized_per_provider_and_refused_for_any_provider() {
        assert_eq!(
            custody_tombstone_key("anthropic"),
            "claustrum-tombstone:v1:anthropic"
        );
        assert!(is_custody_tombstone("claustrum-tombstone:v1:openai"));
        assert!(!is_custody_tombstone("sk-ant-ort01-real"));
        let foreign = ensure_not_custody_tombstone("claustrum-tombstone:v1:openai", "anthropic");
        assert!(matches!(foreign, Err(Error::CustodyTombstone { .. })));
    }

    #[test]
    fn request_validation_refuses_a_tombstoned_session() {
        let now = Utc::now();
        let tombstoned = session(
            "sk-ant-oat01-aaaaaaaaaaaaaaaaaaaaaaaa",
            &custody_tombstone_key("anthropic"),
        );
        assert!(matches!(
            tombstoned.validate_for_request(now),
            Err(Error::CustodyTombstone { .. })
        ));
        let live = session(
            "sk-ant-oat01-aaaaaaaaaaaaaaaaaaaaaaaa",
            "sk-ant-ort01-bbbbbbbbbbbbbbbbbbbbbbbb",
        );
        assert!(live.validate_for_request(now).is_ok());
    }
}
