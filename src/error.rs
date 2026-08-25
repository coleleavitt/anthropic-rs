//! The crate error type.

use thiserror::Error;

/// Crate result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Everything that can go wrong resolving, refreshing, or persisting an
/// Anthropic credential, or calling the Messages API.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// An HTTP endpoint returned a non-success status. Use [`Error::is_permanent`]
    /// to decide whether a retry could ever succeed.
    #[error("anthropic endpoint returned HTTP {status}: {body}")]
    Endpoint {
        /// HTTP status code.
        status: u16,
        /// Whether the failure is unrecoverable (bad code, revoked refresh
        /// token) as opposed to transient (rate limit, 5xx).
        permanent: bool,
        /// Machine-readable error code, when the body carried one.
        error_code: Option<String>,
        /// Server-advised cooldown before retrying, parsed from a
        /// `retry-after` / `retry-after-ms` header (clamped to 24h).
        retry_after_ms: Option<i64>,
        /// Raw, token-redacted response body, safe to log.
        body: String,
    },

    /// The returned `state` did not match the locally generated one — a
    /// possible CSRF / interception attempt. The exchange is aborted.
    #[error("oauth state mismatch (possible CSRF); refusing code exchange")]
    StateMismatch,

    /// The OAuth access token is expired or inside the proactive refresh
    /// window; refresh it before sending an API request. The historical variant
    /// name is retained for compatibility.
    #[error("oauth access token must be refreshed before use")]
    ExpiredNoRefresh,

    /// The persisted refresh-token lifetime has ended; the user must
    /// re-authenticate instead of retrying the token endpoint.
    #[error("oauth refresh token has expired; re-authentication is required")]
    RefreshTokenExpired,

    /// The token response was missing or malformed in a field required for a
    /// usable session.
    #[error("token response invalid: {0}")]
    MalformedTokenResponse(&'static str),

    /// A manual-paste redirect value could not be parsed into `code#state`.
    #[error("could not parse authorization redirect value")]
    InvalidRedirect,

    /// Writing the credential store would have deleted the last account; the
    /// write was refused to avoid wiping credentials.
    #[error("refusing to persist a credential store with zero accounts")]
    WouldDeleteAllAccounts,

    /// The credential store path is a symlink; refused to read or write through
    /// it (a symlink-swap tampering guard).
    #[error("credential store path is a symlink; refusing to follow it")]
    StoreIsSymlink,

    /// No usable account remains: every account is disabled, rate-limited, or
    /// failed to refresh.
    #[error("no usable anthropic account: {0}")]
    NoUsableAccount(String),

    /// The named account does not exist in the store.
    #[error("no such account: {0}")]
    UnknownAccount(String),

    /// An authorization URL or endpoint could not be parsed.
    #[error("invalid url: {0}")]
    Url(#[from] url::ParseError),

    /// Underlying HTTP transport failure (connection, TLS, timeout).
    #[cfg(feature = "client")]
    #[error("http transport error: {0}")]
    Http(#[from] reqwest::Error),

    /// Credential store I/O failure.
    #[error("credential store i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// Credential (de)serialization failure.
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    /// A protocol value or transition was invalid.
    #[error("anthropic protocol error: {0}")]
    Protocol(String),

    /// The operating-system cryptographic random source failed.
    #[error("cryptographic random source failed: {0}")]
    Random(String),

    /// Automatic loopback OAuth completion failed.
    #[error("oauth callback error: {0}")]
    Callback(String),

    /// Workload identity federation failed.
    #[error("workload identity federation error: {0}")]
    Federation(String),

    /// Native secure storage failed.
    #[error("secure credential storage error: {0}")]
    SecretStore(String),

    /// Device key generation, encoding, or signing failed.
    #[error("device cryptography error: {0}")]
    Crypto(String),
}

#[cfg(feature = "client")]
pub(crate) async fn redacted_response_body(
    mut response: reqwest::Response,
    additional_secrets: &[&str],
) -> String {
    const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;

    let mut bytes = Vec::new();
    let mut truncated = false;
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                let remaining = MAX_ERROR_BODY_BYTES.saturating_sub(bytes.len());
                if chunk.len() > remaining {
                    bytes.extend_from_slice(&chunk[..remaining]);
                    truncated = true;
                    break;
                }
                bytes.extend_from_slice(&chunk);
                if bytes.len() == MAX_ERROR_BODY_BYTES {
                    truncated = true;
                    break;
                }
            }
            Ok(None) => break,
            Err(_) => return "<failed to read redacted endpoint response>".into(),
        }
    }
    let mut body = crate::token::redact_secrets(&String::from_utf8_lossy(&bytes));
    for secret in additional_secrets {
        if !secret.is_empty() {
            body = body.replace(secret, "***REDACTED***");
        }
    }
    if truncated {
        body.push_str("…<truncated>");
    }
    body
}

impl Error {
    /// Whether this represents an unrecoverable failure. Callers use this to
    /// decide between disabling an account and scheduling a retry.
    pub fn is_permanent(&self) -> bool {
        match self {
            Error::Endpoint { permanent, .. } => *permanent,
            Error::StateMismatch
            | Error::ExpiredNoRefresh
            | Error::RefreshTokenExpired
            | Error::MalformedTokenResponse(_)
            | Error::InvalidRedirect
            | Error::WouldDeleteAllAccounts
            | Error::StoreIsSymlink
            | Error::UnknownAccount(_)
            | Error::Url(_)
            | Error::Protocol(_)
            | Error::Callback(_)
            | Error::Crypto(_) => true,
            Error::NoUsableAccount(_)
            | Error::Io(_)
            | Error::Random(_)
            | Error::Federation(_)
            | Error::SecretStore(_) => false,
            #[cfg(feature = "client")]
            Error::Http(_) => false,
            Error::Serde(_) => false,
        }
    }

    /// The server-advised retry cooldown in milliseconds, when the endpoint
    /// supplied one.
    pub fn retry_after_ms(&self) -> Option<i64> {
        match self {
            Error::Endpoint { retry_after_ms, .. } => *retry_after_ms,
            _ => None,
        }
    }

    /// Whether this failure means the account hit a rate limit and should be
    /// rotated away from rather than disabled.
    pub fn is_rate_limited(&self) -> bool {
        matches!(self, Error::Endpoint { status: 429, .. })
    }
}
