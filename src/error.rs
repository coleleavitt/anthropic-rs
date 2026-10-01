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

    /// Anthropic rejected this refresh token with `invalid_grant` (the token
    /// family is revoked). It is never presented again; the user must
    /// re-authenticate. `origin` says whether the endpoint said so just now
    /// or a local record of an earlier verdict short-circuited the call.
    #[error(
        "oauth refresh token was revoked by anthropic ({origin}); re-authentication is required"
    )]
    RefreshTokenRevoked {
        /// Where the verdict came from.
        origin: RevocationOrigin,
    },

    /// The shared refresh declined to spend the refresh token because it
    /// could not establish exclusive, well-founded ownership of it (claim
    /// timed out, the account vanished, the store was unreadable, or the
    /// commit was superseded by an unusable row). Nothing was sent to the
    /// token endpoint; retrying later may succeed.
    #[error("oauth refresh refused (fail-closed): {0}")]
    RefreshRefused(String),

    /// Claude Code's credentials could not be read right now (its
    /// `.storage-write.lock` stayed held, the Keychain was locked or
    /// `security` failed or timed out, or an I/O error), for a store row
    /// that is linked to Claude Code's account. Without that read the row
    /// cannot be judged: a newer Claude Code login may have revoked the
    /// row's token, so the row is neither refreshed nor marked dead.
    /// Transient: retry after `retry_after_ms`.
    #[error("claude code's credentials are busy ({reason}); retry in {retry_after_ms} ms")]
    LinkBusy {
        /// Why the read failed (secret-free).
        reason: String,
        /// Suggested wait before retrying, in milliseconds.
        retry_after_ms: u64,
    },

    /// A network call did not finish inside its deadline. For a refresh this
    /// is deliberately shorter than the refresh claim, so the claim never
    /// lapses while the token is in flight. Transient; the token may or may
    /// not have been spent, and a result that arrives late is discarded.
    #[error("timed out: {0}")]
    Timeout(String),

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

    /// The configuration forbids the operation: e.g. OAuth test mode refused
    /// a non-loopback OAuth host. Nothing was sent.
    #[error("configuration error: {0}")]
    Config(String),

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

    /// A credential is a vault-custody tombstone (`claustrum-tombstone:v1:*`):
    /// a non-secret marker left where a vaulted credential used to live. It
    /// must never be presented to the token endpoint or sent as a bearer.
    #[error("{provider} OAuth credentials are vault-custodied; local token use is forbidden")]
    CustodyTombstone {
        /// Provider named by the tombstone (e.g. `anthropic`), when known.
        provider: String,
    },

    /// A private JSON document (credential store, native credential file,
    /// device identity) is corrupt. Carries only the position: parser text
    /// can echo token bytes and is never surfaced.
    #[error("{what} is not valid JSON (line {line}, column {column})")]
    InvalidJson {
        /// Which document failed to parse.
        what: &'static str,
        /// 1-based line of the failure.
        line: usize,
        /// 1-based column of the failure.
        column: usize,
    },
}

/// Where an [`Error::RefreshTokenRevoked`] verdict came from.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RevocationOrigin {
    /// The token endpoint answered just now (HTTP 400, `invalid_grant`).
    Endpoint {
        /// HTTP status of the answer.
        status: u16,
        /// The parsed OAuth `error` code.
        error_code: Option<String>,
    },
    /// This process already saw the endpoint reject the token; nothing was
    /// sent.
    LocalDeadSet,
    /// The store's dead-token record (`dead_refresh_fingerprint`) matched the
    /// token at claim time; nothing was sent.
    DeadTokenClaim,
}

impl std::fmt::Display for RevocationOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Endpoint { status, error_code } => write!(
                f,
                "token endpoint answered HTTP {status} {}",
                error_code.as_deref().unwrap_or("without an error code")
            ),
            Self::LocalDeadSet => f.write_str("already rejected earlier in this process"),
            Self::DeadTokenClaim => f.write_str("the shared store records this token as dead"),
        }
    }
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
            Error::Timeout(_) => false,
            Error::StateMismatch
            | Error::ExpiredNoRefresh
            | Error::RefreshTokenExpired
            | Error::RefreshTokenRevoked { .. }
            | Error::MalformedTokenResponse(_)
            | Error::InvalidRedirect
            | Error::WouldDeleteAllAccounts
            | Error::StoreIsSymlink
            | Error::UnknownAccount(_)
            | Error::Url(_)
            | Error::Protocol(_)
            | Error::Callback(_)
            | Error::Crypto(_)
            | Error::Config(_)
            | Error::CustodyTombstone { .. } => true,
            Error::NoUsableAccount(_)
            | Error::RefreshRefused(_)
            | Error::LinkBusy { .. }
            | Error::Io(_)
            | Error::Random(_)
            | Error::Federation(_)
            | Error::SecretStore(_) => false,
            #[cfg(feature = "client")]
            Error::Http(_) => false,
            Error::Serde(_) => false,
            // Same retry class as `Serde`, which it replaces for private documents.
            Error::InvalidJson { .. } => false,
        }
    }

    /// The server-advised retry cooldown in milliseconds, when the endpoint
    /// supplied one.
    pub fn retry_after_ms(&self) -> Option<i64> {
        match self {
            Error::Endpoint { retry_after_ms, .. } => *retry_after_ms,
            Error::LinkBusy { retry_after_ms, .. } => i64::try_from(*retry_after_ms).ok(),
            _ => None,
        }
    }

    /// Where a [`Error::RefreshTokenRevoked`] verdict came from; `None` for
    /// every other error.
    pub fn revocation_origin(&self) -> Option<&RevocationOrigin> {
        match self {
            Error::RefreshTokenRevoked { origin } => Some(origin),
            _ => None,
        }
    }

    /// The revocation this endpoint error amounts to, when it is a real
    /// `invalid_grant` (see [`Error::is_invalid_grant`]).
    pub fn into_revocation(self) -> std::result::Result<Error, Error> {
        match self {
            Error::Endpoint {
                status: 400,
                error_code: Some(code),
                ..
            } if code == "invalid_grant" => Ok(Error::RefreshTokenRevoked {
                origin: RevocationOrigin::Endpoint {
                    status: 400,
                    error_code: Some(code),
                },
            }),
            revoked @ Error::RefreshTokenRevoked { .. } => Ok(revoked),
            other => Err(other),
        }
    }

    /// Whether this failure means the account hit a rate limit and should be
    /// rotated away from rather than disabled.
    pub fn is_rate_limited(&self) -> bool {
        matches!(self, Error::Endpoint { status: 429, .. })
    }

    /// Whether the token endpoint rejected the refresh token: HTTP 400 whose
    /// parsed `error` is exactly `invalid_grant`, or the local
    /// [`Error::RefreshTokenRevoked`] verdict. Nothing else qualifies — not a
    /// body that merely mentions the text, not another status, not another
    /// OAuth error code — because this is the only signal that marks a token
    /// dead, and a false positive strands a working login.
    pub fn is_invalid_grant(&self) -> bool {
        match self {
            Error::RefreshTokenRevoked { .. } => true,
            Error::Endpoint {
                status: 400,
                error_code,
                ..
            } => error_code.as_deref() == Some("invalid_grant"),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(status: u16, error_code: Option<&str>, body: &str) -> Error {
        Error::Endpoint {
            status,
            permanent: true,
            error_code: error_code.map(str::to_owned),
            retry_after_ms: None,
            body: body.to_owned(),
        }
    }

    #[test]
    fn only_a_400_with_the_invalid_grant_code_is_invalid_grant() {
        assert!(endpoint(400, Some("invalid_grant"), "").is_invalid_grant());
        assert!(
            Error::RefreshTokenRevoked {
                origin: RevocationOrigin::LocalDeadSet
            }
            .is_invalid_grant()
        );
        let revoked = endpoint(400, Some("invalid_grant"), "")
            .into_revocation()
            .unwrap();
        assert_eq!(
            revoked.revocation_origin(),
            Some(&RevocationOrigin::Endpoint {
                status: 400,
                error_code: Some("invalid_grant".into())
            })
        );
        assert!(
            endpoint(401, Some("invalid_grant"), "")
                .into_revocation()
                .is_err()
        );
        // The body merely mentioning it is not the verdict.
        assert!(!endpoint(400, None, "upstream said invalid_grant somewhere").is_invalid_grant());
        assert!(!endpoint(400, Some("invalid_client"), "invalid_grant").is_invalid_grant());
        // Any other status is not the verdict either.
        assert!(!endpoint(401, Some("invalid_grant"), "").is_invalid_grant());
        assert!(!endpoint(500, Some("invalid_grant"), "").is_invalid_grant());
        assert!(!Error::Timeout("refresh".into()).is_permanent());
    }
}
