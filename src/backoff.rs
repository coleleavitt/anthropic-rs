//! Persisted refresh / quota failure records and the backoff they arm.
//!
//! Ported from anthropic-auth's `AccountOperationError` family
//! (`buildRefreshOperationError`, `isPermanentRefreshError`,
//! `refreshBackoffActive`, `buildQuotaOperationError`,
//! `quotaBackoffActive`) and `network-errors.ts`, at upstream `b504bc8`.
//!
//! Two upstream fixes are load-bearing here:
//!
//! * **f095ad5** — a refresh failure records the fingerprint of the refresh
//!   token that produced it, and an active backoff is ignored once the
//!   current credential's fingerprint differs. Without it a permanent
//!   `invalid_grant` latch outlives the re-login that fixed it.
//! * Only `400 invalid_grant` is *permanent* (re-login required). Other 400s
//!   (`invalid_client`, …) and retry-exhausted network failures get long
//!   backoffs but are never reported as dead tokens.
//!
//! All times are epoch milliseconds.

use serde::{Deserialize, Serialize};

use crate::error::Error;

/// Refresh retry floor (also the fixed delay after a network failure).
pub const MIN_REFRESH_RETRY_DELAY_MS: i64 = 5 * 60_000;
/// Refresh retry ceiling for transient (429/5xx) failures.
pub const MAX_REFRESH_RETRY_DELAY_MS: i64 = 60 * 60_000;
/// Delay after a non-transient refresh failure.
pub const NON_TRANSIENT_REFRESH_RETRY_DELAY_MS: i64 = 24 * 60 * 60_000;
/// Quota-poll retry floor.
pub const MIN_QUOTA_RETRY_DELAY_MS: i64 = 60_000;
/// Quota-poll retry ceiling.
pub const MAX_QUOTA_RETRY_DELAY_MS: i64 = 15 * 60_000;
/// Delay after a non-transient quota failure.
pub const NON_TRANSIENT_QUOTA_RETRY_DELAY_MS: i64 = 5 * 60_000;

/// Node/undici/Bun error codes that mean "the network, not the server":
/// the merged union of upstream's set and the fork's mirror of Claude Code's
/// `sie` (reset-like) and `gde` (connect-like) sets (`network-errors.ts`).
pub const TRANSIENT_NETWORK_ERROR_CODES: [&str; 18] = [
    "EAI_AGAIN",
    "ECONNREFUSED",
    "ECONNRESET",
    "EHOSTUNREACH",
    "ENETUNREACH",
    "ENOTFOUND",
    "ETIMEDOUT",
    "UND_ERR_CONNECT_TIMEOUT",
    "EPIPE",
    "ConnectionClosed",
    "ECONNABORTED",
    "ERR_SOCKET_CLOSED",
    "StreamSuspended",
    "ConnectionRefused",
    "ENETDOWN",
    "EHOSTDOWN",
    "FailedToOpenSocket",
    "ERR_PROXY_TUNNEL",
];

/// Whether an error message describes a transient network failure
/// (a known code, or `fetch failed`).
pub fn is_transient_network_message(message: &str) -> bool {
    message.contains("fetch failed")
        || TRANSIENT_NETWORK_ERROR_CODES
            .iter()
            .any(|code| message.contains(code))
}

/// Whether a crate error is a transient network failure: a transport error
/// that never produced an HTTP status, or an I/O error of a connect/timeout
/// kind.
pub fn is_transient_network_error(error: &Error) -> bool {
    match error {
        #[cfg(feature = "client")]
        Error::Http(http) => {
            http.status().is_none() && (http.is_connect() || http.is_timeout() || http.is_request())
        }
        Error::Io(io) => matches!(
            io.kind(),
            std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::NotConnected
                | std::io::ErrorKind::HostUnreachable
                | std::io::ErrorKind::NetworkUnreachable
                | std::io::ErrorKind::NetworkDown
                | std::io::ErrorKind::BrokenPipe
        ),
        _ => false,
    }
}

/// A persisted refresh or quota failure (anthropic-auth's
/// `AccountOperationError`). The message is secret-redacted at construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationError {
    /// Redacted failure text.
    pub message: String,
    /// When the failure was observed.
    pub checked_at: i64,
    /// Earliest next attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_retry_at: Option<i64>,
    /// Consecutive failures for the same identity (and token).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_count: Option<u32>,
    /// Stable account identity the failure belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_identity: Option<String>,
    /// Fingerprint of the refresh token that produced a refresh failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token_fingerprint: Option<String>,
    /// HTTP status of the failure, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// `true` only for `400 invalid_grant` (dead token → re-login).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permanent: Option<bool>,
}

/// What a failed refresh looked like, reduced from whatever error type the
/// caller holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FailureFacts {
    /// Failure text (redacted before storage).
    pub message: String,
    /// HTTP status, when one was received.
    pub status: Option<u16>,
    /// Response body, when one was received (redacted, only searched).
    pub body: String,
    /// Server-directed retry delay in seconds (`retry-after`).
    pub retry_after_secs: Option<i64>,
    /// The failure never reached HTTP (DNS, connect, reset, timeout).
    pub network: bool,
}

impl FailureFacts {
    /// Reduce a crate error.
    pub fn from_error(error: &Error) -> Self {
        let (status, body, retry_after_secs) = match error {
            Error::Endpoint {
                status,
                body,
                retry_after_ms,
                error_code,
                ..
            } => (
                Some(*status),
                match error_code {
                    Some(code) if !body.contains(code.as_str()) => format!("{code} {body}"),
                    _ => body.clone(),
                },
                retry_after_ms.map(|ms| (ms + 999) / 1000),
            ),
            #[cfg(feature = "client")]
            Error::Http(http) => (http.status().map(|s| s.as_u16()), String::new(), None),
            _ => (None, String::new(), None),
        };
        let message = error.to_string();
        Self {
            network: is_transient_network_error(error)
                || (status.is_none() && is_transient_network_message(&message)),
            message,
            status,
            body,
            retry_after_secs,
        }
    }

    fn is_transient_status(&self) -> bool {
        self.status.is_some_and(|s| s == 429 || s >= 500)
    }
}

fn exponential(min: i64, max: i64, retry_count: u32) -> i64 {
    let shift = retry_count.saturating_sub(1).min(6);
    (min << shift).min(max)
}

/// Record a refresh failure. The retry count continues only for the same
/// account identity *and* refresh-token fingerprint.
pub fn build_refresh_operation_error(
    facts: &FailureFacts,
    now: i64,
    account_identity: Option<&str>,
    refresh_token_fingerprint: Option<&str>,
    previous: Option<&OperationError>,
) -> OperationError {
    let previous_count = previous
        .filter(|p| {
            p.account_identity.as_deref() == account_identity
                && p.refresh_token_fingerprint.as_deref() == refresh_token_fingerprint
        })
        .and_then(|p| p.retry_count)
        .unwrap_or(0);
    let retry_count = previous_count + 1;
    let delay = match facts.retry_after_secs.filter(|s| *s > 0) {
        Some(seconds) => seconds.saturating_mul(1000),
        None if facts.network => MIN_REFRESH_RETRY_DELAY_MS,
        None if facts.is_transient_status() => exponential(
            MIN_REFRESH_RETRY_DELAY_MS,
            MAX_REFRESH_RETRY_DELAY_MS,
            retry_count,
        ),
        None => NON_TRANSIENT_REFRESH_RETRY_DELAY_MS,
    };
    let invalid_grant =
        facts.body.contains("invalid_grant") || facts.message.contains("invalid_grant");
    OperationError {
        message: crate::token::redact_secrets(&facts.message),
        checked_at: now,
        next_retry_at: Some(now.saturating_add(delay)),
        retry_count: Some(retry_count),
        account_identity: account_identity.map(str::to_owned),
        refresh_token_fingerprint: refresh_token_fingerprint.map(str::to_owned),
        status: facts.status,
        permanent: Some(facts.status == Some(400) && invalid_grant),
    }
}

/// Whether a refresh failure means the token is dead and the account needs a
/// re-login. Precedence: the explicit `permanent` flag; else a captured
/// status (400); else — only for records predating both fields — the legacy
/// 24h-delay heuristic.
pub fn is_permanent_refresh_error(error: Option<&OperationError>) -> bool {
    let Some(error) = error else {
        return false;
    };
    if let Some(permanent) = error.permanent {
        return permanent;
    }
    if let Some(status) = error.status {
        return status == 400;
    }
    if is_transient_network_message(&error.message) {
        return false;
    }
    error
        .next_retry_at
        .is_some_and(|at| at - error.checked_at >= NON_TRANSIENT_REFRESH_RETRY_DELAY_MS)
}

fn effective_refresh_retry_at(error: &OperationError) -> Option<i64> {
    let persisted = error.next_retry_at?;
    if !is_transient_network_message(&error.message) {
        return Some(persisted);
    }
    // Connectivity recovery must not inherit an hour-long backoff.
    Some(persisted.min(error.checked_at + MIN_REFRESH_RETRY_DELAY_MS))
}

/// Whether a recorded refresh failure still blocks a refresh of
/// `account_identity` holding `current_refresh_fingerprint` at `now`. A
/// record from a *different* refresh token (a re-login) never blocks.
pub fn refresh_backoff_active(
    error: Option<&OperationError>,
    account_identity: Option<&str>,
    now: i64,
    current_refresh_fingerprint: Option<&str>,
) -> bool {
    let Some(error) = error else {
        return false;
    };
    match effective_refresh_retry_at(error) {
        Some(at) if at > now => {}
        _ => return false,
    }
    if let (Some(recorded), Some(current)) = (
        error.refresh_token_fingerprint.as_deref(),
        current_refresh_fingerprint,
    ) && recorded != current
    {
        return false;
    }
    match (error.account_identity.as_deref(), account_identity) {
        (Some(recorded), Some(current)) => recorded == current,
        _ => true,
    }
}

/// `Claude OAuth refresh is backed off for Ns after: …`.
pub fn format_refresh_backoff_message(error: &OperationError, now: i64) -> String {
    let at = effective_refresh_retry_at(error).unwrap_or(now);
    let seconds = ((at - now) as f64 / 1000.0).ceil().max(1.0) as i64;
    format!(
        "Claude OAuth refresh is backed off for {seconds}s after: {}",
        error.message
    )
}

/// Whether a quota failure is transient (429/5xx, a lock contention, or the
/// network).
pub fn is_transient_quota_failure(facts: &FailureFacts) -> bool {
    facts.is_transient_status()
        || facts
            .message
            .contains("Quota refresh is already in progress")
        || facts.network
}

/// Whether a quota failure is an auth/policy problem (401/403) rather than
/// endpoint saturation. These surface without arming quota backoff so the
/// caller can refresh, re-auth or move to another account immediately.
pub fn is_quota_auth_failure(facts: &FailureFacts) -> bool {
    matches!(facts.status, Some(401 | 403))
}

/// Record a quota failure. The retry count continues only for the same
/// account identity.
pub fn build_quota_operation_error(
    facts: &FailureFacts,
    now: i64,
    account_identity: Option<&str>,
    previous: Option<&OperationError>,
) -> OperationError {
    let previous_count = previous
        .filter(|p| p.account_identity.as_deref() == account_identity)
        .and_then(|p| p.retry_count)
        .unwrap_or(0);
    let retry_count = previous_count + 1;
    let delay = if is_transient_quota_failure(facts) {
        exponential(
            MIN_QUOTA_RETRY_DELAY_MS,
            MAX_QUOTA_RETRY_DELAY_MS,
            retry_count,
        )
    } else {
        NON_TRANSIENT_QUOTA_RETRY_DELAY_MS
    };
    OperationError {
        message: crate::token::redact_secrets(&facts.message),
        checked_at: now,
        next_retry_at: Some(now.saturating_add(delay)),
        retry_count: Some(retry_count),
        account_identity: account_identity.map(str::to_owned),
        refresh_token_fingerprint: None,
        status: facts.status,
        permanent: None,
    }
}

/// Whether a quota failure's backoff is still running.
pub fn quota_backoff_active(error: Option<&OperationError>, now: i64) -> bool {
    error
        .and_then(|e| e.next_retry_at)
        .is_some_and(|at| at > now)
}

/// Monotonic merge of two "error cleared at" stamps.
pub fn merge_cleared_at(existing: Option<i64>, incoming: Option<i64>) -> Option<i64> {
    match (existing, incoming) {
        (_, None) => existing,
        (None, Some(_)) => incoming,
        (Some(a), Some(b)) => Some(a.max(b)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000_000;

    fn http(status: u16, body: &str) -> FailureFacts {
        FailureFacts {
            message: format!("Claude OAuth refresh failed: {status} — {body}"),
            status: Some(status),
            body: body.into(),
            ..Default::default()
        }
    }

    #[test]
    fn only_400_invalid_grant_is_permanent() {
        let dead = build_refresh_operation_error(
            &http(400, r#"{"error":"invalid_grant"}"#),
            NOW,
            Some("a"),
            Some("fp1"),
            None,
        );
        assert_eq!(dead.permanent, Some(true));
        assert!(is_permanent_refresh_error(Some(&dead)));
        assert_eq!(
            dead.next_retry_at,
            Some(NOW + NON_TRANSIENT_REFRESH_RETRY_DELAY_MS)
        );

        let client = build_refresh_operation_error(
            &http(400, r#"{"error":"invalid_client"}"#),
            NOW,
            Some("a"),
            Some("fp1"),
            None,
        );
        assert_eq!(client.permanent, Some(false));
        assert!(!is_permanent_refresh_error(Some(&client)));

        let network = FailureFacts {
            message: "fetch failed: ECONNRESET".into(),
            network: true,
            ..Default::default()
        };
        let net = build_refresh_operation_error(&network, NOW, Some("a"), None, None);
        assert_eq!(net.next_retry_at, Some(NOW + MIN_REFRESH_RETRY_DELAY_MS));
        assert!(!is_permanent_refresh_error(Some(&net)));
    }

    #[test]
    fn transient_refresh_backoff_grows_per_identity_and_token() {
        let first = build_refresh_operation_error(&http(503, ""), NOW, Some("a"), Some("fp"), None);
        let second =
            build_refresh_operation_error(&http(503, ""), NOW, Some("a"), Some("fp"), Some(&first));
        assert_eq!(second.retry_count, Some(2));
        assert_eq!(
            second.next_retry_at,
            Some(NOW + 2 * MIN_REFRESH_RETRY_DELAY_MS)
        );
        let rotated = build_refresh_operation_error(
            &http(503, ""),
            NOW,
            Some("a"),
            Some("fp2"),
            Some(&second),
        );
        assert_eq!(rotated.retry_count, Some(1));
        let capped = (0..10).fold(first.clone(), |prev, _| {
            build_refresh_operation_error(&http(503, ""), NOW, Some("a"), Some("fp"), Some(&prev))
        });
        assert_eq!(capped.next_retry_at, Some(NOW + MAX_REFRESH_RETRY_DELAY_MS));
        let directed = FailureFacts {
            retry_after_secs: Some(42),
            ..http(429, "")
        };
        assert_eq!(
            build_refresh_operation_error(&directed, NOW, None, None, None).next_retry_at,
            Some(NOW + 42_000)
        );
    }

    #[test]
    fn a_permanent_latch_clears_when_the_refresh_token_rotates() {
        let dead = build_refresh_operation_error(
            &http(400, "invalid_grant"),
            NOW,
            Some("main"),
            Some("old"),
            None,
        );
        assert!(refresh_backoff_active(
            Some(&dead),
            Some("main"),
            NOW + 1,
            Some("old")
        ));
        assert!(!refresh_backoff_active(
            Some(&dead),
            Some("main"),
            NOW + 1,
            Some("new")
        ));
        assert!(!refresh_backoff_active(
            Some(&dead),
            Some("other"),
            NOW + 1,
            Some("old")
        ));
        // Unknown identity or fingerprint stays conservative.
        assert!(refresh_backoff_active(Some(&dead), None, NOW + 1, None));
        assert!(!refresh_backoff_active(
            Some(&dead),
            Some("main"),
            NOW + NON_TRANSIENT_REFRESH_RETRY_DELAY_MS,
            Some("old")
        ));
    }

    #[test]
    fn legacy_records_fall_back_to_status_then_delay_heuristic() {
        let legacy = OperationError {
            message: "boom".into(),
            checked_at: NOW,
            next_retry_at: Some(NOW + NON_TRANSIENT_REFRESH_RETRY_DELAY_MS),
            retry_count: None,
            account_identity: None,
            refresh_token_fingerprint: None,
            status: None,
            permanent: None,
        };
        assert!(is_permanent_refresh_error(Some(&legacy)));
        let with_status = OperationError {
            status: Some(503),
            ..legacy.clone()
        };
        assert!(!is_permanent_refresh_error(Some(&with_status)));
        let network = OperationError {
            message: "fetch failed".into(),
            ..legacy.clone()
        };
        assert!(!is_permanent_refresh_error(Some(&network)));
        // A persisted hour-long network backoff is capped at the floor.
        assert!(!refresh_backoff_active(
            Some(&network),
            None,
            NOW + MIN_REFRESH_RETRY_DELAY_MS,
            None
        ));
        assert!(format_refresh_backoff_message(&legacy, NOW).contains("86400s"));
    }

    #[test]
    fn quota_backoff_is_exponential_for_transient_and_fixed_otherwise() {
        let first = build_quota_operation_error(&http(429, ""), NOW, Some("a"), None);
        assert_eq!(first.next_retry_at, Some(NOW + MIN_QUOTA_RETRY_DELAY_MS));
        let second = build_quota_operation_error(&http(429, ""), NOW, Some("a"), Some(&first));
        assert_eq!(
            second.next_retry_at,
            Some(NOW + 2 * MIN_QUOTA_RETRY_DELAY_MS)
        );
        let other = build_quota_operation_error(&http(429, ""), NOW, Some("b"), Some(&second));
        assert_eq!(other.retry_count, Some(1));
        let fixed = build_quota_operation_error(&http(404, ""), NOW, Some("a"), None);
        assert_eq!(
            fixed.next_retry_at,
            Some(NOW + NON_TRANSIENT_QUOTA_RETRY_DELAY_MS)
        );
        assert!(quota_backoff_active(Some(&fixed), NOW));
        assert!(!quota_backoff_active(
            Some(&fixed),
            NOW + NON_TRANSIENT_QUOTA_RETRY_DELAY_MS
        ));
        assert!(is_quota_auth_failure(&http(403, "")));
        assert!(!is_quota_auth_failure(&http(429, "")));
    }

    #[test]
    fn messages_are_redacted_and_network_codes_recognized() {
        let facts = FailureFacts {
            message: "token sk-ant-ort01-abcdefghijklmnopqrstuvwxyz rejected".into(),
            ..Default::default()
        };
        let recorded = build_quota_operation_error(&facts, NOW, None, None);
        assert!(!recorded.message.contains("abcdefghijklmnop"));
        for code in TRANSIENT_NETWORK_ERROR_CODES {
            assert!(is_transient_network_message(&format!(
                "connect {code} 1.2.3.4"
            )));
        }
        assert!(!is_transient_network_message("400 invalid_grant"));
        // Merged union (network-errors.ts): the fork's Claude Code mirror.
        for code in [
            "EPIPE",
            "StreamSuspended",
            "ERR_PROXY_TUNNEL",
            "FailedToOpenSocket",
        ] {
            assert!(is_transient_network_message(&format!("socket: {code}")));
        }
        assert!(is_transient_network_error(&Error::Io(
            std::io::Error::from(std::io::ErrorKind::BrokenPipe)
        )));
        assert_eq!(merge_cleared_at(Some(5), Some(3)), Some(5));
        assert_eq!(merge_cleared_at(None, Some(3)), Some(3));
        assert_eq!(merge_cleared_at(Some(5), None), Some(5));
    }

    #[test]
    fn endpoint_errors_reduce_to_facts() {
        let error = Error::Endpoint {
            status: 400,
            permanent: true,
            error_code: Some("invalid_grant".into()),
            retry_after_ms: Some(1_500),
            body: "{}".into(),
        };
        let facts = FailureFacts::from_error(&error);
        assert_eq!(facts.status, Some(400));
        assert_eq!(facts.retry_after_secs, Some(2));
        assert!(!facts.network);
        let record = build_refresh_operation_error(&facts, NOW, None, None, None);
        assert_eq!(record.permanent, Some(true));
    }
}
