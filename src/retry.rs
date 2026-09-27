//! Transport retry policy ported from Claude Code 2.1.241/2.1.260.
//!
//! The CLI retries 408/409/429/5xx, honours `retry-after-ms` then
//! `retry-after`, and otherwise backs off exponentially. The important part is
//! the split between a *soft* 429 (transient pressure) and a *hard* 429 (no
//! billing headroom for the period): a soft 429 is worth waiting out on the
//! same account, a hard one must rotate or surface immediately — an
//! `anthropic-ratelimit-unified-status: rejected` 429 with a 66-hour
//! `retry-after` must never be slept on.

/// Claude Code's default retry budget (user overrides are clamped to 15).
pub const DEFAULT_MAX_RETRIES: u32 = 10;
const BASE_BACKOFF_SECONDS: f64 = 0.5;
const MAX_BACKOFF_SECONDS: f64 = 8.0;
const JITTER_RATIO: f64 = 0.25;

/// `anthropic-ratelimit-unified-overage-disabled-reason`
pub const OVERAGE_DISABLED_REASON_HEADER: &str =
    "anthropic-ratelimit-unified-overage-disabled-reason";
/// `anthropic-ratelimit-unified-representative-claim`
pub const REPRESENTATIVE_CLAIM_HEADER: &str = "anthropic-ratelimit-unified-representative-claim";
/// `anthropic-ratelimit-unified-overage-status`
pub const OVERAGE_STATUS_HEADER: &str = "anthropic-ratelimit-unified-overage-status";
/// `anthropic-ratelimit-unified-status`
pub const UNIFIED_STATUS_HEADER: &str = "anthropic-ratelimit-unified-status";

/// Overage reasons that make a 429 permanent even alongside a unified claim
/// (the CLI's `G9f`).
const UNCONDITIONAL_HARD_REASONS: [&str; 2] = ["org_spend_cap_reached", "org_level_disabled_until"];
/// Overage reasons that make a 429 permanent only when no unified claim
/// contradicts them (the CLI's `$9f`).
const HARD_REASONS: [&str; 5] = [
    "org_spend_cap_reached",
    "org_level_disabled_until",
    "out_of_credits",
    "org_level_disabled",
    "org_service_level_disabled",
];
/// Reasons the CLI keeps retryable despite a credits-required body.
const SOFT_CREDIT_REASONS: [&str; 2] = ["fetch_error", "org_level_disabled_until"];

/// Case-insensitive header lookup over any header representation.
pub trait HeaderLookup {
    /// The first value of header `name` (case-insensitive), if present.
    fn header(&self, name: &str) -> Option<&str>;
}

impl HeaderLookup for [(String, String)] {
    fn header(&self, name: &str) -> Option<&str> {
        self.iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

impl HeaderLookup for Vec<(String, String)> {
    fn header(&self, name: &str) -> Option<&str> {
        self.as_slice().header(name)
    }
}

impl<const N: usize> HeaderLookup for [(&str, &str); N] {
    fn header(&self, name: &str) -> Option<&str> {
        self.iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
    }
}

impl HeaderLookup for [(&str, &str)] {
    fn header(&self, name: &str) -> Option<&str> {
        self.iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
    }
}

#[cfg(feature = "client")]
impl HeaderLookup for reqwest::header::HeaderMap {
    fn header(&self, name: &str) -> Option<&str> {
        self.get(name).and_then(|v| v.to_str().ok())
    }
}

fn header_value<'a>(headers: &'a (impl HeaderLookup + ?Sized), name: &str) -> Option<&'a str> {
    headers
        .header(name)
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

/// Whether the response carries a unified claim — the server described which
/// limit binds rather than leaving it unattributed (the CLI's `mWn`).
pub fn has_unified_claim(headers: &(impl HeaderLookup + ?Sized)) -> bool {
    header_value(headers, REPRESENTATIVE_CLAIM_HEADER).is_some()
        || header_value(headers, OVERAGE_STATUS_HEADER).is_some()
}

/// Verdict on a 429.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitClass {
    /// `true` when the limit is permanent for this billing period.
    pub hard: bool,
    /// The reason that decided it, when one was reported.
    pub reason: Option<String>,
}

/// Extract `"overageDisabledReason":"<reason>"` (possibly JSON-escaped) from a
/// body.
fn embedded_overage_reason(body: &str) -> Option<&str> {
    let key = "overageDisabledReason";
    let pos = body.find(key)?;
    let rest = &body[pos + key.len()..];
    // Skip `\"?` `:` whitespace `\"?` up to the value.
    let start = rest.find(|c: char| !matches!(c, '\\' | '"' | ':' | ' ' | '\t' | '\n' | '\r'))?;
    let value = &rest[start..];
    let end = value
        .find(|c: char| !(c.is_ascii_lowercase() || c == '_'))
        .unwrap_or(value.len());
    (end > 0).then(|| &value[..end])
}

/// Classify a 429 as hard or soft, mirroring the CLI's `Utw` plus its
/// `credits_required` pre-check. `body` may be empty when it has not been
/// read; that only loses body-derived signals.
pub fn classify_rate_limit(headers: &(impl HeaderLookup + ?Sized), body: &str) -> RateLimitClass {
    let reason = header_value(headers, OVERAGE_DISABLED_REASON_HEADER);
    let lowered = body.to_ascii_lowercase();
    if (lowered.contains("\"credits_required\"")
        || lowered.contains("usage credits are required")
        || lowered.contains("extra usage is required"))
        && !reason.is_some_and(|r| SOFT_CREDIT_REASONS.contains(&r))
    {
        return RateLimitClass {
            hard: true,
            reason: Some(reason.unwrap_or("credits_required").to_owned()),
        };
    }
    if body.contains("service_spend_limit_reached") {
        return RateLimitClass {
            hard: true,
            reason: Some("service_spend_limit_reached".into()),
        };
    }
    if let Some(reason) = reason {
        if UNCONDITIONAL_HARD_REASONS.contains(&reason)
            || (!has_unified_claim(headers) && HARD_REASONS.contains(&reason))
        {
            return RateLimitClass {
                hard: true,
                reason: Some(reason.to_owned()),
            };
        }
    }
    // An explicit `rejected` verdict is the server stating the account has no
    // headroom in the binding window; retrying is guaranteed to fail.
    if header_value(headers, UNIFIED_STATUS_HEADER) == Some("rejected") {
        return RateLimitClass {
            hard: true,
            reason: Some("unified_status_rejected".into()),
        };
    }
    if body.contains("exceeded_limit") {
        if let Some(matched) = embedded_overage_reason(body).filter(|r| HARD_REASONS.contains(r)) {
            return RateLimitClass {
                hard: true,
                reason: Some(matched.to_owned()),
            };
        }
    }
    RateLimitClass {
        hard: false,
        reason: reason.map(str::to_owned),
    }
}

/// Whether a response is worth re-sending.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryClassification {
    /// Re-send after a delay.
    pub retryable: bool,
    /// Present when a 429 is permanent for this billing period.
    pub hard_limit_reason: Option<String>,
}

/// Decide whether a response is worth re-sending. `x-should-retry` wins
/// outright in both directions.
pub fn classify_retry(
    status: u16,
    headers: &(impl HeaderLookup + ?Sized),
    body: &str,
) -> RetryClassification {
    match header_value(headers, "x-should-retry") {
        Some("true") => {
            return RetryClassification {
                retryable: true,
                hard_limit_reason: None,
            };
        }
        Some("false") => {
            return RetryClassification {
                retryable: false,
                hard_limit_reason: None,
            };
        }
        _ => {}
    }
    if status == 429 {
        let class = classify_rate_limit(headers, body);
        return if class.hard {
            RetryClassification {
                retryable: false,
                hard_limit_reason: class.reason,
            }
        } else {
            RetryClassification {
                retryable: true,
                hard_limit_reason: None,
            }
        };
    }
    RetryClassification {
        retryable: status == 408 || status == 409 || status >= 500,
        hard_limit_reason: None,
    }
}

/// Whether Anthropic says this 1M-context request requires usage credits
/// (recognized only on HTTP 429, like Claude Code 2.1.260's
/// `longContext1mCreditsBlocked` latch).
pub fn is_long_context_credits_required_error(status: u16, body: &str) -> bool {
    if status != 429 {
        return false;
    }
    let text = body.to_ascii_lowercase();
    text.contains("extra usage is required for long context")
        || text.contains("usage credits are required for long context")
}

/// A server-side policy verdict on the request — not a fault to retry. Claude
/// Code 2.1.280 names each separately so the user learns which policy fired
/// instead of seeing a bare 400/403 body. All three are already
/// non-retryable under [`classify_retry`] (non-429 4xx); this only *names*
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderBlockKind {
    /// HTTP 400 with `error.type == "policy_blocked"`.
    PolicyBlocked,
    /// `error.details.error_code == "dlp_request_denied"`: the organization's
    /// data-loss-prevention rules.
    DlpRequestDenied,
    /// Pre-wired in 2.1.280 (its predicate is hard-coded false); recognized by
    /// body text only.
    SafetyMonitorBlocked,
}

impl ProviderBlockKind {
    /// The wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PolicyBlocked => "policy_blocked",
            Self::DlpRequestDenied => "dlp_request_denied",
            Self::SafetyMonitorBlocked => "safety_monitor_blocked",
        }
    }

    /// An actionable, user-facing explanation.
    pub fn message(self) -> &'static str {
        match self {
            Self::PolicyBlocked => {
                "Anthropic refused this request under an account or organization policy. Retrying will not change the verdict."
            }
            Self::DlpRequestDenied => {
                "Anthropic refused this request under your organization's data-loss-prevention rules. Retrying will not change the verdict."
            }
            Self::SafetyMonitorBlocked => {
                "Anthropic refused this request at a safety monitor. Retrying will not change the verdict."
            }
        }
    }
}

/// Name a 4xx policy verdict, or `None` for anything else (2xx, 5xx, an
/// unrelated 4xx, a rate limit).
pub fn classify_provider_block(status: u16, body: &str) -> Option<ProviderBlockKind> {
    if !(400..500).contains(&status) {
        return None;
    }
    let text = body.to_ascii_lowercase();
    [
        ProviderBlockKind::PolicyBlocked,
        ProviderBlockKind::DlpRequestDenied,
        ProviderBlockKind::SafetyMonitorBlocked,
    ]
    .into_iter()
    .find(|kind| text.contains(kind.as_str()))
}

/// `error.details.error_code` Anthropic returns when a model is gated on a
/// newer Claude Code version than the request's `user-agent` declares.
pub const CLAUDE_CODE_VERSION_TOO_OLD_ERROR_CODE: &str = "claude_code_version_too_old";

const VERSION_TOO_OLD_MARKER: &str = "does not support this model; version ";
const VERSION_TOO_OLD_SUFFIX: &str = " or newer is required";

fn version_named_in(body: &str) -> Option<&str> {
    let start = body.find(VERSION_TOO_OLD_MARKER)? + VERSION_TOO_OLD_MARKER.len();
    let rest = &body[start..];
    let end = rest.find(VERSION_TOO_OLD_SUFFIX)?;
    let version = &rest[..end];
    let mut parts = version.split('.');
    let valid = (0..3).all(|_| {
        parts
            .next()
            .is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    }) && parts.next().is_none();
    valid.then_some(version)
}

/// Whether a 400 is the model version gate (`claude_code_version_too_old`).
/// Anthropic gates new models on the `user-agent`'s declared
/// `claude-cli/<version>`, not on the billing header's `cc_version`; retrying
/// without changing the declared version is pointless. Scoped to 400 so a 429
/// body cannot trip it.
pub fn is_claude_code_version_too_old_error(status: u16, body: &str) -> bool {
    status == 400
        && (body.contains(CLAUDE_CODE_VERSION_TOO_OLD_ERROR_CODE)
            || version_named_in(body).is_some())
}

/// The minimum Claude Code version a version-gate rejection names, if any.
pub fn required_claude_code_version(body: &str) -> Option<&str> {
    version_named_in(body)
}

/// Coarse class of a failed provider response, for a structured failure
/// diagnostic (the fork's `provider_stream_failure.details.kind`). Never
/// includes body text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderFailureKind {
    /// 401.
    Auth,
    /// 403.
    Permission,
    /// 429.
    RateLimit,
    /// 529 or an `overloaded_error` body.
    Overloaded,
    /// Other 5xx.
    ServerError,
    /// Other 4xx.
    InvalidRequest,
    /// Anything else.
    Unknown,
}

/// Classify a non-2xx provider response. `provider_error_type` is the body's
/// `error.type`, when it parsed.
pub fn classify_provider_failure(
    status: u16,
    provider_error_type: Option<&str>,
) -> ProviderFailureKind {
    match status {
        401 => ProviderFailureKind::Auth,
        403 => ProviderFailureKind::Permission,
        429 => ProviderFailureKind::RateLimit,
        _ if status == 529 || provider_error_type == Some("overloaded_error") => {
            ProviderFailureKind::Overloaded
        }
        500.. => ProviderFailureKind::ServerError,
        400.. => ProviderFailureKind::InvalidRequest,
        _ => ProviderFailureKind::Unknown,
    }
}

/// The credential a request was actually sent with, reduced to non-secret
/// identity. `version` distinguishes rotations of the same credential: a
/// vault record version, or a [`crate::token_fingerprint`] of the access
/// token for a shared-store credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialReceipt {
    /// Stable credential slot (store account id, vault credential id).
    pub credential_id: String,
    /// Provider account the token executes under.
    pub account_id: String,
    /// Rotation marker; never the token itself.
    pub version: String,
}

/// Why a genuine upstream 401 did or did not earn one retry. Carries no
/// credential material, so it is safe to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryAfter401Reason {
    /// Same credential, same account, new version: retry once.
    Rotated,
    /// Re-authorization / refresh failed; nothing to retry with.
    ReauthorizeFailed,
    /// The replacement is a different credential slot.
    CredentialChanged,
    /// The replacement executes under a different provider account.
    AccountChanged,
    /// The replacement is the exact credential that was just rejected.
    VersionUnchanged,
}

impl RetryAfter401Reason {
    /// Stable log spelling (matches anthropic-auth's `ScopedRetryReason`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rotated => "rotated",
            Self::ReauthorizeFailed => "reauthorize-failed",
            Self::CredentialChanged => "credential-changed",
            Self::AccountChanged => "account-changed",
            Self::VersionUnchanged => "version-unchanged",
        }
    }
}

/// Decision after a 401 and one re-authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryAfter401 {
    /// Re-send once with the current credential.
    pub retry: bool,
    /// Why.
    pub reason: RetryAfter401Reason,
}

/// Decide whether a request rejected with 401 should be re-sent once with
/// `current` (the credential obtained by re-authorizing / refreshing after
/// the 401). Only a *new version of the same credential for the same
/// account* may replace an in-flight 401: re-sending the exact rejected
/// credential loops, and silently switching account or credential would
/// change who the request executes as. Ported from anthropic-auth's
/// `decideScopedRetryAfter401`, which is custody-independent.
pub fn decide_retry_after_401(
    served: &CredentialReceipt,
    current: Option<&CredentialReceipt>,
) -> RetryAfter401 {
    let reason = match current {
        None => RetryAfter401Reason::ReauthorizeFailed,
        Some(c) if c.credential_id != served.credential_id => {
            RetryAfter401Reason::CredentialChanged
        }
        Some(c) if c.account_id != served.account_id => RetryAfter401Reason::AccountChanged,
        Some(c) if c.version == served.version => RetryAfter401Reason::VersionUnchanged,
        Some(_) => RetryAfter401Reason::Rotated,
    };
    RetryAfter401 {
        retry: reason == RetryAfter401Reason::Rotated,
        reason,
    }
}

/// Server-directed delay in milliseconds, or `None` when pacing is left to the
/// client. `retry-after` may be seconds or an HTTP date (evaluated against
/// `now_unix_ms`). Malformed values are ignored rather than waited on forever.
pub fn retry_after_ms(headers: &(impl HeaderLookup + ?Sized), now_unix_ms: i64) -> Option<f64> {
    if let Some(ms) = headers
        .header("retry-after-ms")
        .and_then(|v| v.trim().parse::<f64>().ok())
    {
        if ms.is_finite() && ms >= 0.0 {
            return Some(ms);
        }
    }
    let retry_after = headers.header("retry-after")?.trim();
    if let Ok(seconds) = retry_after.parse::<f64>() {
        if seconds.is_finite() && seconds >= 0.0 {
            return Some(seconds * 1000.0);
        }
        return None;
    }
    let at = chrono::DateTime::parse_from_rfc2822(retry_after).ok()?;
    Some((at.timestamp_millis() - now_unix_ms).max(0) as f64)
}

/// Backoff for `attempt` (0-based): `min(0.5 * 2^n, 8)` seconds scaled by a
/// `[0.75, 1.0]` jitter factor; `random` supplies the `[0, 1)` sample.
pub fn backoff_delay_ms(attempt: u32, random: f64) -> f64 {
    let exponential = (BASE_BACKOFF_SECONDS * 2f64.powi(attempt as i32)).min(MAX_BACKOFF_SECONDS);
    exponential * (1.0 - random.clamp(0.0, 1.0) * JITTER_RATIO) * 1000.0
}

/// Server-directed delay when offered, otherwise the jittered backoff.
pub fn next_retry_delay_ms(
    headers: &(impl HeaderLookup + ?Sized),
    attempt: u32,
    random: f64,
    now_unix_ms: i64,
) -> f64 {
    retry_after_ms(headers, now_unix_ms).unwrap_or_else(|| backoff_delay_ms(attempt, random))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONE: [(&str, &str); 0] = [];

    #[test]
    fn retries_transport_statuses_and_honours_directive() {
        for status in [408, 409, 500, 502, 529] {
            assert!(classify_retry(status, &NONE, "").retryable, "{status}");
        }
        for status in [400, 401, 403, 404, 422] {
            assert!(!classify_retry(status, &NONE, "").retryable, "{status}");
        }
        assert!(classify_retry(400, &[("x-should-retry", "true")], "").retryable);
        assert!(!classify_retry(500, &[("X-Should-Retry", "false")], "").retryable);
    }

    #[test]
    fn unattributed_429_is_soft() {
        let class = classify_retry(429, &NONE, "");
        assert!(class.retryable);
        assert!(class.hard_limit_reason.is_none());
    }

    #[test]
    fn out_of_credits_depends_on_unified_claim() {
        let hard = classify_rate_limit(&[(OVERAGE_DISABLED_REASON_HEADER, "out_of_credits")], "");
        assert_eq!(
            hard,
            RateLimitClass {
                hard: true,
                reason: Some("out_of_credits".into())
            }
        );
        let soft = classify_rate_limit(
            &[
                (OVERAGE_DISABLED_REASON_HEADER, "out_of_credits"),
                (REPRESENTATIVE_CLAIM_HEADER, "five_hour"),
            ],
            "",
        );
        assert!(!soft.hard);
        assert_eq!(soft.reason.as_deref(), Some("out_of_credits"));
        let cap = classify_rate_limit(
            &[
                (OVERAGE_DISABLED_REASON_HEADER, "org_spend_cap_reached"),
                (OVERAGE_STATUS_HEADER, "rejected"),
            ],
            "",
        );
        assert!(cap.hard);
    }

    #[test]
    fn credits_required_body_and_rejected_status() {
        assert!(
            classify_rate_limit(
                &[(REPRESENTATIVE_CLAIM_HEADER, "x")],
                r#"{"error":{"type":"credits_required"}}"#
            )
            .hard
        );
        assert!(
            !classify_rate_limit(
                &[(OVERAGE_DISABLED_REASON_HEADER, "fetch_error")],
                "Usage credits are required"
            )
            .hard
        );
        let rejected = classify_retry(
            429,
            &[
                (UNIFIED_STATUS_HEADER, "rejected"),
                ("retry-after", "168070"),
            ],
            "",
        );
        assert!(!rejected.retryable);
        assert_eq!(
            rejected.hard_limit_reason.as_deref(),
            Some("unified_status_rejected")
        );
        assert!(classify_retry(429, &[(UNIFIED_STATUS_HEADER, "allowed_warning")], "").retryable);
        assert!(classify_rate_limit(&NONE, "service_spend_limit_reached").hard);
        let embedded = classify_rate_limit(
            &NONE,
            r#"{"type":"exceeded_limit","details":"{\"overageDisabledReason\":\"out_of_credits\"}"}"#,
        );
        assert_eq!(embedded.reason.as_deref(), Some("out_of_credits"));
        assert!(embedded.hard);
    }

    #[test]
    fn retry_after_parsing() {
        assert_eq!(
            retry_after_ms(&[("retry-after-ms", "1500"), ("retry-after", "5")], 0),
            Some(1500.0)
        );
        assert_eq!(retry_after_ms(&[("retry-after", "5")], 0), Some(5000.0));
        let date = "Wed, 21 Oct 2015 07:28:00 GMT";
        let at = chrono::DateTime::parse_from_rfc2822(date)
            .unwrap()
            .timestamp_millis();
        assert_eq!(
            retry_after_ms(&[("retry-after", date)], at - 2000),
            Some(2000.0)
        );
        assert_eq!(
            retry_after_ms(&[("retry-after", date)], at + 2000),
            Some(0.0)
        );
        assert_eq!(retry_after_ms(&NONE, 0), None);
        assert_eq!(retry_after_ms(&[("retry-after", "soon")], 0), None);
        assert_eq!(retry_after_ms(&[("retry-after", "-3")], 0), None);
    }

    #[test]
    fn backoff_doubles_saturates_and_jitters_down_only() {
        assert_eq!(backoff_delay_ms(0, 0.0), 500.0);
        assert_eq!(backoff_delay_ms(1, 0.0), 1000.0);
        assert_eq!(backoff_delay_ms(3, 0.0), 4000.0);
        assert_eq!(backoff_delay_ms(4, 0.0), 8000.0);
        assert_eq!(backoff_delay_ms(9, 0.0), 8000.0);
        assert_eq!(backoff_delay_ms(4, 1.0), 6000.0);
        assert_eq!(
            next_retry_delay_ms(&[("retry-after", "2")], 5, 0.0, 0),
            2000.0
        );
        assert_eq!(next_retry_delay_ms(&NONE, 0, 0.0, 0), 500.0);
        assert_eq!(DEFAULT_MAX_RETRIES, 10);
    }

    #[test]
    fn long_context_credits_latch_is_429_only() {
        assert!(is_long_context_credits_required_error(
            429,
            "Extra usage is required for long context requests"
        ));
        assert!(is_long_context_credits_required_error(
            429,
            "usage credits are required for long context"
        ));
        assert!(!is_long_context_credits_required_error(
            429,
            "usage credits are required"
        ));
        assert!(!is_long_context_credits_required_error(
            400,
            "extra usage is required for long context"
        ));
    }
}

#[cfg(test)]
mod provider_verdict_tests {
    //! Ports of retry-policy.test.ts (fork cbc1b58) and the scoped 401
    //! decision tests of claustrum-scoped.test.ts (upstream ee0bdb5/9a1a490).
    use super::*;

    const NONE: [(&str, &str); 0] = [];

    fn version_gate_body() -> String {
        serde_json::json!({
            "type": "error",
            "error": {
                "type": "invalid_request_error",
                "message": "Claude Code 2.1.260 does not support this model; version 2.1.280 or newer is required. Run 'claude update', or update the Claude desktop app, then try again.",
                "details": { "error_code": "claude_code_version_too_old" }
            }
        })
        .to_string()
    }

    #[test]
    fn detects_the_version_gate_on_a_400() {
        assert!(is_claude_code_version_too_old_error(
            400,
            &version_gate_body()
        ));
        assert!(is_claude_code_version_too_old_error(
            400,
            "Claude Code 2.1.260 does not support this model; version 2.1.280 or newer is required."
        ));
    }

    #[test]
    fn version_gate_is_scoped_to_400_and_ignores_unrelated_400s() {
        assert!(!is_claude_code_version_too_old_error(
            429,
            &version_gate_body()
        ));
        assert!(!is_claude_code_version_too_old_error(
            200,
            &version_gate_body()
        ));
        assert!(!is_claude_code_version_too_old_error(
            400,
            r#"{"error":{"message":"thinking.type.disabled is not supported for this model"}}"#
        ));
    }

    #[test]
    fn reports_the_required_version_and_stays_non_retryable() {
        assert_eq!(
            required_claude_code_version(&version_gate_body()),
            Some("2.1.280")
        );
        assert_eq!(required_claude_code_version("no version here"), None);
        assert!(!classify_retry(400, &NONE, &version_gate_body()).retryable);
    }

    #[test]
    fn names_policy_verdicts_without_changing_retryability() {
        let body = r#"{"type":"error","error":{"type":"policy_blocked","message":"blocked"}}"#;
        let block = classify_provider_block(400, body).unwrap();
        assert_eq!(block, ProviderBlockKind::PolicyBlocked);
        assert!(block.message().contains("policy"));
        assert!(!classify_retry(400, &NONE, body).retryable);
        assert_eq!(
            classify_provider_block(
                403,
                r#"{"error":{"details":{"error_code":"dlp_request_denied"}}}"#
            ),
            Some(ProviderBlockKind::DlpRequestDenied)
        );
        assert_eq!(
            classify_provider_block(400, "safety_monitor_blocked"),
            Some(ProviderBlockKind::SafetyMonitorBlocked)
        );
    }

    #[test]
    fn provider_block_ignores_non_4xx_unrelated_and_rate_limits() {
        assert_eq!(classify_provider_block(500, "policy_blocked"), None);
        assert_eq!(classify_provider_block(200, "policy_blocked"), None);
        assert_eq!(
            classify_provider_block(400, "messages.0: invalid role"),
            None
        );
        assert_eq!(
            classify_provider_block(429, r#"{"error":{"type":"rate_limit_error"}}"#),
            None
        );
    }

    #[test]
    fn failure_kinds_match_the_diagnostic_vocabulary() {
        use ProviderFailureKind::*;
        assert_eq!(classify_provider_failure(401, None), Auth);
        assert_eq!(classify_provider_failure(403, None), Permission);
        assert_eq!(classify_provider_failure(429, None), RateLimit);
        assert_eq!(classify_provider_failure(529, None), Overloaded);
        assert_eq!(
            classify_provider_failure(500, Some("overloaded_error")),
            Overloaded
        );
        assert_eq!(classify_provider_failure(502, None), ServerError);
        assert_eq!(classify_provider_failure(404, None), InvalidRequest);
        assert_eq!(classify_provider_failure(302, None), Unknown);
    }

    fn receipt(credential: &str, account: &str, version: &str) -> CredentialReceipt {
        CredentialReceipt {
            credential_id: credential.into(),
            account_id: account.into(),
            version: version.into(),
        }
    }

    #[test]
    fn a_401_retries_only_on_a_rotation_of_the_same_credential_and_account() {
        let served = receipt("oauth:anthropic", "acct-a", "7");
        let decide =
            |current: Option<CredentialReceipt>| decide_retry_after_401(&served, current.as_ref());

        let rotated = decide(Some(receipt("oauth:anthropic", "acct-a", "8")));
        assert!(rotated.retry);
        assert_eq!(rotated.reason, RetryAfter401Reason::Rotated);

        for (current, reason) in [
            (None, RetryAfter401Reason::ReauthorizeFailed),
            (
                Some(receipt("oauth:other", "acct-a", "8")),
                RetryAfter401Reason::CredentialChanged,
            ),
            (
                Some(receipt("oauth:anthropic", "acct-b", "8")),
                RetryAfter401Reason::AccountChanged,
            ),
            (
                Some(receipt("oauth:anthropic", "acct-a", "7")),
                RetryAfter401Reason::VersionUnchanged,
            ),
        ] {
            let decision = decide(current);
            assert!(!decision.retry, "{reason:?}");
            assert_eq!(decision.reason, reason);
        }
        assert_eq!(
            RetryAfter401Reason::ReauthorizeFailed.as_str(),
            "reauthorize-failed"
        );
    }
}
