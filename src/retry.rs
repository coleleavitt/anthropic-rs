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
