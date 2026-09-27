//! Low-priority queue state harvested from rate-limit response headers.
//!
//! When rate limited, an account may opt into a lower-priority queue
//! (server-side flag `tengu_toasty_breeze`). The server describes the offer
//! and the queue on every response with the
//! `anthropic-ratelimit-unified-slow-*` headers; this module parses them into
//! a [`LowPriorityState`]. Ported from the anthropic-auth fork's
//! `low-priority.ts` (host slash-command wiring excluded).
//!
//! | header | meaning |
//! |---|---|
//! | `…-slow-offer` | `treatment` (available) \| `control` |
//! | `…-slow-status` | `active` \| `not_needed` \| `slot_busy` \| `weekly_limit` \| `budget_exhausted` \| `ineligible` \| `off` |
//! | `…-slow-retry-after` | seconds until the next retry |
//! | `…-slow-max-wait` | maximum wait, seconds |
//! | `…-slow-budget-utilization` | 0–1 float |
//! | `…-slow-budget-reset` | budget reset, epoch seconds |

use chrono::{DateTime, Utc};

use crate::retry::HeaderLookup;

/// Common prefix of the low-priority headers.
pub const LOW_PRIORITY_HEADER_PREFIX: &str = "anthropic-ratelimit-unified-slow-";
/// `…-slow-offer`
pub const LOW_PRIORITY_OFFER_HEADER: &str = "anthropic-ratelimit-unified-slow-offer";
/// `…-slow-status`
pub const LOW_PRIORITY_STATUS_HEADER: &str = "anthropic-ratelimit-unified-slow-status";
/// `…-slow-retry-after`
pub const LOW_PRIORITY_RETRY_AFTER_HEADER: &str = "anthropic-ratelimit-unified-slow-retry-after";
/// `…-slow-max-wait`
pub const LOW_PRIORITY_MAX_WAIT_HEADER: &str = "anthropic-ratelimit-unified-slow-max-wait";
/// `…-slow-budget-utilization`
pub const LOW_PRIORITY_BUDGET_UTILIZATION_HEADER: &str =
    "anthropic-ratelimit-unified-slow-budget-utilization";
/// `…-slow-budget-reset`
pub const LOW_PRIORITY_BUDGET_RESET_HEADER: &str = "anthropic-ratelimit-unified-slow-budget-reset";

/// Default retry interval while waiting, in milliseconds.
pub const LOW_PRIORITY_DEFAULT_RETRY_INTERVAL_MS: u64 = 20_000;
/// Maximum total wait, in milliseconds (20 minutes).
pub const LOW_PRIORITY_MAX_WAIT_MS: u64 = 1_200_000;
/// Cool-off period, in milliseconds (10 minutes).
pub const LOW_PRIORITY_COOLOFF_MS: u64 = 600_000;
/// Retry jitter factor.
pub const LOW_PRIORITY_JITTER_FACTOR: f64 = 0.3;

/// Whether the low-priority queue is offered to this account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LowPriorityOffer {
    /// Offered (`treatment`).
    Treatment,
    /// Not offered (`control`).
    Control,
    /// Absent or unrecognized.
    #[default]
    Unknown,
}

impl LowPriorityOffer {
    fn parse(value: Option<&str>) -> Self {
        match value {
            Some("treatment") => Self::Treatment,
            Some("control") => Self::Control,
            _ => Self::Unknown,
        }
    }
}

/// The low-priority queue's status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LowPriorityStatus {
    /// Working at lower priority.
    Active,
    /// Available but not needed.
    NotNeeded,
    /// Waiting for a slot.
    SlotBusy,
    /// Weekly budget reached.
    WeeklyLimit,
    /// Budget exhausted.
    BudgetExhausted,
    /// Account not eligible.
    Ineligible,
    /// Mode is off.
    Off,
    /// Absent or unrecognized.
    #[default]
    Unrecognized,
}

impl LowPriorityStatus {
    fn parse(value: Option<&str>) -> Self {
        match value {
            Some("active") => Self::Active,
            Some("not_needed") => Self::NotNeeded,
            Some("slot_busy") => Self::SlotBusy,
            Some("weekly_limit") => Self::WeeklyLimit,
            Some("budget_exhausted") => Self::BudgetExhausted,
            Some("ineligible") => Self::Ineligible,
            Some("off") => Self::Off,
            _ => Self::Unrecognized,
        }
    }

    /// The header token for this status (`None` for unrecognized).
    pub fn as_str(self) -> Option<&'static str> {
        Some(match self {
            Self::Active => "active",
            Self::NotNeeded => "not_needed",
            Self::SlotBusy => "slot_busy",
            Self::WeeklyLimit => "weekly_limit",
            Self::BudgetExhausted => "budget_exhausted",
            Self::Ineligible => "ineligible",
            Self::Off => "off",
            Self::Unrecognized => return None,
        })
    }
}

/// Low-priority state captured from one response.
#[derive(Debug, Clone, PartialEq)]
pub struct LowPriorityState {
    /// Whether the queue is offered.
    pub offer: LowPriorityOffer,
    /// Queue status.
    pub status: LowPriorityStatus,
    /// Seconds until the next retry is allowed.
    pub retry_after_seconds: Option<f64>,
    /// Maximum wait, seconds.
    pub max_wait_seconds: Option<f64>,
    /// Budget utilization, 0–1.
    pub budget_utilization: Option<f64>,
    /// When the budget resets (absent when the header is missing or zero).
    pub budget_reset_at: Option<DateTime<Utc>>,
    /// When this state was captured.
    pub captured_at: DateTime<Utc>,
}

fn raw_header<'a>(headers: &'a (impl HeaderLookup + ?Sized), name: &str) -> Option<&'a str> {
    headers.header(name)
}

/// A finite number from a header; empty/whitespace/non-numeric → `None`.
fn finite_number(value: Option<&str>) -> Option<f64> {
    let trimmed = value?.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed.parse::<f64>().ok().filter(|v| v.is_finite())
}

/// Whether a response carries low-priority information (an offer or status
/// header).
pub fn has_low_priority_headers(headers: &(impl HeaderLookup + ?Sized)) -> bool {
    raw_header(headers, LOW_PRIORITY_OFFER_HEADER).is_some()
        || raw_header(headers, LOW_PRIORITY_STATUS_HEADER).is_some()
}

/// Extract the low-priority state from response headers, captured at `now`.
pub fn extract_low_priority_state(
    headers: &(impl HeaderLookup + ?Sized),
    now: DateTime<Utc>,
) -> LowPriorityState {
    let budget_reset_at = finite_number(raw_header(headers, LOW_PRIORITY_BUDGET_RESET_HEADER))
        .filter(|secs| *secs != 0.0)
        .and_then(|secs| DateTime::<Utc>::from_timestamp_millis((secs * 1000.0) as i64));
    LowPriorityState {
        offer: LowPriorityOffer::parse(raw_header(headers, LOW_PRIORITY_OFFER_HEADER)),
        status: LowPriorityStatus::parse(raw_header(headers, LOW_PRIORITY_STATUS_HEADER)),
        retry_after_seconds: finite_number(raw_header(headers, LOW_PRIORITY_RETRY_AFTER_HEADER)),
        max_wait_seconds: finite_number(raw_header(headers, LOW_PRIORITY_MAX_WAIT_HEADER)),
        budget_utilization: finite_number(raw_header(
            headers,
            LOW_PRIORITY_BUDGET_UTILIZATION_HEADER,
        )),
        budget_reset_at,
        captured_at: now,
    }
}

impl LowPriorityState {
    /// Whether low-priority mode is available (`offer: treatment`).
    pub fn is_available(&self) -> bool {
        self.offer == LowPriorityOffer::Treatment
    }

    /// Whether the caller should keep waiting in the low-priority queue.
    pub fn should_wait(&self) -> bool {
        self.is_available()
            && matches!(
                self.status,
                LowPriorityStatus::Active | LowPriorityStatus::SlotBusy
            )
    }

    /// A human-readable description of the status.
    pub fn describe(&self) -> &'static str {
        match self.status {
            LowPriorityStatus::Active => "Working at lower priority · waiting for capacity",
            LowPriorityStatus::NotNeeded => "Low-priority mode available but not needed",
            LowPriorityStatus::SlotBusy => "Waiting for a low-priority slot",
            LowPriorityStatus::WeeklyLimit => "Weekly low-priority budget reached",
            LowPriorityStatus::BudgetExhausted => "Low-priority budget exhausted",
            LowPriorityStatus::Ineligible => "Not eligible for low-priority mode",
            LowPriorityStatus::Off => "Low-priority mode is off",
            LowPriorityStatus::Unrecognized => "Low-priority status unknown",
        }
    }
}

/// Budget utilization as a rounded percentage (`"42%"`), or `"unknown"`.
pub fn format_budget_utilization(utilization: Option<f64>) -> String {
    match utilization {
        Some(value) => format!("{}%", (value * 100.0).round()),
        None => "unknown".to_owned(),
    }
}

/// A caller's low-priority activation bookkeeping.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct LowPriorityActivation {
    /// Whether the user enabled low-priority mode.
    pub enabled: bool,
    /// When the activation started.
    pub activated_at: Option<DateTime<Utc>>,
    /// Requests served in this activation.
    pub requests_served: u64,
    /// Total wait in this activation, milliseconds.
    pub total_wait_ms: u64,
    /// Retry attempts.
    pub attempts: u64,
    /// Last state reported by the server.
    pub last_state: Option<LowPriorityState>,
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.timestamp_opt(1_790_000_000, 0).unwrap()
    }

    #[test]
    fn extracts_full_state_from_headers() {
        let headers = [
            ("Anthropic-Ratelimit-Unified-Slow-Offer", "treatment"),
            ("anthropic-ratelimit-unified-slow-status", "slot_busy"),
            ("anthropic-ratelimit-unified-slow-retry-after", "20"),
            ("anthropic-ratelimit-unified-slow-max-wait", " 1200 "),
            (
                "anthropic-ratelimit-unified-slow-budget-utilization",
                "0.425",
            ),
            (
                "anthropic-ratelimit-unified-slow-budget-reset",
                "1790003600",
            ),
        ];
        assert!(has_low_priority_headers(&headers));
        let state = extract_low_priority_state(&headers, now());
        assert_eq!(state.offer, LowPriorityOffer::Treatment);
        assert_eq!(state.status, LowPriorityStatus::SlotBusy);
        assert_eq!(state.retry_after_seconds, Some(20.0));
        assert_eq!(state.max_wait_seconds, Some(1200.0));
        assert_eq!(state.budget_utilization, Some(0.425));
        assert_eq!(
            state.budget_reset_at,
            Some(Utc.timestamp_opt(1_790_003_600, 0).unwrap())
        );
        assert_eq!(state.captured_at, now());
        assert!(state.is_available() && state.should_wait());
        assert_eq!(state.describe(), "Waiting for a low-priority slot");
        assert_eq!(format_budget_utilization(state.budget_utilization), "43%");
    }

    #[test]
    fn missing_or_garbage_headers_degrade_to_unknown() {
        let empty: [(&str, &str); 0] = [];
        assert!(!has_low_priority_headers(&empty));
        let state = extract_low_priority_state(&empty, now());
        assert_eq!(state.offer, LowPriorityOffer::Unknown);
        assert_eq!(state.status, LowPriorityStatus::Unrecognized);
        assert_eq!(state.retry_after_seconds, None);
        assert!(!state.is_available() && !state.should_wait());
        assert_eq!(state.describe(), "Low-priority status unknown");
        assert_eq!(format_budget_utilization(None), "unknown");

        let garbage = [
            ("anthropic-ratelimit-unified-slow-status", "paused"),
            ("anthropic-ratelimit-unified-slow-retry-after", "  "),
            ("anthropic-ratelimit-unified-slow-max-wait", "soon"),
            ("anthropic-ratelimit-unified-slow-budget-utilization", "inf"),
            ("anthropic-ratelimit-unified-slow-budget-reset", "0"),
        ];
        assert!(has_low_priority_headers(&garbage));
        let state = extract_low_priority_state(&garbage, now());
        assert_eq!(state.status, LowPriorityStatus::Unrecognized);
        assert_eq!(state.retry_after_seconds, None);
        assert_eq!(state.max_wait_seconds, None);
        assert_eq!(state.budget_utilization, None);
        assert_eq!(state.budget_reset_at, None);
    }

    #[test]
    fn only_active_or_busy_treatment_waits() {
        for (offer, status, waits) in [
            ("treatment", "active", true),
            ("treatment", "slot_busy", true),
            ("treatment", "not_needed", false),
            ("treatment", "weekly_limit", false),
            ("control", "active", false),
        ] {
            let headers = [
                (LOW_PRIORITY_OFFER_HEADER, offer),
                (LOW_PRIORITY_STATUS_HEADER, status),
            ];
            let state = extract_low_priority_state(&headers, now());
            assert_eq!(state.should_wait(), waits, "{offer}/{status}");
            assert_eq!(state.status.as_str(), Some(status));
        }
        let activation = LowPriorityActivation::default();
        assert!(!activation.enabled && activation.requests_served == 0);
        assert_eq!(LOW_PRIORITY_MAX_WAIT_MS, 20 * 60 * 1000);
        assert_eq!(LOW_PRIORITY_COOLOFF_MS, 10 * 60 * 1000);
    }
}
