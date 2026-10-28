//! Plan-quota snapshots: the `/api/oauth/usage` poll, the
//! `anthropic-ratelimit-unified-*` response headers, how the two merge, and
//! the routing policy that reads them.
//!
//! Ported from anthropic-auth (`quota-headers.ts`, the quota half of
//! `accounts.ts`) at upstream `b504bc8` plus the fork's overage/grace header
//! extraction (`cbc1b58`). Everything here is pure: timestamps are epoch
//! milliseconds passed in by the caller, so every rule is testable without a
//! clock or a network. [`crate::quota_manager`] layers caching, backoff and
//! identity fencing on top.
//!
//! # Field ownership
//!
//! A snapshot is assembled from two producers that know different things:
//!
//! * the **poll** (`GET /api/oauth/usage`) knows the 5h/7d windows, the
//!   per-model weekly *scoped* windows, extra-usage credits and which limit is
//!   binding;
//! * **headers** on every Messages response know only the 5h/7d windows, the
//!   representative claim and the fallback advisory.
//!
//! Merging a header harvest into a polled snapshot must therefore never erase
//! poll-owned fields (`scoped`, `extraUsage`, a polled `bindingWindow`).
//! [`QuotaFieldSources`] records, per field, which producer last wrote it.

use serde::{Deserialize, Serialize};

use crate::retry::HeaderLookup;

/// `GET` endpoint for the plan-usage poll.
pub const QUOTA_URL: &str = "https://api.anthropic.com/api/oauth/usage";

/// Header prefix shared by every unified rate-limit header.
pub const UNIFIED_HEADER_PREFIX: &str = "anthropic-ratelimit-unified-";

/// Default minimum gap between quota polls for one account.
pub const DEFAULT_QUOTA_CHECK_INTERVAL_MS: i64 = 5 * 60_000;

/// JavaScript's `Date` range, which bounds what anthropic-auth can render as an
/// ISO reset; values outside it are dropped rather than wrapped.
const MAX_JS_DATE_MS: f64 = 8.64e15;

/// A standard plan window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaWindowName {
    /// The five-hour session window (`5h` in headers).
    FiveHour,
    /// The seven-day window (`7d` in headers, `1w` in UI).
    SevenDay,
}

impl QuotaWindowName {
    /// Both standard windows, in evaluation order.
    pub const ALL: [QuotaWindowName; 2] = [QuotaWindowName::FiveHour, QuotaWindowName::SevenDay];

    /// The wire / binding-window spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FiveHour => "five_hour",
            Self::SevenDay => "seven_day",
        }
    }

    fn header_suffix(self) -> &'static str {
        match self {
            Self::FiveHour => "5h",
            Self::SevenDay => "7d",
        }
    }
}

/// Which producer last wrote a snapshot field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QuotaFieldSource {
    /// The `/api/oauth/usage` poll.
    Poll,
    /// Messages-response headers.
    Headers,
}

/// A snapshot field whose provenance is tracked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaField {
    /// `five_hour`.
    FiveHour,
    /// `seven_day`.
    SevenDay,
    /// `scoped`.
    Scoped,
    /// `extraUsage`.
    ExtraUsage,
    /// `bindingWindow`.
    BindingWindow,
    /// `fallbackAdvised`.
    FallbackAdvised,
}

impl QuotaField {
    /// Every tracked field (anthropic-auth's `QUOTA_FIELD_NAMES`).
    pub const ALL: [QuotaField; 6] = [
        QuotaField::FiveHour,
        QuotaField::SevenDay,
        QuotaField::Scoped,
        QuotaField::ExtraUsage,
        QuotaField::BindingWindow,
        QuotaField::FallbackAdvised,
    ];
}

/// Per-field provenance.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuotaFieldSources {
    /// Provenance of `five_hour`.
    #[serde(rename = "five_hour", default, skip_serializing_if = "Option::is_none")]
    pub five_hour: Option<QuotaFieldSource>,
    /// Provenance of `seven_day`.
    #[serde(rename = "seven_day", default, skip_serializing_if = "Option::is_none")]
    pub seven_day: Option<QuotaFieldSource>,
    /// Provenance of `scoped`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scoped: Option<QuotaFieldSource>,
    /// Provenance of `extraUsage`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra_usage: Option<QuotaFieldSource>,
    /// Provenance of `bindingWindow`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_window: Option<QuotaFieldSource>,
    /// Provenance of `fallbackAdvised`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_advised: Option<QuotaFieldSource>,
}

impl QuotaFieldSources {
    /// Provenance of `field`.
    pub fn get(&self, field: QuotaField) -> Option<QuotaFieldSource> {
        match field {
            QuotaField::FiveHour => self.five_hour,
            QuotaField::SevenDay => self.seven_day,
            QuotaField::Scoped => self.scoped,
            QuotaField::ExtraUsage => self.extra_usage,
            QuotaField::BindingWindow => self.binding_window,
            QuotaField::FallbackAdvised => self.fallback_advised,
        }
    }

    /// Set the provenance of `field`.
    pub fn set(&mut self, field: QuotaField, source: Option<QuotaFieldSource>) {
        let slot = match field {
            QuotaField::FiveHour => &mut self.five_hour,
            QuotaField::SevenDay => &mut self.seven_day,
            QuotaField::Scoped => &mut self.scoped,
            QuotaField::ExtraUsage => &mut self.extra_usage,
            QuotaField::BindingWindow => &mut self.binding_window,
            QuotaField::FallbackAdvised => &mut self.fallback_advised,
        };
        *slot = source;
    }

    /// Whether no field has recorded provenance.
    pub fn is_empty(&self) -> bool {
        QuotaField::ALL.iter().all(|f| self.get(*f).is_none())
    }
}

/// One standard plan window.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuotaWindow {
    /// Utilisation, 0–100.
    pub used_percent: f64,
    /// Headroom, 0–100.
    pub remaining_percent: f64,
    /// When the window resets (ISO-8601), when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resets_at: Option<String>,
    /// When this window was observed, epoch ms.
    pub checked_at: i64,
}

/// A model-scoped weekly window (e.g. "Fable only"), poll-owned.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopedQuotaWindow {
    /// Wire-derived identity, `claude-weekly-scoped-<slug>`.
    pub id: String,
    /// Display title, `<model> only`.
    pub title: String,
    /// Model id, when the server named one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
    /// Model display name.
    pub model_name: String,
    /// Utilisation, 0–100.
    pub used_percent: f64,
    /// Headroom, 0–100.
    pub remaining_percent: f64,
    /// Reset time (ISO-8601), when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resets_at: Option<String>,
    /// When observed, epoch ms.
    pub checked_at: i64,
}

/// A money amount in minor units.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuotaMoney {
    /// Amount in minor units (cents for USD).
    pub amount_minor: f64,
    /// ISO-4217 currency code.
    pub currency: String,
    /// Minor-unit exponent (2 for USD).
    pub exponent: u32,
}

impl QuotaMoney {
    /// `12.34 USD`-style rendering without locale data.
    pub fn format(&self) -> String {
        let scale = 10f64.powi(self.exponent as i32);
        format!(
            "{:.*} {}",
            self.exponent as usize,
            self.amount_minor / scale,
            self.currency
        )
    }
}

/// Extra-usage (pay-as-you-go credits) state, poll-owned.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtraUsageSnapshot {
    /// Credits spent this period.
    pub used: QuotaMoney,
    /// Monthly credit limit.
    pub limit: QuotaMoney,
    /// Server-reported utilisation percent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utilization_percent: Option<f64>,
    /// Server-reported spend severity (e.g. `critical`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// `used >= limit`.
    pub exhausted: bool,
}

/// Everything known about one account's plan quota
/// (anthropic-auth's `OAuthQuotaSnapshot`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuotaSnapshot {
    /// Five-hour window.
    #[serde(rename = "five_hour", default, skip_serializing_if = "Option::is_none")]
    pub five_hour: Option<QuotaWindow>,
    /// Seven-day window.
    #[serde(rename = "seven_day", default, skip_serializing_if = "Option::is_none")]
    pub seven_day: Option<QuotaWindow>,
    /// The stable account identity this snapshot was observed for. Access
    /// tokens are fetch credentials only and never key quota.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_identity: Option<String>,
    /// Model-scoped windows. `Some(vec![])` is a real poll result ("none
    /// visible"); `None` means the snapshot never saw a poll.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scoped: Option<Vec<ScopedQuotaWindow>>,
    /// Extra-usage credits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra_usage: Option<ExtraUsageSnapshot>,
    /// Which limit currently binds: `five_hour`, `seven_day`, or a scoped id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_window: Option<String>,
    /// Who reported `binding_window`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_window_source: Option<QuotaFieldSource>,
    /// Per-field provenance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field_sources: Option<QuotaFieldSources>,
    /// `anthropic-ratelimit-unified-fallback: available`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_advised: Option<bool>,
    /// Top-level producer (compatibility; see `field_sources`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<QuotaFieldSource>,
    /// Whole-snapshot freshness stamp, epoch ms. Lets a windowless snapshot
    /// (e.g. only `scoped: []`) still order against older data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<i64>,
}

impl QuotaSnapshot {
    /// The standard window `name`.
    pub fn window(&self, name: QuotaWindowName) -> Option<&QuotaWindow> {
        match name {
            QuotaWindowName::FiveHour => self.five_hour.as_ref(),
            QuotaWindowName::SevenDay => self.seven_day.as_ref(),
        }
    }

    fn window_slot(&mut self, name: QuotaWindowName) -> &mut Option<QuotaWindow> {
        match name {
            QuotaWindowName::FiveHour => &mut self.five_hour,
            QuotaWindowName::SevenDay => &mut self.seven_day,
        }
    }

    /// Whether `field` is present (anthropic-auth: `snapshot[field] !== undefined`).
    pub fn has_field(&self, field: QuotaField) -> bool {
        match field {
            QuotaField::FiveHour => self.five_hour.is_some(),
            QuotaField::SevenDay => self.seven_day.is_some(),
            QuotaField::Scoped => self.scoped.is_some(),
            QuotaField::ExtraUsage => self.extra_usage.is_some(),
            QuotaField::BindingWindow => self.binding_window.is_some(),
            QuotaField::FallbackAdvised => self.fallback_advised.is_some(),
        }
    }

    /// Provenance of a present field: its recorded source, else the
    /// snapshot's top-level source.
    pub fn field_source(&self, field: QuotaField) -> Option<QuotaFieldSource> {
        if !self.has_field(field) {
            return None;
        }
        self.field_sources
            .as_ref()
            .and_then(|s| s.get(field))
            .or(self.source)
    }

    /// Both standard windows are present.
    pub fn has_standard_windows(&self) -> bool {
        self.five_hour.is_some() && self.seven_day.is_some()
    }

    /// Newest observation time across every window and the top-level stamp
    /// (0 when nothing is stamped).
    pub fn checked_at_max(&self) -> i64 {
        [
            self.five_hour.as_ref().map(|w| w.checked_at),
            self.seven_day.as_ref().map(|w| w.checked_at),
            self.checked_at,
        ]
        .into_iter()
        .flatten()
        .chain(self.scoped.iter().flatten().map(|w| w.checked_at))
        .fold(0, i64::max)
    }

    /// Build a poll snapshot from a `/api/oauth/usage` response body.
    pub fn from_usage_response(usage: &serde_json::Value, checked_at: i64) -> Self {
        let limits = usage.get("limits").and_then(serde_json::Value::as_array);
        let binding_window = map_binding_window(limits);
        let mut snapshot = QuotaSnapshot {
            five_hour: map_usage_window(usage.get("five_hour"), checked_at),
            seven_day: map_usage_window(usage.get("seven_day"), checked_at),
            scoped: Some(map_scoped_weekly_limits(limits, checked_at)),
            extra_usage: map_extra_usage(usage),
            binding_window_source: binding_window.as_ref().map(|_| QuotaFieldSource::Poll),
            binding_window,
            source: Some(QuotaFieldSource::Poll),
            checked_at: Some(checked_at),
            ..Default::default()
        };
        let mut sources = QuotaFieldSources::default();
        for field in QuotaField::ALL {
            if field != QuotaField::FallbackAdvised && snapshot.has_field(field) {
                sources.set(field, Some(QuotaFieldSource::Poll));
            }
        }
        if !sources.is_empty() {
            snapshot.field_sources = Some(sources);
        }
        snapshot
    }

    /// The model-scoped window for `model`, if any. Matching is on a
    /// normalized key (`fable`/`mythos` families collapse) against the
    /// window's model id, name and title.
    pub fn scoped_window_for_model(&self, model: Option<&str>) -> Option<&ScopedQuotaWindow> {
        let key = scoped_quota_model_key(model?)?;
        self.scoped.as_ref()?.iter().find(|window| {
            let haystack = [
                window.model_id.as_deref(),
                Some(window.model_name.as_str()),
                Some(window.title.as_str()),
            ]
            .into_iter()
            .flatten()
            .map(normalize_scoped_quota_model)
            .collect::<Vec<_>>()
            .join(" ");
            haystack.contains(&key)
        })
    }

    /// Whether the scoped window for `model` is exhausted.
    pub fn model_scope_is_exhausted(&self, model: Option<&str>) -> bool {
        self.scoped_window_for_model(model)
            .is_some_and(|w| w.remaining_percent.is_finite() && w.remaining_percent <= 0.0)
    }

    /// Reduce to the store's coarse [`crate::QuotaObservation`] (utilisation
    /// percentages plus the newest window stamp).
    pub fn to_observation(&self) -> crate::account::QuotaObservation {
        let stamp = self.checked_at_max();
        crate::account::QuotaObservation {
            five_hour_percent: self.five_hour.as_ref().map(|w| w.used_percent),
            seven_day_percent: self.seven_day.as_ref().map(|w| w.used_percent),
            checked_at: (stamp > 0)
                .then(|| chrono::DateTime::from_timestamp_millis(stamp))
                .flatten(),
        }
    }
}

fn normalize_scoped_quota_model(value: &str) -> String {
    value
        .chars()
        .flat_map(char::to_lowercase)
        .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        .collect()
}

fn scoped_quota_model_key(model: &str) -> Option<String> {
    let normalized = normalize_scoped_quota_model(model);
    if normalized.contains("fable") {
        return Some("fable".into());
    }
    if normalized.contains("mythos") {
        return Some("mythos".into());
    }
    Some(normalized)
}

fn clamp_percent(value: f64) -> f64 {
    if !value.is_finite() {
        0.0
    } else {
        value.clamp(0.0, 100.0)
    }
}

fn non_empty_str(value: Option<&serde_json::Value>) -> Option<String> {
    value
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

fn finite_number(value: Option<&serde_json::Value>) -> Option<f64> {
    value
        .and_then(serde_json::Value::as_f64)
        .filter(|v| v.is_finite())
}

fn slug_for_quota_identity(value: &str) -> String {
    let lower = value.to_lowercase();
    let mut slug = String::with_capacity(lower.len());
    let mut pending_dash = false;
    for c in lower.chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            if pending_dash && !slug.is_empty() {
                slug.push('-');
            }
            pending_dash = false;
            slug.push(c);
        } else {
            pending_dash = true;
        }
    }
    slug
}

fn scoped_limit_identity(limit: &serde_json::Value) -> Option<(String, String, Option<String>)> {
    let model = limit.get("scope")?.get("model")?;
    let model_name = non_empty_str(model.get("display_name"))?;
    let model_id = non_empty_str(model.get("id"));
    let slug = slug_for_quota_identity(model_id.as_deref().unwrap_or(&model_name));
    if slug.is_empty() {
        return None;
    }
    Some((format!("claude-weekly-scoped-{slug}"), model_name, model_id))
}

fn is_weekly_scoped(limit: &serde_json::Value) -> bool {
    limit.get("kind").and_then(serde_json::Value::as_str) == Some("weekly_scoped")
        && limit.get("group").and_then(serde_json::Value::as_str) == Some("weekly")
}

fn map_scoped_weekly_limits(
    limits: Option<&Vec<serde_json::Value>>,
    checked_at: i64,
) -> Vec<ScopedQuotaWindow> {
    let mut seen = std::collections::HashSet::new();
    let mut scoped = Vec::new();
    for limit in limits.into_iter().flatten() {
        if !is_weekly_scoped(limit) {
            continue;
        }
        let Some(percent) = finite_number(limit.get("percent")) else {
            continue;
        };
        let Some((id, model_name, model_id)) = scoped_limit_identity(limit) else {
            continue;
        };
        if !seen.insert(id.clone()) {
            continue;
        }
        let used_percent = clamp_percent(percent);
        scoped.push(ScopedQuotaWindow {
            id,
            title: format!("{model_name} only"),
            model_id,
            model_name,
            used_percent,
            remaining_percent: clamp_percent(100.0 - used_percent),
            resets_at: limit
                .get("resets_at")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            checked_at,
        });
    }
    scoped
}

fn map_extra_usage(usage: &serde_json::Value) -> Option<ExtraUsageSnapshot> {
    let extra = usage.get("extra_usage")?;
    if extra.get("is_enabled").and_then(serde_json::Value::as_bool) != Some(true) {
        return None;
    }
    let used = finite_number(extra.get("used_credits"))?;
    let limit = finite_number(extra.get("monthly_limit"))?;
    let spend = usage.get("spend").filter(|v| !v.is_null());
    let spend_limit = spend.and_then(|s| s.get("limit")).filter(|v| !v.is_null());
    let currency = match spend_limit.and_then(|l| l.get("currency")) {
        None | Some(serde_json::Value::Null) => "USD".to_owned(),
        Some(value) => non_empty_str(Some(value))?,
    };
    let exponent = match spend_limit.and_then(|l| l.get("exponent")) {
        None | Some(serde_json::Value::Null) => 2,
        Some(value) => {
            let raw = value.as_f64()?;
            if raw.fract() != 0.0 || !(0.0..=20.0).contains(&raw) {
                return None;
            }
            raw as u32
        }
    };
    if currency.len() != 3 || !currency.bytes().all(|b| b.is_ascii_alphabetic()) {
        return None;
    }
    Some(ExtraUsageSnapshot {
        used: QuotaMoney {
            amount_minor: used,
            currency: currency.clone(),
            exponent,
        },
        limit: QuotaMoney {
            amount_minor: limit,
            currency,
            exponent,
        },
        utilization_percent: finite_number(extra.get("utilization")),
        severity: non_empty_str(spend.and_then(|s| s.get("severity"))),
        exhausted: used >= limit,
    })
}

fn map_binding_window(limits: Option<&Vec<serde_json::Value>>) -> Option<String> {
    let active = limits?
        .iter()
        .find(|l| l.get("is_active").and_then(serde_json::Value::as_bool) == Some(true))?;
    match active.get("kind").and_then(serde_json::Value::as_str) {
        Some("session") => Some("five_hour".into()),
        Some("weekly_all") => Some("seven_day".into()),
        _ if is_weekly_scoped(active) => scoped_limit_identity(active).map(|(id, _, _)| id),
        _ => None,
    }
}

fn map_usage_window(window: Option<&serde_json::Value>, checked_at: i64) -> Option<QuotaWindow> {
    let window = window?;
    let utilization = finite_number(window.get("utilization"))?;
    let used_percent = clamp_percent(utilization);
    Some(QuotaWindow {
        used_percent,
        remaining_percent: clamp_percent(100.0 - used_percent),
        resets_at: window
            .get("resets_at")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        checked_at,
    })
}

// ---------------------------------------------------------------------------
// Headers
// ---------------------------------------------------------------------------

fn unified(name: &str) -> String {
    format!("{UNIFIED_HEADER_PREFIX}{name}")
}

/// JavaScript `Number(value)` restricted to finite results, with an empty or
/// whitespace value treated as absent.
fn finite_header_number(headers: &(impl HeaderLookup + ?Sized), name: &str) -> Option<f64> {
    let raw = headers.header(name)?.trim();
    if raw.is_empty() {
        return None;
    }
    raw.parse::<f64>().ok().filter(|v| v.is_finite())
}

fn iso_from_epoch_seconds(seconds: f64) -> Option<String> {
    let millis = seconds * 1000.0;
    if !millis.is_finite() || millis.abs() > MAX_JS_DATE_MS {
        return None;
    }
    let at = chrono::DateTime::from_timestamp_millis(millis as i64)?;
    Some(at.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
}

/// JavaScript `Math.round`: halves round toward +∞.
fn js_round(value: f64) -> f64 {
    (value + 0.5).floor()
}

fn normalize_header_window(
    headers: &(impl HeaderLookup + ?Sized),
    name: QuotaWindowName,
    checked_at: i64,
) -> Option<QuotaWindow> {
    let suffix = name.header_suffix();
    let utilization = finite_header_number(headers, &unified(&format!("{suffix}-utilization")))?;
    let used_percent = js_round(utilization * 100.0).clamp(0.0, 100.0);
    let resets_at = finite_header_number(headers, &unified(&format!("{suffix}-reset")))
        .and_then(iso_from_epoch_seconds);
    Some(QuotaWindow {
        used_percent,
        remaining_percent: 100.0 - used_percent,
        resets_at,
        checked_at,
    })
}

/// Whether a response carries at least one standard-window utilisation
/// header (an overage-only frame does not count).
pub fn is_quota_bearing_header_frame(headers: &(impl HeaderLookup + ?Sized)) -> bool {
    QuotaWindowName::ALL.iter().any(|name| {
        finite_header_number(
            headers,
            &unified(&format!("{}-utilization", name.header_suffix())),
        )
        .is_some()
    })
}

/// Normalize `anthropic-ratelimit-unified-*` response headers into a
/// header-sourced snapshot observed at `now` (epoch ms).
pub fn normalize_quota_headers(headers: &(impl HeaderLookup + ?Sized), now: i64) -> QuotaSnapshot {
    let fallback_header = headers.header(&unified("fallback"));
    let mut sources = QuotaFieldSources::default();
    let mut snapshot = QuotaSnapshot {
        fallback_advised: Some(fallback_header == Some("available")),
        source: Some(QuotaFieldSource::Headers),
        checked_at: Some(now),
        ..Default::default()
    };
    for name in QuotaWindowName::ALL {
        if let Some(window) = normalize_header_window(headers, name, now) {
            *snapshot.window_slot(name) = Some(window);
            sources.set(
                match name {
                    QuotaWindowName::FiveHour => QuotaField::FiveHour,
                    QuotaWindowName::SevenDay => QuotaField::SevenDay,
                },
                Some(QuotaFieldSource::Headers),
            );
        }
    }
    if let Some(claim) = headers
        .header(&unified("representative-claim"))
        .filter(|c| !c.is_empty())
    {
        snapshot.binding_window = Some(claim.to_owned());
        snapshot.binding_window_source = Some(QuotaFieldSource::Headers);
        sources.binding_window = Some(QuotaFieldSource::Headers);
    }
    if fallback_header.is_some() {
        sources.fallback_advised = Some(QuotaFieldSource::Headers);
    }
    snapshot.field_sources = Some(sources);
    snapshot
}

/// `anthropic-ratelimit-unified-overage-status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverageStatus {
    /// Overage is being consumed.
    Active,
    /// Overage could be used.
    Available,
    /// Overage is off (see `disabled_reason`).
    Disabled,
    /// Any other value.
    Unknown,
}

/// `anthropic-ratelimit-unified-overage-scope`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverageScope {
    /// Organization-level.
    Org,
    /// User-level.
    User,
    /// Absent or unrecognized.
    Unknown,
}

/// Overage state advertised by response headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverageState {
    /// Current status.
    pub status: OverageStatus,
    /// Why overage is disabled, when it is.
    pub disabled_reason: Option<String>,
    /// Org or user scope.
    pub scope: OverageScope,
    /// `overage-in-use: true`.
    pub in_use: bool,
}

/// Extract overage state; `None` when no `overage-status` header is present.
pub fn extract_overage_state(headers: &(impl HeaderLookup + ?Sized)) -> Option<OverageState> {
    let status = headers
        .header(&unified("overage-status"))
        .filter(|s| !s.is_empty())?;
    Some(OverageState {
        status: match status {
            "active" => OverageStatus::Active,
            "available" => OverageStatus::Available,
            "disabled" => OverageStatus::Disabled,
            _ => OverageStatus::Unknown,
        },
        disabled_reason: headers
            .header(&unified("overage-disabled-reason"))
            .map(str::to_owned),
        scope: match headers.header(&unified("overage-scope")) {
            Some("org") => OverageScope::Org,
            Some("user") => OverageScope::User,
            _ => OverageScope::Unknown,
        },
        in_use: headers.header(&unified("overage-in-use")) == Some("true"),
    })
}

/// Grace-period state advertised by response headers.
#[derive(Debug, Clone, PartialEq)]
pub struct GraceState {
    /// Utilisation is present and above zero.
    pub active: bool,
    /// Grace utilisation (0–1).
    pub utilization: Option<f64>,
    /// Grace reset (ISO-8601).
    pub resets_at: Option<String>,
}

/// Extract grace state; `None` when neither grace header is present.
pub fn extract_grace_state(headers: &(impl HeaderLookup + ?Sized)) -> Option<GraceState> {
    let utilization = finite_header_number(headers, &unified("grace-utilization"));
    let reset = finite_header_number(headers, &unified("grace-reset"));
    if utilization.is_none() && reset.is_none() {
        return None;
    }
    Some(GraceState {
        active: utilization.is_some_and(|u| u > 0.0),
        utilization,
        resets_at: reset.and_then(iso_from_epoch_seconds),
    })
}

// ---------------------------------------------------------------------------
// Merging
// ---------------------------------------------------------------------------

fn overlay<T: Clone>(incoming: &Option<T>, existing: &Option<T>) -> Option<T> {
    incoming.clone().or_else(|| existing.clone())
}

fn incoming_fallback_advised(
    existing: Option<&QuotaSnapshot>,
    incoming: &QuotaSnapshot,
) -> Option<bool> {
    let incoming_owns = incoming
        .field_sources
        .as_ref()
        .and_then(|s| s.fallback_advised)
        .is_some();
    if incoming_owns {
        incoming.fallback_advised
    } else {
        existing
            .and_then(|e| e.fallback_advised)
            .or(incoming.fallback_advised)
    }
}

/// Merge a header harvest into an in-memory snapshot (anthropic-auth's
/// `mergeHeaderQuotaSnapshot`). Headers win for what they carry; poll-owned
/// fields (`scoped`, `extraUsage`, a polled `bindingWindow`) are preserved
/// from `existing` and never introduced by `incoming`.
pub fn merge_header_quota_snapshot(
    existing: Option<&QuotaSnapshot>,
    incoming: &QuotaSnapshot,
) -> QuotaSnapshot {
    let empty = QuotaSnapshot::default();
    let base = existing.unwrap_or(&empty);
    let poll_binding = base.binding_window_source == Some(QuotaFieldSource::Poll);

    let fallback_advised = incoming_fallback_advised(existing, incoming);
    let binding_window = if poll_binding {
        base.binding_window.clone()
    } else {
        overlay(&incoming.binding_window, &base.binding_window)
    };
    let binding_window_source = if poll_binding {
        Some(QuotaFieldSource::Poll)
    } else {
        incoming
            .binding_window_source
            .or(base.binding_window_source)
    };

    let mut merged = QuotaSnapshot {
        five_hour: overlay(&incoming.five_hour, &base.five_hour),
        seven_day: overlay(&incoming.seven_day, &base.seven_day),
        account_identity: overlay(&incoming.account_identity, &base.account_identity),
        scoped: base.scoped.clone(),
        extra_usage: base.extra_usage.clone(),
        binding_window,
        binding_window_source,
        field_sources: None,
        fallback_advised,
        // Top-level source stays `headers` for compatibility; field_sources
        // records ownership after partial harvests.
        source: Some(QuotaFieldSource::Headers),
        checked_at: overlay(&incoming.checked_at, &base.checked_at),
    };

    let incoming_sources = incoming.field_sources.as_ref();
    let existing_sources = existing.and_then(|e| e.field_sources.as_ref());
    let mut sources = QuotaFieldSources::default();
    for field in QuotaField::ALL {
        if !merged.has_field(field) {
            continue;
        }
        let source = match field {
            QuotaField::FallbackAdvised => incoming_sources
                .and_then(|s| s.fallback_advised)
                .or_else(|| {
                    let existing = existing?;
                    existing.fallback_advised?;
                    match existing_sources {
                        Some(s) => s.fallback_advised,
                        None => existing.field_source(field),
                    }
                }),
            QuotaField::Scoped | QuotaField::ExtraUsage => Some(QuotaFieldSource::Poll),
            QuotaField::BindingWindow if poll_binding && base.binding_window.is_some() => {
                Some(QuotaFieldSource::Poll)
            }
            _ if incoming.has_field(field) => incoming_sources
                .and_then(|s| s.get(field))
                .or_else(|| incoming.field_source(field)),
            _ => existing_sources
                .and_then(|s| s.get(field))
                .or_else(|| existing.and_then(|e| e.field_source(field))),
        };
        sources.set(field, source);
    }
    if !sources.is_empty() {
        merged.field_sources = Some(sources);
    }
    merged
}

fn source_precedence(snapshot: &QuotaSnapshot) -> u8 {
    match snapshot.source {
        Some(QuotaFieldSource::Poll) => 2,
        Some(QuotaFieldSource::Headers) => 1,
        None => 0,
    }
}

fn merge_header_owned_window(
    existing: &QuotaSnapshot,
    incoming: &QuotaSnapshot,
    name: QuotaWindowName,
) -> Option<QuotaWindow> {
    match (existing.window(name), incoming.window(name)) {
        (e, None) => e.cloned(),
        (None, Some(i)) => Some(i.clone()),
        (Some(e), Some(i)) => {
            let keep_existing = i.checked_at < e.checked_at
                || (i.checked_at == e.checked_at
                    && source_precedence(existing) > source_precedence(incoming));
            Some(if keep_existing { e.clone() } else { i.clone() })
        }
    }
}

fn merge_header_scoped(
    existing: &QuotaSnapshot,
    incoming: &QuotaSnapshot,
) -> Option<Vec<ScopedQuotaWindow>> {
    let Some(existing_scoped) = &existing.scoped else {
        return incoming.scoped.clone();
    };
    if existing_scoped.is_empty() {
        return Some(existing_scoped.clone());
    }
    let Some(incoming_scoped) = incoming.scoped.as_ref().filter(|s| !s.is_empty()) else {
        return Some(existing_scoped.clone());
    };
    let mut merged: Vec<ScopedQuotaWindow> = incoming_scoped.clone();
    for window in existing_scoped {
        match merged.iter_mut().find(|w| w.id == window.id) {
            Some(candidate) if window.checked_at >= candidate.checked_at => {
                *candidate = window.clone()
            }
            Some(_) => {}
            None => merged.push(window.clone()),
        }
    }
    Some(merged)
}

/// Merge a header snapshot into a *persisted* snapshot (anthropic-auth's
/// `mergeHeaderQuotaForPersistence`): unlike the in-memory merge, each
/// window keeps whichever observation is newer, so a delayed writer cannot
/// regress a fresher persisted reading.
pub fn merge_header_quota_for_persistence(
    existing: Option<&QuotaSnapshot>,
    incoming: &QuotaSnapshot,
) -> QuotaSnapshot {
    let Some(existing) = existing else {
        return incoming.clone();
    };
    if incoming.source != Some(QuotaFieldSource::Headers) {
        return incoming.clone();
    }
    let poll_binding = existing.binding_window_source == Some(QuotaFieldSource::Poll);
    let mut merged = QuotaSnapshot {
        five_hour: merge_header_owned_window(existing, incoming, QuotaWindowName::FiveHour),
        seven_day: merge_header_owned_window(existing, incoming, QuotaWindowName::SevenDay),
        account_identity: overlay(&incoming.account_identity, &existing.account_identity),
        scoped: merge_header_scoped(existing, incoming),
        extra_usage: overlay(&existing.extra_usage, &incoming.extra_usage),
        binding_window: if poll_binding {
            existing.binding_window.clone()
        } else {
            overlay(&incoming.binding_window, &existing.binding_window)
        },
        binding_window_source: if poll_binding {
            Some(QuotaFieldSource::Poll)
        } else {
            incoming
                .binding_window_source
                .or(existing.binding_window_source)
        },
        field_sources: None,
        fallback_advised: incoming_fallback_advised(Some(existing), incoming),
        source: incoming.source.or(existing.source),
        checked_at: overlay(&incoming.checked_at, &existing.checked_at),
    };
    let mut sources = QuotaFieldSources::default();
    for field in QuotaField::ALL {
        if !merged.has_field(field) {
            continue;
        }
        let source = match field {
            QuotaField::Scoped | QuotaField::ExtraUsage => Some(QuotaFieldSource::Poll),
            QuotaField::BindingWindow
                if poll_binding && existing.binding_window == merged.binding_window =>
            {
                Some(QuotaFieldSource::Poll)
            }
            QuotaField::FallbackAdvised
                if incoming
                    .field_sources
                    .as_ref()
                    .and_then(|s| s.fallback_advised)
                    .is_none() =>
            {
                existing.field_source(field)
            }
            _ => {
                let from_incoming = field_equal(incoming, &merged, field);
                let from_existing = field_equal(existing, &merged, field);
                if from_incoming {
                    incoming.field_source(field)
                } else if from_existing {
                    existing.field_source(field)
                } else {
                    existing
                        .field_source(field)
                        .or_else(|| incoming.field_source(field))
                }
            }
        };
        sources.set(field, source);
    }
    if !sources.is_empty() {
        merged.field_sources = Some(sources);
    }
    merged
}

fn field_equal(a: &QuotaSnapshot, b: &QuotaSnapshot, field: QuotaField) -> bool {
    match field {
        QuotaField::FiveHour => a.five_hour.is_some() && a.five_hour == b.five_hour,
        QuotaField::SevenDay => a.seven_day.is_some() && a.seven_day == b.seven_day,
        QuotaField::Scoped => a.scoped.is_some() && a.scoped == b.scoped,
        QuotaField::ExtraUsage => a.extra_usage.is_some() && a.extra_usage == b.extra_usage,
        QuotaField::BindingWindow => {
            a.binding_window.is_some() && a.binding_window == b.binding_window
        }
        QuotaField::FallbackAdvised => {
            a.fallback_advised.is_some() && a.fallback_advised == b.fallback_advised
        }
    }
}

/// A poll that completes after a newer header harvest must not regress the
/// header windows: keep each header window that is newer than the polled one
/// while adopting the poll's scoped/extra-usage data.
pub fn merge_poll_completion_with_newer_headers(
    current: Option<&QuotaSnapshot>,
    polled: &QuotaSnapshot,
) -> QuotaSnapshot {
    let Some(current) = current.filter(|c| c.source == Some(QuotaFieldSource::Headers)) else {
        return polled.clone();
    };
    let newer = |name: QuotaWindowName| {
        current
            .window(name)
            .is_some_and(|c| c.checked_at > polled.window(name).map_or(0, |p| p.checked_at))
    };
    let five_newer = newer(QuotaWindowName::FiveHour);
    let seven_newer = newer(QuotaWindowName::SevenDay);
    if !five_newer && !seven_newer {
        return polled.clone();
    }
    let header_binding = current.binding_window_source == Some(QuotaFieldSource::Headers);
    let incoming = QuotaSnapshot {
        five_hour: five_newer.then(|| current.five_hour.clone()).flatten(),
        seven_day: seven_newer.then(|| current.seven_day.clone()).flatten(),
        fallback_advised: current.fallback_advised,
        binding_window: header_binding
            .then(|| current.binding_window.clone())
            .flatten(),
        binding_window_source: header_binding.then_some(QuotaFieldSource::Headers),
        source: Some(QuotaFieldSource::Headers),
        checked_at: Some(
            [
                five_newer.then(|| current.five_hour.as_ref().map(|w| w.checked_at)),
                seven_newer.then(|| current.seven_day.as_ref().map(|w| w.checked_at)),
            ]
            .into_iter()
            .flatten()
            .flatten()
            .fold(0, i64::max),
        ),
        ..Default::default()
    };
    merge_header_quota_snapshot(Some(polled), &incoming)
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// Quota policy knobs (anthropic-auth's `storage.quota`).
#[derive(Debug, Clone, PartialEq)]
pub struct QuotaPolicy {
    /// When `false`, every quota gate passes.
    pub enabled: bool,
    /// Poll cadence and freshness horizon, ms (minimum one minute).
    pub check_interval_ms: i64,
    /// Minimum remaining percent on the five-hour window.
    pub minimum_remaining_five_hour: f64,
    /// Minimum remaining percent on the seven-day window.
    pub minimum_remaining_seven_day: f64,
    /// Treat a missing/non-finite window as failing.
    pub fail_closed_on_unknown: bool,
    /// Force a refresh every N requests (0 disables).
    pub refresh_every_n_requests: u64,
}

impl Default for QuotaPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            check_interval_ms: DEFAULT_QUOTA_CHECK_INTERVAL_MS,
            minimum_remaining_five_hour: 0.0,
            minimum_remaining_seven_day: 0.0,
            fail_closed_on_unknown: true,
            refresh_every_n_requests: 0,
        }
    }
}

impl QuotaPolicy {
    /// The configured interval, floored at one minute.
    pub fn interval_ms(&self) -> i64 {
        self.check_interval_ms.max(60_000)
    }

    /// Minimum remaining percent for `name`.
    pub fn minimum_remaining(&self, name: QuotaWindowName) -> f64 {
        match name {
            QuotaWindowName::FiveHour => self.minimum_remaining_five_hour,
            QuotaWindowName::SevenDay => self.minimum_remaining_seven_day,
        }
    }

    /// Whether `quota` satisfies the minimum-remaining policy.
    pub fn passes(&self, quota: Option<&QuotaSnapshot>) -> bool {
        if !self.enabled {
            return true;
        }
        for name in QuotaWindowName::ALL {
            let Some(window) = quota.and_then(|q| q.window(name)) else {
                return !self.fail_closed_on_unknown;
            };
            if !window.remaining_percent.is_finite() {
                return !self.fail_closed_on_unknown;
            }
            if window.remaining_percent < self.minimum_remaining(name) {
                return false;
            }
        }
        true
    }

    /// Both standard windows were observed within the interval.
    pub fn snapshot_is_fresh(&self, quota: Option<&QuotaSnapshot>, now: i64) -> bool {
        if !self.enabled {
            return true;
        }
        let max_age = self.interval_ms();
        QuotaWindowName::ALL.iter().all(|name| {
            quota
                .and_then(|q| q.window(*name))
                .is_some_and(|w| now - w.checked_at < max_age)
        })
    }

    /// Stale when either standard window, or the scoped window for `model`,
    /// is older than the interval.
    pub fn is_stale(&self, quota: Option<&QuotaSnapshot>, now: i64, model: Option<&str>) -> bool {
        if !self.snapshot_is_fresh(quota, now) {
            return true;
        }
        quota
            .and_then(|q| q.scoped_window_for_model(model))
            .is_some_and(|w| now - w.checked_at >= self.interval_ms())
    }

    /// When `quota` is next due for a poll: one interval out, capped at the
    /// oldest window's freshness deadline; when a window blocks policy, one
    /// minute after its reset (the earliest blocking reset wins).
    pub fn next_refresh_at(&self, quota: Option<&QuotaSnapshot>, now: i64) -> i64 {
        let interval = self.interval_ms();
        if !self.enabled {
            return now + interval;
        }
        let oldest_deadline = quota.and_then(|q| {
            [
                q.five_hour.as_ref().map(|w| w.checked_at),
                q.seven_day.as_ref().map(|w| w.checked_at),
            ]
            .into_iter()
            .flatten()
            .chain(q.scoped.iter().flatten().map(|w| w.checked_at))
            .map(|c| c + interval)
            .min()
        });
        let cap = |candidate: i64| oldest_deadline.map_or(candidate, |d| candidate.min(d));

        let mut blocked_resets = Vec::new();
        for name in QuotaWindowName::ALL {
            let Some(window) = quota.and_then(|q| q.window(name)) else {
                return cap(now + interval);
            };
            if window.remaining_percent >= self.minimum_remaining(name) {
                continue;
            }
            match window.resets_at.as_deref().and_then(parse_iso_ms) {
                Some(reset) if reset > now => blocked_resets.push(reset),
                _ => return cap(now + interval),
            }
        }
        match blocked_resets.into_iter().min() {
            Some(reset) => cap(reset + 60_000),
            None => cap(now + interval),
        }
    }

    /// Whether request number `request_count` forces a refresh.
    pub fn should_refresh_on_request_count(&self, request_count: u64) -> bool {
        self.refresh_every_n_requests > 0
            && request_count > 0
            && request_count % self.refresh_every_n_requests == 0
    }
}

/// Parse an ISO-8601 / RFC-3339 timestamp to epoch ms.
pub fn parse_iso_ms(value: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|d| d.timestamp_millis())
}

/// A cached window is still relevant until its reset passes (an unparseable
/// or absent reset keeps it relevant).
pub fn cached_window_still_relevant(window: Option<&QuotaWindow>, now: i64) -> bool {
    let Some(window) = window else {
        return false;
    };
    match window.resets_at.as_deref() {
        None => true,
        Some(reset) => parse_iso_ms(reset).is_none_or(|r| r > now),
    }
}

/// Both standard windows are still relevant (see
/// [`cached_window_still_relevant`]).
pub fn cached_snapshot_still_relevant(quota: Option<&QuotaSnapshot>, now: i64) -> bool {
    QuotaWindowName::ALL
        .iter()
        .all(|name| cached_window_still_relevant(quota.and_then(|q| q.window(*name)), now))
}

#[cfg(test)]
mod tests {
    //! Ports of quota-surfaces.test.ts, quota-provenance.test.ts and the
    //! header-merge cases of quota-manager.test.ts.
    use super::*;

    const NOW: i64 = 1_700_000_000_000;

    fn main_usage_capture() -> serde_json::Value {
        serde_json::json!({
            "five_hour": { "utilization": 4 },
            "seven_day": { "utilization": 13 },
            "limits": [
                { "kind": "session", "group": "session", "percent": 4, "is_active": false },
                { "kind": "weekly_all", "group": "weekly", "percent": 13, "is_active": false },
                { "kind": "weekly_scoped", "group": "weekly", "percent": 15, "is_active": true,
                  "scope": { "model": { "id": null, "display_name": "Fable" } } }
            ],
            "extra_usage": { "is_enabled": false, "monthly_limit": null, "used_credits": null },
            "spend": null
        })
    }

    fn team_usage_capture() -> serde_json::Value {
        serde_json::json!({
            "five_hour": { "utilization": 77 },
            "seven_day": { "utilization": 40 },
            "limits": [
                { "kind": "session", "group": "session", "percent": 77, "is_active": true },
                { "kind": "weekly_all", "group": "weekly", "percent": 40, "is_active": false },
                { "kind": "weekly_scoped", "group": "weekly", "percent": 51, "is_active": false,
                  "scope": { "model": { "id": null, "display_name": "Fable" } } }
            ],
            "extra_usage": { "is_enabled": true, "monthly_limit": 10000, "used_credits": 10035, "utilization": 100 },
            "spend": { "severity": "critical",
                       "limit": { "amount_minor": 10000, "currency": "USD", "exponent": 2 },
                       "can_purchase_credits": false }
        })
    }

    const MAIN_HEADERS: [(&str, &str); 12] = [
        ("anthropic-ratelimit-unified-status", "allowed"),
        ("anthropic-ratelimit-unified-reset", "1784252400"),
        (
            "anthropic-ratelimit-unified-representative-claim",
            "five_hour",
        ),
        ("anthropic-ratelimit-unified-5h-status", "allowed"),
        ("anthropic-ratelimit-unified-5h-utilization", "0.03"),
        ("anthropic-ratelimit-unified-5h-reset", "1784252400"),
        ("anthropic-ratelimit-unified-7d-status", "allowed"),
        ("anthropic-ratelimit-unified-7d-utilization", "0.12"),
        ("anthropic-ratelimit-unified-7d-reset", "1784502000"),
        ("anthropic-ratelimit-unified-fallback-percentage", "0.5"),
        ("anthropic-ratelimit-unified-overage-status", "rejected"),
        (
            "anthropic-ratelimit-unified-overage-disabled-reason",
            "org_level_disabled",
        ),
    ];

    const TEAM_HEADERS: [(&str, &str); 4] = [
        ("anthropic-ratelimit-unified-5h-utilization", "0.78"),
        ("anthropic-ratelimit-unified-7d-utilization", "0.4"),
        ("anthropic-ratelimit-unified-fallback", "available"),
        (
            "anthropic-ratelimit-unified-representative-claim",
            "five_hour",
        ),
    ];

    #[test]
    fn normalizes_enabled_exhausted_extra_usage_from_the_team_capture() {
        let team = QuotaSnapshot::from_usage_response(&team_usage_capture(), NOW);
        let extra = team.extra_usage.as_ref().unwrap();
        assert_eq!(extra.used.amount_minor, 10035.0);
        assert_eq!(extra.limit.amount_minor, 10000.0);
        assert_eq!(extra.severity.as_deref(), Some("critical"));
        assert!(extra.exhausted);
        assert_eq!(team.source, Some(QuotaFieldSource::Poll));
        assert_eq!(team.five_hour.as_ref().unwrap().remaining_percent, 23.0);
    }

    #[test]
    fn omits_extra_usage_when_disabled_and_rejects_bad_money_metadata() {
        assert!(
            QuotaSnapshot::from_usage_response(&main_usage_capture(), NOW)
                .extra_usage
                .is_none()
        );
        for limit in [
            serde_json::json!({ "amount_minor": 10000, "currency": "ZZZZ", "exponent": 2 }),
            serde_json::json!({ "amount_minor": 10000, "currency": "USD", "exponent": 50 }),
        ] {
            let mut capture = team_usage_capture();
            capture["spend"]["limit"] = limit;
            assert!(
                QuotaSnapshot::from_usage_response(&capture, NOW)
                    .extra_usage
                    .is_none()
            );
        }
    }

    #[test]
    fn maps_binding_windows_from_the_active_limit() {
        let team = QuotaSnapshot::from_usage_response(&team_usage_capture(), NOW);
        assert_eq!(team.binding_window.as_deref(), Some("five_hour"));
        assert_eq!(team.binding_window_source, Some(QuotaFieldSource::Poll));
        let main = QuotaSnapshot::from_usage_response(&main_usage_capture(), NOW);
        assert_eq!(
            main.binding_window.as_deref(),
            Some("claude-weekly-scoped-fable")
        );
        let scoped = main.scoped.as_ref().unwrap();
        assert_eq!(scoped.len(), 1);
        assert_eq!(scoped[0].title, "Fable only");
        assert_eq!(scoped[0].remaining_percent, 85.0);
        assert_eq!(
            main.field_sources.as_ref().unwrap().scoped,
            Some(QuotaFieldSource::Poll)
        );
    }

    #[test]
    fn classifies_quota_bearing_frames() {
        assert!(is_quota_bearing_header_frame(&MAIN_HEADERS));
        assert!(!is_quota_bearing_header_frame(&[(
            "anthropic-ratelimit-unified-status",
            "allowed"
        )]));
        assert!(!is_quota_bearing_header_frame(&[(
            "anthropic-ratelimit-unified-overage-utilization",
            "0.8"
        )]));
    }

    #[test]
    fn normalizes_personal_headers_with_rounded_percentages_and_iso_resets() {
        let personal = normalize_quota_headers(&MAIN_HEADERS, NOW);
        let five = personal.five_hour.as_ref().unwrap();
        assert_eq!(
            (five.used_percent, five.remaining_percent, five.checked_at),
            (3.0, 97.0, NOW)
        );
        let seven = personal.seven_day.as_ref().unwrap();
        assert_eq!((seven.used_percent, seven.remaining_percent), (12.0, 88.0));
        assert_eq!(personal.binding_window.as_deref(), Some("five_hour"));
        assert_eq!(
            personal.binding_window_source,
            Some(QuotaFieldSource::Headers)
        );
        assert_eq!(personal.source, Some(QuotaFieldSource::Headers));
        assert_eq!(personal.checked_at, Some(NOW));
        assert_eq!(five.resets_at.as_deref(), Some("2026-07-17T01:40:00.000Z"));
        assert_eq!(personal.fallback_advised, Some(false));
    }

    #[test]
    fn normalizes_team_headers_and_fallback_advisory() {
        let team = normalize_quota_headers(&TEAM_HEADERS, NOW);
        assert_eq!(team.five_hour.unwrap().used_percent, 78.0);
        assert_eq!(team.seven_day.unwrap().used_percent, 40.0);
        assert_eq!(team.fallback_advised, Some(true));
        assert_eq!(
            normalize_quota_headers(
                &[("anthropic-ratelimit-unified-5h-utilization", "0.125")],
                NOW
            )
            .five_hour
            .unwrap()
            .used_percent,
            13.0
        );
    }

    #[test]
    fn rejects_non_finite_values_and_out_of_range_resets() {
        let headers = [
            ("anthropic-ratelimit-unified-5h-utilization", "Infinity"),
            ("anthropic-ratelimit-unified-5h-reset", "not-a-number"),
            ("anthropic-ratelimit-unified-7d-utilization", "NaN"),
        ];
        let snapshot = normalize_quota_headers(&headers, NOW);
        assert!(snapshot.five_hour.is_none() && snapshot.seven_day.is_none());
        assert_eq!(snapshot.fallback_advised, Some(false));
        assert!(!is_quota_bearing_header_frame(&headers));

        let huge = normalize_quota_headers(
            &[
                ("anthropic-ratelimit-unified-5h-utilization", "0.2"),
                ("anthropic-ratelimit-unified-5h-reset", "1e308"),
                ("anthropic-ratelimit-unified-7d-utilization", "0.4"),
                ("anthropic-ratelimit-unified-7d-reset", "1e308"),
            ],
            NOW,
        );
        assert_eq!(huge.five_hour.as_ref().unwrap().used_percent, 20.0);
        assert!(huge.five_hour.unwrap().resets_at.is_none());
        assert!(huge.seven_day.unwrap().resets_at.is_none());
    }

    #[test]
    fn extracts_overage_and_grace_state() {
        let overage = extract_overage_state(&[
            ("anthropic-ratelimit-unified-overage-status", "disabled"),
            (
                "anthropic-ratelimit-unified-overage-disabled-reason",
                "org_level_disabled",
            ),
            ("anthropic-ratelimit-unified-overage-scope", "org"),
        ])
        .unwrap();
        assert_eq!(overage.status, OverageStatus::Disabled);
        assert_eq!(overage.scope, OverageScope::Org);
        assert!(!overage.in_use);
        assert_eq!(
            extract_overage_state(&MAIN_HEADERS).unwrap().status,
            OverageStatus::Unknown
        );
        assert!(extract_overage_state(&TEAM_HEADERS).is_none());

        let grace =
            extract_grace_state(&[("anthropic-ratelimit-unified-grace-utilization", "0.25")])
                .unwrap();
        assert!(grace.active);
        assert!(extract_grace_state(&TEAM_HEADERS).is_none());
    }

    fn polled() -> QuotaSnapshot {
        QuotaSnapshot::from_usage_response(&main_usage_capture(), NOW)
    }

    #[test]
    fn header_merge_never_erases_or_introduces_poll_owned_fields() {
        let existing = QuotaSnapshot::from_usage_response(&team_usage_capture(), NOW);
        let incoming = normalize_quota_headers(&MAIN_HEADERS, NOW + 1_000);
        let merged = merge_header_quota_snapshot(Some(&existing), &incoming);
        assert_eq!(merged.scoped, existing.scoped);
        assert_eq!(merged.extra_usage, existing.extra_usage);
        // A polled binding window outranks the header claim.
        assert_eq!(merged.binding_window.as_deref(), Some("five_hour"));
        assert_eq!(merged.binding_window_source, Some(QuotaFieldSource::Poll));
        assert_eq!(merged.five_hour.as_ref().unwrap().used_percent, 3.0);
        let sources = merged.field_sources.unwrap();
        assert_eq!(sources.five_hour, Some(QuotaFieldSource::Headers));
        assert_eq!(sources.scoped, Some(QuotaFieldSource::Poll));
        assert_eq!(sources.binding_window, Some(QuotaFieldSource::Poll));

        // A header harvest with no prior poll never invents scoped data.
        let fresh = merge_header_quota_snapshot(None, &incoming);
        assert!(fresh.scoped.is_none() && fresh.extra_usage.is_none());
    }

    #[test]
    fn partial_header_harvest_keeps_poll_provenance_for_the_missing_window() {
        let existing = polled();
        let incoming = normalize_quota_headers(
            &[("anthropic-ratelimit-unified-7d-utilization", "0.5")],
            NOW + 1_000,
        );
        let merged = merge_header_quota_snapshot(Some(&existing), &incoming);
        let sources = merged.field_sources.as_ref().unwrap();
        assert_eq!(sources.five_hour, Some(QuotaFieldSource::Poll));
        assert_eq!(sources.seven_day, Some(QuotaFieldSource::Headers));
        assert_eq!(merged.five_hour, existing.five_hour);
        // Present empty scoped arrays survive a header push.
        let mut empty_scoped = existing.clone();
        empty_scoped.scoped = Some(Vec::new());
        assert_eq!(
            merge_header_quota_snapshot(Some(&empty_scoped), &incoming).scoped,
            Some(Vec::new())
        );
    }

    #[test]
    fn fallback_advice_is_header_derived_only_when_its_header_is_present() {
        let mut existing = polled();
        existing.fallback_advised = Some(true);
        existing.field_sources.as_mut().unwrap().fallback_advised = Some(QuotaFieldSource::Poll);
        let without = normalize_quota_headers(
            &[("anthropic-ratelimit-unified-5h-utilization", "0.5")],
            NOW,
        );
        let merged = merge_header_quota_snapshot(Some(&existing), &without);
        assert_eq!(merged.fallback_advised, Some(true));
        assert_eq!(
            merged.field_sources.as_ref().unwrap().fallback_advised,
            Some(QuotaFieldSource::Poll)
        );
        let with = normalize_quota_headers(&TEAM_HEADERS, NOW);
        let merged = merge_header_quota_snapshot(Some(&existing), &with);
        assert_eq!(
            merged.field_sources.as_ref().unwrap().fallback_advised,
            Some(QuotaFieldSource::Headers)
        );
    }

    #[test]
    fn persistence_merge_keeps_the_newer_window() {
        let existing = normalize_quota_headers(&TEAM_HEADERS, NOW + 10_000);
        let stale = normalize_quota_headers(&MAIN_HEADERS, NOW);
        let merged = merge_header_quota_for_persistence(Some(&existing), &stale);
        assert_eq!(merged.five_hour.as_ref().unwrap().used_percent, 78.0);
        let newer = normalize_quota_headers(&MAIN_HEADERS, NOW + 20_000);
        let merged = merge_header_quota_for_persistence(Some(&existing), &newer);
        assert_eq!(merged.five_hour.as_ref().unwrap().used_percent, 3.0);
    }

    #[test]
    fn poll_completion_preserves_newer_header_windows_while_adding_scoped() {
        let header_now = normalize_quota_headers(&TEAM_HEADERS, NOW + 60_000);
        let poll = polled();
        let merged = merge_poll_completion_with_newer_headers(Some(&header_now), &poll);
        assert_eq!(merged.five_hour.as_ref().unwrap().used_percent, 78.0);
        assert_eq!(merged.scoped, poll.scoped);
        // An older header cache yields the poll unchanged.
        let old_header = normalize_quota_headers(&TEAM_HEADERS, NOW - 60_000);
        assert_eq!(
            merge_poll_completion_with_newer_headers(Some(&old_header), &poll),
            poll
        );
    }

    #[test]
    fn scoped_window_matches_normalized_model_keys() {
        let snapshot = polled();
        assert!(
            snapshot
                .scoped_window_for_model(Some("claude-fable-5"))
                .is_some()
        );
        assert!(
            snapshot
                .scoped_window_for_model(Some("claude-opus-4-8"))
                .is_none()
        );
        assert!(snapshot.scoped_window_for_model(None).is_none());
        let mut exhausted = snapshot.clone();
        exhausted.scoped.as_mut().unwrap()[0].remaining_percent = 0.0;
        assert!(exhausted.model_scope_is_exhausted(Some("Fable")));
        assert!(!snapshot.model_scope_is_exhausted(Some("Fable")));
    }

    #[test]
    fn policy_fails_closed_on_unknown_and_respects_minimums() {
        let policy = QuotaPolicy::default();
        assert!(!policy.passes(None));
        assert!(policy.passes(Some(&polled())));
        let lenient = QuotaPolicy {
            fail_closed_on_unknown: false,
            ..QuotaPolicy::default()
        };
        assert!(lenient.passes(None));
        let strict = QuotaPolicy {
            minimum_remaining_seven_day: 90.0,
            ..QuotaPolicy::default()
        };
        assert!(!strict.passes(Some(&polled())));
        let disabled = QuotaPolicy {
            enabled: false,
            ..QuotaPolicy::default()
        };
        assert!(disabled.passes(None));
    }

    #[test]
    fn next_refresh_is_capped_at_the_oldest_window_and_waits_for_blocking_resets() {
        let policy = QuotaPolicy::default();
        let snapshot = polled();
        assert_eq!(
            policy.next_refresh_at(Some(&snapshot), NOW),
            NOW + DEFAULT_QUOTA_CHECK_INTERVAL_MS
        );
        assert_eq!(
            policy.next_refresh_at(Some(&snapshot), NOW + 60_000),
            NOW + DEFAULT_QUOTA_CHECK_INTERVAL_MS
        );
        let strict = QuotaPolicy {
            minimum_remaining_five_hour: 99.0,
            ..QuotaPolicy::default()
        };
        let mut blocked = snapshot.clone();
        blocked.scoped = Some(Vec::new());
        let reset = NOW + 2 * 60_000;
        blocked.five_hour.as_mut().unwrap().resets_at =
            chrono::DateTime::from_timestamp_millis(reset).map(|d| d.to_rfc3339());
        assert_eq!(strict.next_refresh_at(Some(&blocked), NOW), reset + 60_000);
        assert!(!policy.should_refresh_on_request_count(0));
        let every = QuotaPolicy {
            refresh_every_n_requests: 3,
            ..QuotaPolicy::default()
        };
        assert!(every.should_refresh_on_request_count(6));
        assert!(!every.should_refresh_on_request_count(5));
    }

    #[test]
    fn snapshot_round_trips_through_camel_case_json() {
        let snapshot = merge_header_quota_snapshot(
            Some(&polled()),
            &normalize_quota_headers(&TEAM_HEADERS, NOW),
        );
        let json = serde_json::to_value(&snapshot).unwrap();
        assert!(json.get("five_hour").is_some());
        assert!(json.get("fieldSources").is_some());
        assert!(json.get("bindingWindowSource").is_some());
        let back: QuotaSnapshot = serde_json::from_value(json).unwrap();
        assert_eq!(back, snapshot);
        let observation = snapshot.to_observation();
        assert_eq!(observation.five_hour_percent, Some(78.0));
    }

    fn win(used: f64, checked_at: i64) -> QuotaWindow {
        QuotaWindow {
            used_percent: used,
            remaining_percent: 100.0 - used,
            resets_at: None,
            checked_at,
        }
    }

    fn scoped_win(id: &str, checked_at: i64, used: f64) -> ScopedQuotaWindow {
        ScopedQuotaWindow {
            id: id.to_owned(),
            title: format!("{id} only"),
            model_id: None,
            model_name: id.to_owned(),
            used_percent: used,
            remaining_percent: 100.0 - used,
            resets_at: None,
            checked_at,
        }
    }

    #[test]
    fn window_name_wire_spellings_and_evaluation_order() {
        assert_eq!(QuotaWindowName::FiveHour.as_str(), "five_hour");
        assert_eq!(QuotaWindowName::SevenDay.as_str(), "seven_day");
        assert_eq!(
            QuotaWindowName::ALL,
            [QuotaWindowName::FiveHour, QuotaWindowName::SevenDay]
        );
    }

    #[test]
    fn field_sources_get_set_and_is_empty() {
        let mut fs = QuotaFieldSources::default();
        assert!(fs.is_empty());
        for field in QuotaField::ALL {
            assert_eq!(fs.get(field), None);
        }
        fs.set(QuotaField::Scoped, Some(QuotaFieldSource::Poll));
        assert_eq!(fs.get(QuotaField::Scoped), Some(QuotaFieldSource::Poll));
        assert!(!fs.is_empty());
        fs.set(QuotaField::ExtraUsage, Some(QuotaFieldSource::Headers));
        assert_eq!(
            fs.get(QuotaField::ExtraUsage),
            Some(QuotaFieldSource::Headers)
        );
        fs.set(QuotaField::Scoped, None);
        assert_eq!(fs.get(QuotaField::Scoped), None);
        // Every slot round-trips through set/get.
        for field in QuotaField::ALL {
            fs.set(field, Some(QuotaFieldSource::Headers));
            assert_eq!(fs.get(field), Some(QuotaFieldSource::Headers));
        }
        assert!(!fs.is_empty());
    }

    #[test]
    fn money_formats_with_minor_unit_exponent() {
        assert_eq!(
            QuotaMoney {
                amount_minor: 1234.0,
                currency: "USD".to_owned(),
                exponent: 2,
            }
            .format(),
            "12.34 USD"
        );
        // A zero-exponent currency renders with no decimal places.
        assert_eq!(
            QuotaMoney {
                amount_minor: 500.0,
                currency: "JPY".to_owned(),
                exponent: 0,
            }
            .format(),
            "500 JPY"
        );
        // A three-exponent currency keeps all three.
        assert_eq!(
            QuotaMoney {
                amount_minor: 1500.0,
                currency: "BHD".to_owned(),
                exponent: 3,
            }
            .format(),
            "1.500 BHD"
        );
    }

    #[test]
    fn snapshot_has_field_and_standard_windows() {
        let snap = polled();
        assert!(snap.has_field(QuotaField::FiveHour));
        assert!(snap.has_field(QuotaField::SevenDay));
        assert!(snap.has_field(QuotaField::Scoped));
        assert!(snap.has_field(QuotaField::BindingWindow));
        assert!(!snap.has_field(QuotaField::ExtraUsage));
        assert!(!snap.has_field(QuotaField::FallbackAdvised));
        assert!(snap.has_standard_windows());

        let only_five = QuotaSnapshot {
            five_hour: snap.five_hour.clone(),
            ..Default::default()
        };
        assert!(!only_five.has_standard_windows());
        assert!(!QuotaSnapshot::default().has_standard_windows());
    }

    #[test]
    fn field_source_falls_back_to_top_level_source() {
        let snap = QuotaSnapshot {
            five_hour: Some(win(10.0, NOW)),
            source: Some(QuotaFieldSource::Headers),
            field_sources: None,
            ..Default::default()
        };
        // Present field, no per-field provenance: the top-level source answers.
        assert_eq!(
            snap.field_source(QuotaField::FiveHour),
            Some(QuotaFieldSource::Headers)
        );
        // Absent field is None even though a top-level source exists.
        assert_eq!(snap.field_source(QuotaField::ExtraUsage), None);
        // A recorded per-field source outranks the top-level one.
        let mut fs = QuotaFieldSources::default();
        fs.set(QuotaField::FiveHour, Some(QuotaFieldSource::Poll));
        let snap2 = QuotaSnapshot {
            field_sources: Some(fs),
            ..snap.clone()
        };
        assert_eq!(
            snap2.field_source(QuotaField::FiveHour),
            Some(QuotaFieldSource::Poll)
        );
    }

    #[test]
    fn checked_at_max_picks_newest_observation() {
        let snap = QuotaSnapshot {
            five_hour: Some(win(10.0, NOW)),
            seven_day: Some(win(20.0, NOW + 1_000)),
            scoped: Some(vec![scoped_win("a", NOW + 5_000, 5.0)]),
            checked_at: Some(NOW + 2_000),
            ..Default::default()
        };
        assert_eq!(snap.checked_at_max(), NOW + 5_000);
        assert_eq!(QuotaSnapshot::default().checked_at_max(), 0);
    }

    #[test]
    fn observation_carries_percentages_and_newest_stamp() {
        let obs = polled().to_observation();
        assert_eq!(obs.five_hour_percent, Some(4.0));
        assert_eq!(obs.seven_day_percent, Some(13.0));
        assert_eq!(obs.checked_at, chrono::DateTime::from_timestamp_millis(NOW));

        let empty = QuotaSnapshot::default().to_observation();
        assert!(empty.five_hour_percent.is_none());
        assert!(empty.checked_at.is_none());
    }

    #[test]
    fn clamp_percent_bounds_and_zeroes_non_finite() {
        assert_eq!(clamp_percent(50.0), 50.0);
        assert_eq!(clamp_percent(150.0), 100.0);
        assert_eq!(clamp_percent(-5.0), 0.0);
        assert_eq!(clamp_percent(f64::NAN), 0.0);
        assert_eq!(clamp_percent(f64::INFINITY), 0.0);
        assert_eq!(clamp_percent(f64::NEG_INFINITY), 0.0);
    }

    #[test]
    fn string_and_number_json_helpers() {
        assert_eq!(
            non_empty_str(Some(&serde_json::json!("  hi  "))),
            Some("hi".to_owned())
        );
        assert_eq!(non_empty_str(Some(&serde_json::json!("   "))), None);
        assert_eq!(non_empty_str(Some(&serde_json::json!(7))), None);
        assert_eq!(non_empty_str(None), None);

        assert_eq!(finite_number(Some(&serde_json::json!(3.5))), Some(3.5));
        assert_eq!(finite_number(Some(&serde_json::json!(10))), Some(10.0));
        assert_eq!(finite_number(Some(&serde_json::json!("x"))), None);
        assert_eq!(finite_number(None), None);
    }

    #[test]
    fn slug_and_model_key_normalization() {
        assert_eq!(slug_for_quota_identity("Claude Fable 5"), "claude-fable-5");
        // Leading/trailing junk never yields a dangling dash.
        assert_eq!(slug_for_quota_identity("  --Fable!!Pro  "), "fable-pro");
        assert_eq!(slug_for_quota_identity("!!!"), "");

        assert_eq!(
            normalize_scoped_quota_model("Claude-Fable-5"),
            "claudefable5"
        );
        assert_eq!(
            scoped_quota_model_key("anthropic/claude-fable-5").as_deref(),
            Some("fable")
        );
        assert_eq!(
            scoped_quota_model_key("Mythos Prime").as_deref(),
            Some("mythos")
        );
        assert_eq!(
            scoped_quota_model_key("claude-opus-4-8").as_deref(),
            Some("claudeopus48")
        );
    }

    #[test]
    fn scoped_weekly_limits_dedupe_and_skip_invalid() {
        let usage = serde_json::json!({
            "limits": [
                { "kind": "weekly_scoped", "group": "weekly", "percent": 10, "is_active": false,
                  "resets_at": "2026-01-01T00:00:00Z",
                  "scope": { "model": { "id": "claude-fable-5", "display_name": "Fable" } } },
                // Duplicate id (same model) is dropped; the first percent wins.
                { "kind": "weekly_scoped", "group": "weekly", "percent": 99, "is_active": false,
                  "scope": { "model": { "id": "claude-fable-5", "display_name": "Fable" } } },
                // Missing percent is skipped before the id is recorded.
                { "kind": "weekly_scoped", "group": "weekly", "is_active": false,
                  "scope": { "model": { "id": "claude-mythos", "display_name": "Mythos" } } },
                // Empty display name yields no identity and is skipped.
                { "kind": "weekly_scoped", "group": "weekly", "percent": 5, "is_active": false,
                  "scope": { "model": { "id": null, "display_name": "  " } } },
                // Not a weekly-scoped limit at all.
                { "kind": "session", "group": "session", "percent": 50, "is_active": false }
            ]
        });
        let scoped = QuotaSnapshot::from_usage_response(&usage, NOW)
            .scoped
            .unwrap();
        assert_eq!(scoped.len(), 1);
        assert_eq!(scoped[0].id, "claude-weekly-scoped-claude-fable-5");
        assert_eq!(scoped[0].model_id.as_deref(), Some("claude-fable-5"));
        assert_eq!(scoped[0].model_name, "Fable");
        assert_eq!(scoped[0].title, "Fable only");
        assert_eq!(scoped[0].used_percent, 10.0);
        assert_eq!(scoped[0].remaining_percent, 90.0);
        assert_eq!(scoped[0].resets_at.as_deref(), Some("2026-01-01T00:00:00Z"));
        assert_eq!(scoped[0].checked_at, NOW);
    }

    #[test]
    fn extra_usage_defaults_and_reads_spend_metadata() {
        // Spend is null: currency and exponent default to USD / 2.
        let defaulted = serde_json::json!({
            "extra_usage": { "is_enabled": true, "used_credits": 50, "monthly_limit": 100, "utilization": 50 },
            "spend": null
        });
        let e = QuotaSnapshot::from_usage_response(&defaulted, NOW)
            .extra_usage
            .unwrap();
        assert_eq!(e.used.currency, "USD");
        assert_eq!(e.used.exponent, 2);
        assert_eq!(e.used.amount_minor, 50.0);
        assert_eq!(e.limit.amount_minor, 100.0);
        assert_eq!(e.utilization_percent, Some(50.0));
        assert!(e.severity.is_none());
        assert!(!e.exhausted);

        // Spend metadata drives currency/exponent/severity; used >= limit exhausts.
        let detailed = serde_json::json!({
            "extra_usage": { "is_enabled": true, "used_credits": 200, "monthly_limit": 100 },
            "spend": { "severity": "warning", "limit": { "currency": "EUR", "exponent": 3 } }
        });
        let e = QuotaSnapshot::from_usage_response(&detailed, NOW)
            .extra_usage
            .unwrap();
        assert_eq!(e.used.currency, "EUR");
        assert_eq!(e.used.exponent, 3);
        assert_eq!(e.severity.as_deref(), Some("warning"));
        assert!(e.exhausted);
    }

    #[test]
    fn extra_usage_rejected_for_invalid_credits_or_metadata() {
        let reject = |usage: serde_json::Value| {
            QuotaSnapshot::from_usage_response(&usage, NOW)
                .extra_usage
                .is_none()
        };
        // Missing used_credits.
        assert!(reject(serde_json::json!({
            "extra_usage": { "is_enabled": true, "monthly_limit": 100 }
        })));
        // Missing monthly_limit.
        assert!(reject(serde_json::json!({
            "extra_usage": { "is_enabled": true, "used_credits": 50 }
        })));
        // Fractional exponent.
        assert!(reject(serde_json::json!({
            "extra_usage": { "is_enabled": true, "used_credits": 1, "monthly_limit": 2 },
            "spend": { "limit": { "currency": "USD", "exponent": 2.5 } }
        })));
        // Currency that is not three alphabetic characters.
        assert!(reject(serde_json::json!({
            "extra_usage": { "is_enabled": true, "used_credits": 1, "monthly_limit": 2 },
            "spend": { "limit": { "currency": "US", "exponent": 2 } }
        })));
    }

    #[test]
    fn binding_window_maps_each_active_kind() {
        let binding = |usage: serde_json::Value| {
            QuotaSnapshot::from_usage_response(&usage, NOW).binding_window
        };
        assert_eq!(
            binding(serde_json::json!({ "limits": [{ "kind": "session", "is_active": true }] }))
                .as_deref(),
            Some("five_hour")
        );
        assert_eq!(
            binding(serde_json::json!({ "limits": [{ "kind": "weekly_all", "is_active": true }] }))
                .as_deref(),
            Some("seven_day")
        );
        // No active limit yields no binding window and no binding source.
        let idle = QuotaSnapshot::from_usage_response(
            &serde_json::json!({ "limits": [{ "kind": "session", "is_active": false }] }),
            NOW,
        );
        assert!(idle.binding_window.is_none());
        assert!(idle.binding_window_source.is_none());
        // An active limit of an unknown kind is not a binding window.
        assert!(
            binding(serde_json::json!({ "limits": [{ "kind": "mystery", "is_active": true }] }))
                .is_none()
        );
    }

    #[test]
    fn finite_header_number_rejects_empty_and_unparseable() {
        assert_eq!(finite_header_number(&[("h", "3.5")], "h"), Some(3.5));
        assert_eq!(finite_header_number(&[("h", "  2.0 ")], "h"), Some(2.0));
        // Empty and whitespace-only values are treated as absent.
        assert_eq!(finite_header_number(&[("h", "")], "h"), None);
        assert_eq!(finite_header_number(&[("h", "   ")], "h"), None);
        assert_eq!(finite_header_number(&[("h", "nope")], "h"), None);
        assert_eq!(finite_header_number(&[("other", "1")], "h"), None);
    }

    #[test]
    fn js_round_is_half_up() {
        assert_eq!(js_round(0.5), 1.0);
        assert_eq!(js_round(1.5), 2.0);
        assert_eq!(js_round(2.4), 2.0);
        assert_eq!(js_round(2.6), 3.0);
        // Halves round toward +inf, so -0.5 lands on 0, not -1.
        assert_eq!(js_round(-0.5), 0.0);
        assert_eq!(js_round(-1.5), -1.0);
    }

    #[test]
    fn iso_timestamps_respect_js_date_range() {
        assert_eq!(
            iso_from_epoch_seconds(0.0).as_deref(),
            Some("1970-01-01T00:00:00.000Z")
        );
        // Beyond JavaScript's Date range the reset is dropped rather than wrapped.
        assert!(iso_from_epoch_seconds(1e20).is_none());
        assert!(iso_from_epoch_seconds(f64::INFINITY).is_none());
    }

    #[test]
    fn extract_overage_state_user_scope_and_statuses() {
        let active = extract_overage_state(&[
            ("anthropic-ratelimit-unified-overage-status", "active"),
            ("anthropic-ratelimit-unified-overage-scope", "user"),
            ("anthropic-ratelimit-unified-overage-in-use", "true"),
        ])
        .unwrap();
        assert_eq!(active.status, OverageStatus::Active);
        assert_eq!(active.scope, OverageScope::User);
        assert!(active.in_use);
        assert!(active.disabled_reason.is_none());

        let available =
            extract_overage_state(&[("anthropic-ratelimit-unified-overage-status", "available")])
                .unwrap();
        assert_eq!(available.status, OverageStatus::Available);
        assert_eq!(available.scope, OverageScope::Unknown);
        assert!(!available.in_use);

        // An empty status header is treated as no overage frame at all.
        assert!(
            extract_overage_state(&[("anthropic-ratelimit-unified-overage-status", "")]).is_none()
        );
    }

    #[test]
    fn extract_grace_state_reset_only_and_inactive_zero() {
        // Reset present, utilisation absent: inactive but still carries a reset.
        let reset_only =
            extract_grace_state(&[("anthropic-ratelimit-unified-grace-reset", "0")]).unwrap();
        assert!(!reset_only.active);
        assert!(reset_only.utilization.is_none());
        assert_eq!(
            reset_only.resets_at.as_deref(),
            Some("1970-01-01T00:00:00.000Z")
        );

        // Zero utilisation is not active.
        let zero =
            extract_grace_state(&[("anthropic-ratelimit-unified-grace-utilization", "0")]).unwrap();
        assert!(!zero.active);
        assert_eq!(zero.utilization, Some(0.0));
        assert!(zero.resets_at.is_none());

        assert!(extract_grace_state(&[("unrelated", "x")]).is_none());
    }

    #[test]
    fn merge_fallback_without_field_sources_uses_top_level_source() {
        // Existing is a poll-sourced snapshot that advises fallback but has no
        // per-field provenance recorded, so the merge must fall back to the
        // top-level source to label the preserved fallback advisory.
        let existing = QuotaSnapshot {
            five_hour: Some(win(10.0, NOW)),
            fallback_advised: Some(true),
            source: Some(QuotaFieldSource::Poll),
            field_sources: None,
            ..Default::default()
        };
        let incoming = normalize_quota_headers(
            &[("anthropic-ratelimit-unified-5h-utilization", "0.5")],
            NOW + 1_000,
        );
        let merged = merge_header_quota_snapshot(Some(&existing), &incoming);
        assert_eq!(merged.fallback_advised, Some(true));
        assert_eq!(
            merged.field_sources.unwrap().fallback_advised,
            Some(QuotaFieldSource::Poll)
        );
    }

    #[test]
    fn source_precedence_orders_poll_over_headers() {
        assert_eq!(source_precedence(&QuotaSnapshot::default()), 0);
        assert_eq!(
            source_precedence(&QuotaSnapshot {
                source: Some(QuotaFieldSource::Headers),
                ..Default::default()
            }),
            1
        );
        assert_eq!(
            source_precedence(&QuotaSnapshot {
                source: Some(QuotaFieldSource::Poll),
                ..Default::default()
            }),
            2
        );
    }

    #[test]
    fn merge_header_owned_window_keeps_newer_or_higher_precedence() {
        let only_existing = QuotaSnapshot {
            five_hour: Some(win(10.0, NOW)),
            ..Default::default()
        };
        assert_eq!(
            merge_header_owned_window(
                &only_existing,
                &QuotaSnapshot::default(),
                QuotaWindowName::FiveHour
            ),
            only_existing.five_hour
        );

        let only_incoming = QuotaSnapshot {
            five_hour: Some(win(20.0, NOW)),
            ..Default::default()
        };
        assert_eq!(
            merge_header_owned_window(
                &QuotaSnapshot::default(),
                &only_incoming,
                QuotaWindowName::FiveHour
            ),
            only_incoming.five_hour
        );

        // Both present: the newer observation wins regardless of order.
        let older = QuotaSnapshot {
            five_hour: Some(win(10.0, NOW)),
            ..Default::default()
        };
        let newer = QuotaSnapshot {
            five_hour: Some(win(20.0, NOW + 1_000)),
            ..Default::default()
        };
        assert_eq!(
            merge_header_owned_window(&older, &newer, QuotaWindowName::FiveHour)
                .unwrap()
                .used_percent,
            20.0
        );
        assert_eq!(
            merge_header_owned_window(&newer, &older, QuotaWindowName::FiveHour)
                .unwrap()
                .used_percent,
            20.0
        );

        // Equal timestamps: the higher-precedence (poll) source is kept.
        let poll = QuotaSnapshot {
            five_hour: Some(win(10.0, NOW)),
            source: Some(QuotaFieldSource::Poll),
            ..Default::default()
        };
        let header = QuotaSnapshot {
            five_hour: Some(win(20.0, NOW)),
            source: Some(QuotaFieldSource::Headers),
            ..Default::default()
        };
        assert_eq!(
            merge_header_owned_window(&poll, &header, QuotaWindowName::FiveHour)
                .unwrap()
                .used_percent,
            10.0
        );
        // Equal timestamps and equal precedence: incoming wins.
        let header2 = QuotaSnapshot {
            five_hour: Some(win(30.0, NOW)),
            source: Some(QuotaFieldSource::Headers),
            ..Default::default()
        };
        assert_eq!(
            merge_header_owned_window(&header, &header2, QuotaWindowName::FiveHour)
                .unwrap()
                .used_percent,
            30.0
        );
    }

    #[test]
    fn merge_header_scoped_unions_and_prefers_newer() {
        // Existing has no scoped data: incoming is adopted.
        let incoming = QuotaSnapshot {
            scoped: Some(vec![scoped_win("a", NOW, 10.0)]),
            ..Default::default()
        };
        assert_eq!(
            merge_header_scoped(&QuotaSnapshot::default(), &incoming),
            incoming.scoped
        );

        // A present-but-empty existing array survives untouched.
        let empty_existing = QuotaSnapshot {
            scoped: Some(Vec::new()),
            ..Default::default()
        };
        assert_eq!(
            merge_header_scoped(&empty_existing, &incoming),
            Some(Vec::new())
        );

        // Non-empty existing, empty/absent incoming: existing is kept.
        let existing = QuotaSnapshot {
            scoped: Some(vec![scoped_win("a", NOW, 10.0)]),
            ..Default::default()
        };
        assert_eq!(
            merge_header_scoped(&existing, &QuotaSnapshot::default()),
            existing.scoped
        );

        // Union by id: the newer observation of a shared id wins, unique ids
        // from both sides survive.
        let inc = QuotaSnapshot {
            scoped: Some(vec![scoped_win("a", NOW, 10.0), scoped_win("c", NOW, 30.0)]),
            ..Default::default()
        };
        let ex = QuotaSnapshot {
            scoped: Some(vec![
                scoped_win("a", NOW + 1_000, 15.0),
                scoped_win("b", NOW, 20.0),
            ]),
            ..Default::default()
        };
        let merged = merge_header_scoped(&ex, &inc).unwrap();
        assert_eq!(merged.len(), 3);
        assert_eq!(
            merged.iter().find(|w| w.id == "a").unwrap().used_percent,
            15.0
        );
        assert!(merged.iter().any(|w| w.id == "b"));
        assert!(merged.iter().any(|w| w.id == "c"));

        // An older existing observation does not override a newer incoming one.
        let inc_newer = QuotaSnapshot {
            scoped: Some(vec![scoped_win("a", NOW + 5_000, 99.0)]),
            ..Default::default()
        };
        let ex_older = QuotaSnapshot {
            scoped: Some(vec![scoped_win("a", NOW, 10.0)]),
            ..Default::default()
        };
        let merged = merge_header_scoped(&ex_older, &inc_newer).unwrap();
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].used_percent, 99.0);
    }

    #[test]
    fn persistence_merge_short_circuits_on_missing_base_or_poll_incoming() {
        let incoming = normalize_quota_headers(&MAIN_HEADERS, NOW);
        // No base: incoming is returned verbatim.
        assert_eq!(
            merge_header_quota_for_persistence(None, &incoming),
            incoming
        );
        // Incoming is a poll (not header-sourced): it wins outright.
        let poll = polled();
        let existing = normalize_quota_headers(&TEAM_HEADERS, NOW + 5_000);
        assert_eq!(
            merge_header_quota_for_persistence(Some(&existing), &poll),
            poll
        );
    }

    #[test]
    fn persistence_merge_preserves_poll_binding_and_scoped() {
        let existing = polled(); // poll binding = scoped-fable, scoped Some
        let incoming = normalize_quota_headers(&MAIN_HEADERS, NOW + 10_000);
        let merged = merge_header_quota_for_persistence(Some(&existing), &incoming);
        // Poll-owned binding window is preserved against the header claim.
        assert_eq!(
            merged.binding_window.as_deref(),
            Some("claude-weekly-scoped-fable")
        );
        assert_eq!(merged.binding_window_source, Some(QuotaFieldSource::Poll));
        // Poll-owned scoped data is preserved.
        assert_eq!(merged.scoped, existing.scoped);
        // The newer header window is adopted.
        assert_eq!(merged.five_hour.as_ref().unwrap().used_percent, 3.0);
        let srcs = merged.field_sources.unwrap();
        assert_eq!(srcs.scoped, Some(QuotaFieldSource::Poll));
        assert_eq!(srcs.binding_window, Some(QuotaFieldSource::Poll));
        assert_eq!(srcs.five_hour, Some(QuotaFieldSource::Headers));
    }

    #[test]
    fn policy_fails_closed_on_non_finite_remaining() {
        let snap = QuotaSnapshot {
            five_hour: Some(QuotaWindow {
                used_percent: 0.0,
                remaining_percent: f64::NAN,
                resets_at: None,
                checked_at: NOW,
            }),
            seven_day: Some(win(0.0, NOW)),
            ..Default::default()
        };
        assert!(!QuotaPolicy::default().passes(Some(&snap)));
        let lenient = QuotaPolicy {
            fail_closed_on_unknown: false,
            ..QuotaPolicy::default()
        };
        assert!(lenient.passes(Some(&snap)));
    }

    #[test]
    fn policy_floors_interval_and_reads_per_window_minimums() {
        let p = QuotaPolicy {
            check_interval_ms: 1_000,
            minimum_remaining_five_hour: 5.0,
            minimum_remaining_seven_day: 9.0,
            ..QuotaPolicy::default()
        };
        assert_eq!(p.interval_ms(), 60_000);
        assert_eq!(p.minimum_remaining(QuotaWindowName::FiveHour), 5.0);
        assert_eq!(p.minimum_remaining(QuotaWindowName::SevenDay), 9.0);
        let wide = QuotaPolicy {
            check_interval_ms: 600_000,
            ..QuotaPolicy::default()
        };
        assert_eq!(wide.interval_ms(), 600_000);
    }

    #[test]
    fn snapshot_is_fresh_requires_both_windows_within_interval() {
        let policy = QuotaPolicy::default();
        let snap = polled();
        assert!(policy.snapshot_is_fresh(Some(&snap), NOW));
        assert!(policy.snapshot_is_fresh(Some(&snap), NOW + DEFAULT_QUOTA_CHECK_INTERVAL_MS - 1));
        // The horizon is strict: exactly one interval old is no longer fresh.
        assert!(!policy.snapshot_is_fresh(Some(&snap), NOW + DEFAULT_QUOTA_CHECK_INTERVAL_MS));
        // A missing window is never fresh.
        let only_five = QuotaSnapshot {
            five_hour: snap.five_hour.clone(),
            ..Default::default()
        };
        assert!(!policy.snapshot_is_fresh(Some(&only_five), NOW));
        assert!(!policy.snapshot_is_fresh(None, NOW));
        // Disabled policy reports fresh unconditionally.
        let disabled = QuotaPolicy {
            enabled: false,
            ..QuotaPolicy::default()
        };
        assert!(disabled.snapshot_is_fresh(None, NOW));
    }

    #[test]
    fn is_stale_when_standard_or_scoped_window_ages_out() {
        let policy = QuotaPolicy::default();
        let snap = polled();
        assert!(!policy.is_stale(Some(&snap), NOW, Some("Fable")));
        // A standard window past the interval is stale.
        assert!(policy.is_stale(
            Some(&snap),
            NOW + DEFAULT_QUOTA_CHECK_INTERVAL_MS,
            Some("Fable")
        ));

        // Standard windows refreshed but the scoped window left behind.
        let fresh_now = NOW + DEFAULT_QUOTA_CHECK_INTERVAL_MS + 1;
        let mut mixed = snap.clone();
        mixed.five_hour.as_mut().unwrap().checked_at = fresh_now;
        mixed.seven_day.as_mut().unwrap().checked_at = fresh_now;
        assert!(policy.is_stale(Some(&mixed), fresh_now, Some("Fable")));
        // Without a model scope only the standard windows are considered.
        assert!(!policy.is_stale(Some(&mixed), fresh_now, None));
    }

    #[test]
    fn next_refresh_handles_disabled_missing_and_unresettable_blocks() {
        let disabled = QuotaPolicy {
            enabled: false,
            ..QuotaPolicy::default()
        };
        assert_eq!(
            disabled.next_refresh_at(Some(&polled()), NOW),
            NOW + DEFAULT_QUOTA_CHECK_INTERVAL_MS
        );

        let policy = QuotaPolicy::default();
        // No windows at all: one interval out, uncapped.
        assert_eq!(
            policy.next_refresh_at(Some(&QuotaSnapshot::default()), NOW),
            NOW + DEFAULT_QUOTA_CHECK_INTERVAL_MS
        );
        assert_eq!(
            policy.next_refresh_at(None, NOW),
            NOW + DEFAULT_QUOTA_CHECK_INTERVAL_MS
        );

        // A blocking window with no parseable reset falls back to one interval,
        // capped at the oldest window's freshness deadline.
        let strict = QuotaPolicy {
            minimum_remaining_five_hour: 99.0,
            ..QuotaPolicy::default()
        };
        let mut blocked = polled();
        blocked.five_hour.as_mut().unwrap().resets_at = None;
        assert_eq!(
            strict.next_refresh_at(Some(&blocked), NOW),
            NOW + DEFAULT_QUOTA_CHECK_INTERVAL_MS
        );
    }

    #[test]
    fn poll_completion_returns_poll_when_current_absent_or_poll() {
        let poll = polled();
        assert_eq!(merge_poll_completion_with_newer_headers(None, &poll), poll);
        // A poll-sourced current is not a header cache, so the poll wins.
        let other_poll = QuotaSnapshot::from_usage_response(&team_usage_capture(), NOW + 100_000);
        assert_eq!(
            merge_poll_completion_with_newer_headers(Some(&other_poll), &poll),
            poll
        );

        // Only the newer header window is kept; the poll's other data survives.
        let header = normalize_quota_headers(
            &[("anthropic-ratelimit-unified-5h-utilization", "0.9")],
            NOW + 60_000,
        );
        let merged = merge_poll_completion_with_newer_headers(Some(&header), &poll);
        assert_eq!(merged.five_hour.as_ref().unwrap().used_percent, 90.0);
        assert_eq!(merged.seven_day, poll.seven_day);
        assert_eq!(merged.scoped, poll.scoped);
    }

    #[test]
    fn parse_iso_ms_round_trips_and_rejects_garbage() {
        assert_eq!(
            parse_iso_ms("2026-01-01T00:00:00Z"),
            Some(1_767_225_600_000)
        );
        assert_eq!(
            parse_iso_ms("2026-01-01T00:00:00.500Z"),
            Some(1_767_225_600_500)
        );
        assert!(parse_iso_ms("not-a-date").is_none());
        assert!(parse_iso_ms("").is_none());
    }

    #[test]
    fn cached_windows_relevant_until_reset_passes() {
        assert!(!cached_window_still_relevant(None, NOW));

        let base = win(0.0, NOW);
        // No reset: always relevant.
        assert!(cached_window_still_relevant(Some(&base), NOW));
        // Unparseable reset: treated as still relevant.
        let garbage = QuotaWindow {
            resets_at: Some("garbage".to_owned()),
            ..base.clone()
        };
        assert!(cached_window_still_relevant(Some(&garbage), NOW));
        // Future reset: relevant; past reset: no longer relevant.
        let future = chrono::DateTime::from_timestamp_millis(NOW + 60_000)
            .unwrap()
            .to_rfc3339();
        let past = chrono::DateTime::from_timestamp_millis(NOW - 60_000)
            .unwrap()
            .to_rfc3339();
        let relevant = QuotaWindow {
            resets_at: Some(future),
            ..base.clone()
        };
        let expired = QuotaWindow {
            resets_at: Some(past),
            ..base.clone()
        };
        assert!(cached_window_still_relevant(Some(&relevant), NOW));
        assert!(!cached_window_still_relevant(Some(&expired), NOW));

        // The snapshot form requires both standard windows to be relevant.
        let fresh = QuotaSnapshot {
            five_hour: Some(relevant.clone()),
            seven_day: Some(base.clone()),
            ..Default::default()
        };
        assert!(cached_snapshot_still_relevant(Some(&fresh), NOW));
        let stale = QuotaSnapshot {
            five_hour: Some(relevant),
            seven_day: Some(expired),
            ..Default::default()
        };
        assert!(!cached_snapshot_still_relevant(Some(&stale), NOW));
        assert!(!cached_snapshot_still_relevant(None, NOW));
    }
}
