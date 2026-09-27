//! Killswitch: hard-block an account once its remaining plan quota drops
//! below per-account thresholds, even while Anthropic would still accept
//! requests.
//!
//! Ported from anthropic-auth (`killswitch.ts` and the killswitch half of
//! `accounts.ts`, upstream `b504bc8`). The slash-command *rendering* is host
//! glue and is not ported; the command grammar and config update are, so a
//! Rust host can offer the same `/claude-killswitch` surface.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::quota::{QuotaSnapshot, QuotaWindowName, parse_iso_ms};

/// Default remaining-percent thresholds: block the 5h window at < 5%, the
/// 7d window at < 10%, and a model-scoped window at ≤ 0%.
pub const DEFAULT_KILLSWITCH_THRESHOLDS: ResolvedThresholds = ResolvedThresholds {
    five_hour: 5.0,
    seven_day: 10.0,
    scoped: 0.0,
};

/// Fallback `retry-after` when no window names a future reset.
pub const KILLSWITCH_DEFAULT_RETRY_AFTER_SECS: u64 = 300;

/// Thresholds as configured. `5h`/`1w` are accepted aliases.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct KillswitchThresholds {
    /// Five-hour remaining-percent floor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub five_hour: Option<f64>,
    /// Alias for `five_hour`.
    #[serde(rename = "5h", default, skip_serializing_if = "Option::is_none")]
    pub five_hour_alias: Option<f64>,
    /// Seven-day remaining-percent floor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seven_day: Option<f64>,
    /// Alias for `seven_day`.
    #[serde(rename = "1w", default, skip_serializing_if = "Option::is_none")]
    pub seven_day_alias: Option<f64>,
    /// Model-scoped remaining-percent ceiling (blocks at `<=`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scoped: Option<f64>,
}

impl KillswitchThresholds {
    /// Thresholds with explicit values.
    pub fn new(five_hour: f64, seven_day: f64, scoped: Option<f64>) -> Self {
        Self {
            five_hour: Some(five_hour),
            seven_day: Some(seven_day),
            scoped,
            ..Default::default()
        }
    }

    /// Resolve aliases and defaults; non-finite values fall back to defaults.
    pub fn resolve(&self) -> ResolvedThresholds {
        let finite =
            |value: Option<f64>, default: f64| value.filter(|v| v.is_finite()).unwrap_or(default);
        ResolvedThresholds {
            five_hour: finite(
                self.five_hour.or(self.five_hour_alias),
                DEFAULT_KILLSWITCH_THRESHOLDS.five_hour,
            ),
            seven_day: finite(
                self.seven_day.or(self.seven_day_alias),
                DEFAULT_KILLSWITCH_THRESHOLDS.seven_day,
            ),
            scoped: finite(self.scoped, DEFAULT_KILLSWITCH_THRESHOLDS.scoped),
        }
    }
}

/// Fully resolved thresholds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ResolvedThresholds {
    /// Five-hour floor (blocks at `<`).
    pub five_hour: f64,
    /// Seven-day floor (blocks at `<`).
    pub seven_day: f64,
    /// Scoped ceiling (blocks at `<=`).
    pub scoped: f64,
}

impl ResolvedThresholds {
    /// The floor for a standard window.
    pub fn window(&self, name: QuotaWindowName) -> f64 {
        match name {
            QuotaWindowName::FiveHour => self.five_hour,
            QuotaWindowName::SevenDay => self.seven_day,
        }
    }
}

/// Killswitch configuration.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct KillswitchConfig {
    /// Master switch; off by default.
    #[serde(default)]
    pub enabled: bool,
    /// Thresholds for the main account, and the default for every account
    /// without an override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub main: Option<KillswitchThresholds>,
    /// Per-account overrides keyed by account id.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub accounts: BTreeMap<String, KillswitchThresholds>,
}

impl KillswitchConfig {
    /// Thresholds for `account_id` (`None` = the main account).
    pub fn thresholds_for(&self, account_id: Option<&str>) -> ResolvedThresholds {
        if let Some(overrides) = account_id.and_then(|id| self.accounts.get(id)) {
            return overrides.resolve();
        }
        self.main
            .as_ref()
            .map_or(DEFAULT_KILLSWITCH_THRESHOLDS, KillswitchThresholds::resolve)
    }

    /// Whether `quota` stays above the killswitch for `account_id`. Always
    /// `true` while disabled.
    ///
    /// A present window below its floor blocks even if the other window is
    /// unknown. With `model`, the matching scoped window additionally blocks
    /// at `<=` its ceiling — independently of, and before, the
    /// unknown-window decision, so an exhausted scoped window blocks even
    /// when 5h/7d are missing. A model with no scoped window is unaffected.
    /// Only after both checks does an unknown 5h/7d window fall back to
    /// `fail_closed_on_unknown`.
    pub fn passes(
        &self,
        quota: Option<&QuotaSnapshot>,
        account_id: Option<&str>,
        model: Option<&str>,
        fail_closed_on_unknown: bool,
    ) -> bool {
        if !self.enabled {
            return true;
        }
        let thresholds = self.thresholds_for(account_id);
        let mut saw_unknown = false;
        for name in QuotaWindowName::ALL {
            match quota.and_then(|q| q.window(name)) {
                Some(window) if window.remaining_percent.is_finite() => {
                    if window.remaining_percent < thresholds.window(name) {
                        return false;
                    }
                }
                _ => saw_unknown = true,
            }
        }
        if model.is_some()
            && let Some(window) = quota.and_then(|q| q.scoped_window_for_model(model))
            && window.remaining_percent.is_finite()
            && window.remaining_percent <= thresholds.scoped
        {
            return false;
        }
        if saw_unknown {
            return !fail_closed_on_unknown;
        }
        true
    }

    /// Apply a parsed command, returning the updated config (`None` for
    /// read-only actions).
    pub fn apply(
        &self,
        action: &KillswitchCommand,
        account_ids: &[String],
    ) -> Option<KillswitchConfig> {
        match action {
            KillswitchCommand::Status | KillswitchCommand::Usage => None,
            KillswitchCommand::On => Some(KillswitchConfig {
                enabled: true,
                main: Some(self.main.clone().unwrap_or_else(|| {
                    KillswitchThresholds::new(
                        DEFAULT_KILLSWITCH_THRESHOLDS.five_hour,
                        DEFAULT_KILLSWITCH_THRESHOLDS.seven_day,
                        None,
                    )
                })),
                accounts: self.accounts.clone(),
            }),
            KillswitchCommand::Off => Some(KillswitchConfig {
                enabled: false,
                ..self.clone()
            }),
            KillswitchCommand::Set(entries) => {
                let mut updated = KillswitchConfig {
                    enabled: true,
                    ..self.clone()
                };
                for entry in entries {
                    let thresholds =
                        KillswitchThresholds::new(entry.five_hour, entry.seven_day, entry.scoped);
                    match entry.account.as_str() {
                        "main" => updated.main = Some(thresholds),
                        "all" => {
                            updated.main = Some(thresholds.clone());
                            for id in account_ids {
                                updated.accounts.insert(id.clone(), thresholds.clone());
                            }
                        }
                        other => {
                            updated.accounts.insert(other.to_owned(), thresholds);
                        }
                    }
                }
                Some(updated)
            }
        }
    }
}

/// Seconds until the earliest future reset among `quotas`, plus a minute of
/// slack; [`KILLSWITCH_DEFAULT_RETRY_AFTER_SECS`] when nothing resets.
///
/// With `scoped_model`, **only** the matching scoped windows' resets count:
/// the sooner 5h reset would otherwise invite a retry storm against a
/// weekly block that will not clear for days.
pub fn killswitch_retry_after_secs<'a>(
    quotas: impl IntoIterator<Item = Option<&'a QuotaSnapshot>>,
    now: i64,
    scoped_model: Option<&str>,
) -> u64 {
    let mut earliest: Option<i64> = None;
    for quota in quotas.into_iter().flatten() {
        let resets: Vec<Option<&str>> = match scoped_model {
            Some(model) => vec![
                quota
                    .scoped_window_for_model(Some(model))
                    .and_then(|w| w.resets_at.as_deref()),
            ],
            None => QuotaWindowName::ALL
                .iter()
                .map(|name| quota.window(*name).and_then(|w| w.resets_at.as_deref()))
                .collect(),
        };
        for reset in resets.into_iter().flatten().filter_map(parse_iso_ms) {
            if reset > now {
                earliest = Some(earliest.map_or(reset, |e| e.min(reset)));
            }
        }
    }
    match earliest {
        None => KILLSWITCH_DEFAULT_RETRY_AFTER_SECS,
        Some(reset) => {
            let seconds = ((reset - now) as f64 / 1000.0).ceil().max(1.0) as u64;
            seconds + 60
        }
    }
}

/// `retry-after` on a synthesized killswitch block (the host router sends a
/// fixed 60 s).
pub const KILLSWITCH_BLOCK_RETRY_AFTER_SECS: u64 = 60;

/// The response a host synthesizes when the killswitch blocks every OAuth
/// route (merged anthropic-auth `f74d736`, Pi router): HTTP 429 with an
/// Anthropic-shaped `rate_limit_error` body.
///
/// It carries `x-should-retry: false`: this is a *local policy* block, and
/// [`crate::retry::classify_retry`] honours `x-should-retry` before the
/// status, so a retry wrapper surfaces the block instead of sleeping on
/// `retry-after` and re-asking the same gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillswitchBlockResponse {
    /// Always 429.
    pub status: u16,
    /// `content-type`, `retry-after`, `x-should-retry`, in that order.
    pub headers: Vec<(String, String)>,
    /// `{"type":"error","error":{"type":"rate_limit_error","message":…}}`.
    pub body: String,
}

/// Build the [`KillswitchBlockResponse`].
pub fn killswitch_block_response() -> KillswitchBlockResponse {
    KillswitchBlockResponse {
        status: 429,
        headers: vec![
            ("content-type".into(), "application/json".into()),
            (
                "retry-after".into(),
                KILLSWITCH_BLOCK_RETRY_AFTER_SECS.to_string(),
            ),
            ("x-should-retry".into(), "false".into()),
        ],
        body: r#"{"type":"error","error":{"type":"rate_limit_error","message":"Killswitch blocked all OAuth routes"}}"#
            .into(),
    }
}

/// One `account:fh,sd[,scoped]` entry of `/claude-killswitch set`.
#[derive(Debug, Clone, PartialEq)]
pub struct KillswitchSetEntry {
    /// `main`, `all`, or an account id.
    pub account: String,
    /// Five-hour floor.
    pub five_hour: f64,
    /// Seven-day floor.
    pub seven_day: f64,
    /// Optional scoped ceiling.
    pub scoped: Option<f64>,
}

/// A parsed `/claude-killswitch` invocation.
#[derive(Debug, Clone, PartialEq)]
pub enum KillswitchCommand {
    /// No arguments.
    Status,
    /// `on`.
    On,
    /// `off`.
    Off,
    /// `set account:fh,sd[,scoped] …`.
    Set(Vec<KillswitchSetEntry>),
    /// Anything else.
    Usage,
}

fn parse_set_entry(part: &str) -> Option<KillswitchSetEntry> {
    let (account, numbers) = part.split_once(':')?;
    if account.is_empty() {
        return None;
    }
    let values: Vec<&str> = numbers.split(',').collect();
    if !(2..=3).contains(&values.len())
        || values
            .iter()
            .any(|v| v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    let number = |v: &str| v.parse::<f64>().ok();
    Some(KillswitchSetEntry {
        account: account.to_owned(),
        five_hour: number(values[0])?,
        seven_day: number(values[1])?,
        scoped: match values.get(2) {
            Some(v) => Some(number(v)?),
            None => None,
        },
    })
}

/// Parse `/claude-killswitch` arguments.
pub fn parse_killswitch_command(arguments: &str) -> KillswitchCommand {
    let parts: Vec<&str> = arguments.split_whitespace().collect();
    match parts.as_slice() {
        [] => KillswitchCommand::Status,
        ["on"] => KillswitchCommand::On,
        ["off"] => KillswitchCommand::Off,
        ["set", entries @ ..] if !entries.is_empty() => entries
            .iter()
            .map(|e| parse_set_entry(e))
            .collect::<Option<Vec<_>>>()
            .map_or(KillswitchCommand::Usage, KillswitchCommand::Set),
        _ => KillswitchCommand::Usage,
    }
}

#[cfg(test)]
mod tests {
    //! Ports of core `killswitch.test.ts`.
    use super::*;
    use crate::quota::{QuotaWindow, ScopedQuotaWindow};

    const NOW: i64 = 1_700_000_000_000;

    fn window(remaining: f64) -> QuotaWindow {
        QuotaWindow {
            used_percent: 100.0 - remaining,
            remaining_percent: remaining,
            resets_at: None,
            checked_at: NOW,
        }
    }

    fn scoped(remaining: f64, name: &str, id: Option<&str>) -> ScopedQuotaWindow {
        ScopedQuotaWindow {
            id: "claude-weekly-scoped-fable".into(),
            title: format!("{name} only"),
            model_id: id.map(str::to_owned),
            model_name: name.into(),
            used_percent: 100.0 - remaining,
            remaining_percent: remaining,
            resets_at: None,
            checked_at: NOW,
        }
    }

    fn healthy() -> QuotaSnapshot {
        QuotaSnapshot {
            five_hour: Some(window(50.0)),
            seven_day: Some(window(80.0)),
            ..Default::default()
        }
    }

    fn enabled(scoped: f64) -> KillswitchConfig {
        KillswitchConfig {
            enabled: true,
            main: Some(KillswitchThresholds::new(5.0, 10.0, Some(scoped))),
            accounts: BTreeMap::new(),
        }
    }

    fn iso(ms: i64) -> Option<String> {
        chrono::DateTime::from_timestamp_millis(ms).map(|d| d.to_rfc3339())
    }

    #[test]
    fn defaults_and_normalization() {
        assert_eq!(DEFAULT_KILLSWITCH_THRESHOLDS.scoped, 0.0);
        assert_eq!(
            KillswitchThresholds::new(5.0, 10.0, None).resolve().scoped,
            0.0
        );
        assert_eq!(
            KillswitchThresholds::new(5.0, 10.0, Some(20.0))
                .resolve()
                .scoped,
            20.0
        );
        for bad in [f64::NAN, f64::INFINITY] {
            assert_eq!(
                KillswitchThresholds::new(5.0, 10.0, Some(bad))
                    .resolve()
                    .scoped,
                0.0
            );
        }
        let aliased = KillswitchThresholds {
            five_hour_alias: Some(3.0),
            seven_day_alias: Some(8.0),
            ..Default::default()
        };
        assert_eq!(aliased.resolve().five_hour, 3.0);
        assert_eq!(aliased.resolve().seven_day, 8.0);
        let config = enabled(20.0);
        assert_eq!(config.thresholds_for(None).scoped, 20.0);
        assert_eq!(config.thresholds_for(Some("work-alt")).scoped, 20.0);
    }

    #[test]
    fn scoped_check_only_runs_with_a_model() {
        let mut quota = healthy();
        quota.scoped = Some(vec![scoped(0.0, "Claude Fable 5", Some("claude-fable-5"))]);
        let config = enabled(100.0);
        assert!(config.passes(Some(&quota), None, None, true));
        assert!(!config.passes(Some(&quota), None, Some("claude-fable-5"), true));
        // A non-matching model is unaffected by another model's exhaustion.
        assert!(config.passes(Some(&quota), None, Some("claude-opus-4-8"), true));
    }

    #[test]
    fn scoped_threshold_is_inclusive() {
        let config = enabled(0.0);
        let mut quota = healthy();
        quota.scoped = Some(vec![scoped(0.0, "Fable", None)]);
        assert!(!config.passes(Some(&quota), None, Some("claude-fable-5"), true));
        quota.scoped = Some(vec![scoped(1.0, "Fable", None)]);
        assert!(config.passes(Some(&quota), None, Some("claude-fable-5"), true));
        let raised = enabled(20.0);
        quota.scoped = Some(vec![scoped(20.0, "Fable", None)]);
        assert!(!raised.passes(Some(&quota), None, Some("claude-fable-5"), true));
        quota.scoped = Some(vec![scoped(f64::NAN, "Fable", None)]);
        assert!(raised.passes(Some(&quota), None, Some("claude-fable-5"), true));
    }

    #[test]
    fn standard_windows_block_regardless_of_scoped_and_disabled_never_blocks() {
        let config = enabled(0.0);
        let mut quota = healthy();
        quota.five_hour = Some(window(4.0));
        quota.scoped = Some(vec![scoped(90.0, "Fable", None)]);
        assert!(!config.passes(Some(&quota), None, Some("claude-fable-5"), true));
        let disabled = KillswitchConfig::default();
        quota.scoped = Some(vec![scoped(0.0, "Fable", None)]);
        assert!(disabled.passes(Some(&quota), None, Some("claude-fable-5"), true));
    }

    #[test]
    fn scoped_blocks_before_the_unknown_window_fail_open() {
        let config = enabled(0.0);
        let quota = QuotaSnapshot {
            scoped: Some(vec![scoped(0.0, "Fable", None)]),
            ..Default::default()
        };
        assert!(!config.passes(Some(&quota), None, Some("claude-fable-5"), false));
        let mut one_bad = healthy();
        one_bad.seven_day = Some(window(f64::NAN));
        one_bad.scoped = Some(vec![scoped(0.0, "Fable", None)]);
        assert!(!config.passes(Some(&one_bad), None, Some("claude-fable-5"), false));
        // Complements: healthy or absent scoped with unknown 5h/7d + fail-open passes.
        let healthy_scoped = QuotaSnapshot {
            scoped: Some(vec![scoped(50.0, "Fable", None)]),
            ..Default::default()
        };
        assert!(config.passes(Some(&healthy_scoped), None, Some("claude-fable-5"), false));
        assert!(config.passes(
            Some(&QuotaSnapshot::default()),
            None,
            Some("claude-fable-5"),
            false
        ));
        assert!(!config.passes(None, None, None, true));
    }

    #[test]
    fn matches_a_haiku_window_by_display_name_without_model_id() {
        let config = enabled(0.0);
        let mut quota = healthy();
        quota.scoped = Some(vec![scoped(0.0, "Haiku", None)]);
        assert!(!config.passes(Some(&quota), None, Some("haiku"), true));
    }

    #[test]
    fn parses_two_and_three_number_forms() {
        assert_eq!(
            parse_killswitch_command("set main:3,8"),
            KillswitchCommand::Set(vec![KillswitchSetEntry {
                account: "main".into(),
                five_hour: 3.0,
                seven_day: 8.0,
                scoped: None
            }])
        );
        let KillswitchCommand::Set(entries) =
            parse_killswitch_command("set main:3,8,0 work-alt:5,10")
        else {
            panic!("expected set");
        };
        assert_eq!(entries[0].scoped, Some(0.0));
        assert_eq!(entries[1].scoped, None);
        assert_eq!(parse_killswitch_command(""), KillswitchCommand::Status);
        assert_eq!(parse_killswitch_command(" on "), KillswitchCommand::On);
        assert_eq!(parse_killswitch_command("off"), KillswitchCommand::Off);
        assert_eq!(parse_killswitch_command("set"), KillswitchCommand::Usage);
        assert_eq!(
            parse_killswitch_command("set main:3"),
            KillswitchCommand::Usage
        );
        assert_eq!(
            parse_killswitch_command("set main:-3,8"),
            KillswitchCommand::Usage
        );
        assert_eq!(parse_killswitch_command("bogus"), KillswitchCommand::Usage);
    }

    #[test]
    fn per_account_scoped_threshold_round_trips_through_the_command() {
        let config = KillswitchConfig::default();
        let updated = config
            .apply(
                &parse_killswitch_command("set work-alt:5,10,20"),
                &["work-alt".into()],
            )
            .unwrap();
        assert!(updated.enabled);
        assert_eq!(updated.thresholds_for(Some("work-alt")).scoped, 20.0);
        let all = config
            .apply(
                &parse_killswitch_command("set all:5,10"),
                &["a".into(), "b".into()],
            )
            .unwrap();
        assert_eq!(all.accounts.len(), 2);
        let on = config.apply(&KillswitchCommand::On, &[]).unwrap();
        assert_eq!(on.thresholds_for(None), DEFAULT_KILLSWITCH_THRESHOLDS);
        assert!(!on.apply(&KillswitchCommand::Off, &[]).unwrap().enabled);
        assert!(config.apply(&KillswitchCommand::Status, &[]).is_none());
    }

    #[test]
    fn retry_after_uses_scoped_resets_only_when_asked() {
        let five_reset = NOW + 10 * 60_000;
        let scoped_reset = NOW + 3 * 24 * 3_600_000;
        let mut quota = healthy();
        quota.five_hour.as_mut().unwrap().resets_at = iso(five_reset);
        let mut window = scoped(0.0, "Fable", None);
        window.resets_at = iso(scoped_reset);
        quota.scoped = Some(vec![window]);

        assert_eq!(
            killswitch_retry_after_secs([Some(&quota)], NOW, None),
            600 + 60
        );
        assert_eq!(
            killswitch_retry_after_secs([Some(&quota)], NOW, Some("claude-fable-5")),
            3 * 24 * 3600 + 60
        );
        // Scoped window only in a fallback account is still the only source.
        let main = healthy();
        assert_eq!(
            killswitch_retry_after_secs([Some(&main), Some(&quota)], NOW, Some("claude-fable-5")),
            3 * 24 * 3600 + 60
        );
        assert_eq!(
            killswitch_retry_after_secs([Some(&main)], NOW, Some("claude-fable-5")),
            KILLSWITCH_DEFAULT_RETRY_AFTER_SECS
        );
    }

    /// Merge post-fix: the synthesized 429 is a non-retryable local block.
    #[test]
    fn synthesized_block_is_not_retryable() {
        let response = killswitch_block_response();
        assert_eq!(response.status, 429);
        assert_eq!(
            response.headers,
            vec![
                ("content-type".to_owned(), "application/json".to_owned()),
                ("retry-after".to_owned(), "60".to_owned()),
                ("x-should-retry".to_owned(), "false".to_owned()),
            ]
        );
        let body: serde_json::Value = serde_json::from_str(&response.body).unwrap();
        assert_eq!(body["error"]["type"], "rate_limit_error");
        let class =
            crate::retry::classify_retry(response.status, &response.headers, &response.body);
        assert!(!class.retryable);
        // Without the directive a bare soft 429 would be retried.
        let bare = &response.headers[..2];
        assert!(crate::retry::classify_retry(429, bare, &response.body).retryable);
    }
}
