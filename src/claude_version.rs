//! Claude Code version tracking.
//!
//! Anthropic rejects requests whose fingerprint is too old for newer models
//! (`claude_code_version_too_old`), so a pinned version rots. The fork tracks
//! the live `@anthropic-ai/claude-code` npm version with a one-hour TTL and
//! treats [`CLAUDE_CODE_VERSION`] only as the verified offline floor. A stale
//! registry mirror must never downgrade below that floor: a fingerprint
//! Anthropic already rejects must not be reintroduced.

use std::cmp::Ordering;

use chrono::{DateTime, Duration, Utc};

/// Verified offline floor: the Claude Code version this crate's request
/// behavior was aligned against.
///
/// 2.1.280 is the first release that ships `claude-opus-5-5`; Anthropic gates
/// that model on the declared version ("Claude Code 2.1.260 does not support
/// this model; version 2.1.280 or newer is required"). A binary diff of
/// 2.1.278 → 2.1.280 shows no header, beta-assembly, billing-segment or OAuth
/// change, so only the version string moves.
pub const CLAUDE_CODE_VERSION: &str = "2.1.280";

/// npm registry document for the latest Claude Code release.
pub const LATEST_VERSION_URL: &str = "https://registry.npmjs.org/@anthropic-ai/claude-code/latest";

/// How long a fetched version is trusted before it is re-fetched.
pub const VERSION_CACHE_TTL_SECS: i64 = 3_600;

/// Bound on the registry fetch.
pub const VERSION_FETCH_TIMEOUT_SECS: u64 = 5;

/// Environment variable that disables the live version check.
pub const DISABLE_VERSION_CHECK_ENV: &str = "OPENCODE_ANTHROPIC_AUTH_DISABLE_VERSION_CHECK";

/// Whether `version` is a plausible semver (`MAJOR.MINOR.PATCH[-prerelease]`,
/// at most 50 characters).
pub fn is_valid_version(version: &str) -> bool {
    if version.len() > 50 {
        return false;
    }
    let (core, pre) = match version.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (version, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3
        || parts
            .iter()
            .any(|p| p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()))
    {
        return false;
    }
    match pre {
        None => true,
        Some(pre) => {
            !pre.is_empty()
                && pre
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
        }
    }
}

fn version_parts(version: &str) -> [u64; 3] {
    let core = version.split('-').next().unwrap_or("");
    let mut parts = [0u64; 3];
    for (slot, piece) in parts.iter_mut().zip(core.split('.')) {
        *slot = piece.parse().unwrap_or(0);
    }
    parts
}

/// Numeric semver ordering on the `MAJOR.MINOR.PATCH` core; prerelease
/// suffixes are ignored, mirroring the fork's `compareVersions`.
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    version_parts(a).cmp(&version_parts(b))
}

/// A bounded cache of the live Claude Code version that never drops below
/// the verified floor.
#[derive(Debug, Clone)]
pub struct ClaudeCodeVersionTracker {
    floor: String,
    cached: Option<(String, DateTime<Utc>)>,
    ttl: Duration,
}

impl Default for ClaudeCodeVersionTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ClaudeCodeVersionTracker {
    /// A tracker floored at [`CLAUDE_CODE_VERSION`].
    pub fn new() -> Self {
        Self::with_floor(CLAUDE_CODE_VERSION)
    }

    /// A tracker floored at an explicit version (tests, or a newer verified
    /// build).
    pub fn with_floor(floor: &str) -> Self {
        Self {
            floor: floor.to_owned(),
            cached: None,
            ttl: Duration::seconds(VERSION_CACHE_TTL_SECS),
        }
    }

    /// The version request headers and the billing header should carry right
    /// now: the adopted live version, else the floor.
    pub fn current(&self) -> &str {
        self.cached
            .as_ref()
            .map_or(self.floor.as_str(), |(v, _)| v.as_str())
    }

    /// The verified floor.
    pub fn floor(&self) -> &str {
        &self.floor
    }

    /// Whether the cached live version is still inside its TTL at `now`.
    pub fn is_fresh(&self, now: DateTime<Utc>) -> bool {
        self.cached
            .as_ref()
            .is_some_and(|(_, at)| now >= *at && now - *at < self.ttl)
    }

    /// Adopt a version reported by the registry. Invalid strings are ignored;
    /// anything older than the floor is clamped to the floor. Returns the
    /// version now current.
    pub fn adopt(&mut self, candidate: &str, now: DateTime<Utc>) -> &str {
        if !is_valid_version(candidate) {
            return self.current();
        }
        let adopted = if compare_versions(candidate, &self.floor) == Ordering::Less {
            self.floor.clone()
        } else {
            candidate.to_owned()
        };
        self.cached = Some((adopted, now));
        self.current()
    }

    /// Drop the cached live version.
    pub fn reset(&mut self) {
        self.cached = None;
    }

    /// Mark the cached live version stale, ignoring the TTL, while keeping it
    /// current until a re-fetch replaces it (the fork's
    /// `refreshClaudeCodeVersion`).
    ///
    /// Used on `claude_code_version_too_old`: a model launched after this
    /// process cached its version would otherwise stay blocked for the rest
    /// of the hour. The caller re-fetches and calls [`Self::adopt`].
    pub fn invalidate(&mut self) {
        if let Some((_, at)) = self.cached.as_mut() {
            *at = DateTime::<Utc>::UNIX_EPOCH;
        }
    }
}

/// Extract `version` from the npm `latest` document.
pub fn parse_latest_version_document(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let version = value.get("version")?.as_str()?;
    is_valid_version(version).then(|| version.to_owned())
}

/// Fetch the live version from the npm registry, bounded to
/// [`VERSION_FETCH_TIMEOUT_SECS`]. Any failure yields `None`; callers keep
/// using [`ClaudeCodeVersionTracker::current`].
#[cfg(feature = "client")]
pub async fn fetch_latest_claude_code_version(http: &reqwest::Client) -> Option<String> {
    fetch_latest_claude_code_version_from(http, LATEST_VERSION_URL).await
}

/// [`fetch_latest_claude_code_version`] against an explicit URL (tests).
#[cfg(feature = "client")]
pub async fn fetch_latest_claude_code_version_from(
    http: &reqwest::Client,
    url: &str,
) -> Option<String> {
    let response = http
        .get(url)
        .timeout(std::time::Duration::from_secs(VERSION_FETCH_TIMEOUT_SECS))
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    let body = response.text().await.ok()?;
    parse_latest_version_document(&body)
}

/// Identity details for the `claude-cli/<version> (external, …)` user agent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserAgentDetails<'a> {
    /// `CLAUDE_CODE_ENTRYPOINT`; empty means `cli`.
    pub entrypoint: Option<&'a str>,
    /// `CLAUDE_AGENT_SDK_VERSION`, rendered as `agent-sdk/<v>`.
    pub sdk_version: Option<&'a str>,
    /// `CLAUDE_AGENT_SDK_CLIENT_APP`, rendered as `client-app/<app>`.
    pub client_app: Option<&'a str>,
}

/// The Claude Code user agent: `claude-cli/<version> (external, <entrypoint>
/// [, agent-sdk/<v>][, client-app/<app>])`.
pub fn claude_code_user_agent(version: &str, details: &UserAgentDetails<'_>) -> String {
    let entrypoint = details
        .entrypoint
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .unwrap_or("cli");
    let mut parts = vec![entrypoint.to_owned()];
    if let Some(sdk) = details.sdk_version.map(str::trim).filter(|s| !s.is_empty()) {
        parts.push(format!("agent-sdk/{sdk}"));
    }
    if let Some(app) = details.client_app.map(str::trim).filter(|s| !s.is_empty()) {
        parts.push(format!("client-app/{app}"));
    }
    format!("claude-cli/{version} (external, {})", parts.join(", "))
}

/// [`claude_code_user_agent`] with the details read from the process
/// environment.
pub fn claude_code_user_agent_from_env(version: &str) -> String {
    let entrypoint = std::env::var("CLAUDE_CODE_ENTRYPOINT").ok();
    let sdk = std::env::var("CLAUDE_AGENT_SDK_VERSION").ok();
    let app = std::env::var("CLAUDE_AGENT_SDK_CLIENT_APP").ok();
    claude_code_user_agent(
        version,
        &UserAgentDetails {
            entrypoint: entrypoint.as_deref(),
            sdk_version: sdk.as_deref(),
            client_app: app.as_deref(),
        },
    )
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000 + secs, 0).unwrap()
    }

    #[test]
    fn orders_numerically_and_ignores_prerelease() {
        assert_eq!(compare_versions("2.1.260", "2.1.233"), Ordering::Greater);
        assert_eq!(compare_versions("2.1.9", "2.1.10"), Ordering::Less);
        assert_eq!(compare_versions("3.0.0", "2.99.99"), Ordering::Greater);
        assert_eq!(
            compare_versions("2.1.260-beta.1", "2.1.260"),
            Ordering::Equal
        );
    }

    #[test]
    fn validates_semver_shape() {
        assert!(is_valid_version("2.1.260"));
        assert!(is_valid_version("2.1.260-rc.1"));
        assert!(!is_valid_version("2.1"));
        assert!(!is_valid_version("v2.1.260"));
        assert!(!is_valid_version("2.1.260-"));
        assert!(!is_valid_version(&"9".repeat(51)));
    }

    #[test]
    fn floor_is_at_least_2_1_251_for_fable_era_models() {
        assert!(compare_versions(CLAUDE_CODE_VERSION, "2.1.251") != Ordering::Less);
        assert_eq!(
            ClaudeCodeVersionTracker::new().current(),
            CLAUDE_CODE_VERSION
        );
    }

    #[test]
    fn adopts_newer_and_never_downgrades_below_floor() {
        let mut tracker = ClaudeCodeVersionTracker::new();
        assert_eq!(tracker.adopt("2.1.292", at(0)), "2.1.292");
        assert!(tracker.is_fresh(at(10)));
        assert!(!tracker.is_fresh(at(VERSION_CACHE_TTL_SECS + 1)));
        // A stale mirror reporting an older release is clamped to the floor.
        assert_eq!(tracker.adopt("2.1.100", at(20)), CLAUDE_CODE_VERSION);
        assert_eq!(tracker.adopt("2.1.278", at(25)), CLAUDE_CODE_VERSION);
        // Garbage is ignored and leaves the current value alone.
        tracker.adopt("2.1.300", at(30));
        assert_eq!(tracker.adopt("not-a-version", at(40)), "2.1.300");
        tracker.reset();
        assert_eq!(tracker.current(), CLAUDE_CODE_VERSION);
    }

    #[test]
    fn floor_is_2_1_280_for_opus_5_5() {
        assert_eq!(CLAUDE_CODE_VERSION, "2.1.280");
        assert_eq!(
            claude_code_user_agent(CLAUDE_CODE_VERSION, &UserAgentDetails::default()),
            "claude-cli/2.1.280 (external, cli)"
        );
    }

    #[test]
    fn invalidate_forces_a_refresh_but_keeps_the_version() {
        let mut tracker = ClaudeCodeVersionTracker::new();
        // Invalidating an empty tracker is a no-op.
        tracker.invalidate();
        assert!(!tracker.is_fresh(at(0)));
        assert_eq!(tracker.current(), CLAUDE_CODE_VERSION);
        tracker.adopt("2.1.290", at(0));
        assert!(tracker.is_fresh(at(1)));
        tracker.invalidate();
        assert!(!tracker.is_fresh(at(1)));
        assert_eq!(tracker.current(), "2.1.290");
        assert_eq!(tracker.adopt("2.1.291", at(2)), "2.1.291");
        assert!(tracker.is_fresh(at(3)));
    }

    #[test]
    fn parses_registry_document() {
        assert_eq!(
            parse_latest_version_document(
                r#"{"name":"@anthropic-ai/claude-code","version":"2.1.272"}"#
            )
            .as_deref(),
            Some("2.1.272")
        );
        assert_eq!(parse_latest_version_document(r#"{"version":"nope"}"#), None);
        assert_eq!(parse_latest_version_document("{"), None);
    }

    #[test]
    fn user_agent_matches_claude_cli_shape() {
        assert_eq!(
            claude_code_user_agent("2.1.260", &UserAgentDetails::default()),
            "claude-cli/2.1.260 (external, cli)"
        );
        assert_eq!(
            claude_code_user_agent(
                "2.1.260",
                &UserAgentDetails {
                    entrypoint: Some("sdk-ts"),
                    sdk_version: Some("0.1.2"),
                    client_app: Some("acme"),
                }
            ),
            "claude-cli/2.1.260 (external, sdk-ts, agent-sdk/0.1.2, client-app/acme)"
        );
        assert_eq!(
            claude_code_user_agent(
                "2.1.260",
                &UserAgentDetails {
                    entrypoint: Some("  "),
                    ..Default::default()
                }
            ),
            "claude-cli/2.1.260 (external, cli)"
        );
    }
}
