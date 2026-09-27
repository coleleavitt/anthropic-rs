//! Sticky-balanced session routing: assign each session to a quota-weighted
//! OAuth account and keep it there across transient failures, migrating only
//! on confirmed long-lived exhaustion, an explicit exclusion, or a **model
//! change**.
//!
//! Ported from anthropic-auth `sticky-routing.ts` (upstream `b504bc8`),
//! including 5a8fabf "reset sticky affinity on model change": an assignment
//! records the model it was chosen for (`affinityModelId`), and a request for
//! a different model re-selects instead of inheriting an account picked for
//! another model's scoped quota. A caller may pin affinity to the
//! user-selected model (`affinity_model_id`) so an internal recovery model
//! (e.g. a refusal fallback) does not move the session.
//!
//! Session ids are persisted only as SHA-256 digests. The state file is
//! written atomically, `0600`, and never followed through a symlink.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::killswitch::{KillswitchConfig, killswitch_retry_after_secs};
use crate::quota::{QuotaPolicy, QuotaSnapshot, QuotaWindowName, parse_iso_ms};

/// Candidate id conventionally used for the "main" account.
pub const STICKY_ROUTING_MAIN_ACCOUNT_ID: &str = "main";
/// A five-hour exhaustion that resets within this window is held, not migrated.
pub const STICKY_ROUTING_SHORT_RESET_GRACE_MS: i64 = 15 * 60_000;
/// Assignments idle longer than this expire.
pub const STICKY_ROUTING_ASSIGNMENT_TTL_MS: i64 = 7 * 24 * 60 * 60_000;
/// Minimum interval between `lastSeenAt` touches of a cached assignment.
pub const STICKY_ROUTING_TOUCH_INTERVAL_MS: i64 = 60 * 60_000;
/// Assignment cap; the least recently seen are pruned first.
pub const STICKY_ROUTING_MAX_ASSIGNMENTS: usize = 4_096;
#[cfg(feature = "store")]
const MIN_WEIGHT: f64 = 0.000_001;

/// Which quota pool a model draws on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StickyRouteFamily {
    /// Fable / Mythos 5 (model-scoped weekly window).
    Fable,
    /// Any Opus model.
    Opus,
    /// Everything else.
    General,
}

/// The family for `model`.
pub fn sticky_route_family_for_model(model: &str) -> StickyRouteFamily {
    if crate::models::is_claude_fable_or_mythos_5_model(model) {
        StickyRouteFamily::Fable
    } else if model.to_lowercase().contains("opus") {
        StickyRouteFamily::Opus
    } else {
        StickyRouteFamily::General
    }
}

/// An account the router may assign. `quota: None` is an *unknown* quota —
/// a retained route, not an absent one.
#[derive(Debug, Clone, PartialEq)]
pub struct StickyRouteCandidate {
    /// Account id.
    pub account_id: String,
    /// Known quota, or `None` when unknown.
    pub quota: Option<QuotaSnapshot>,
    /// Configured order (lower first) for tie-breaks and cold fallbacks.
    pub order: i64,
}

/// A persisted session → account assignment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StickyRouteAssignment {
    /// Assigned account.
    pub account_id: String,
    /// Family at assignment time.
    pub family: StickyRouteFamily,
    /// Model the assignment was chosen for. Legacy assignments without it
    /// are re-selected on the next model-scoped request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affinity_model_id: Option<String>,
    /// When assigned, epoch ms.
    pub assigned_at: i64,
    /// Last use, epoch ms.
    pub last_seen_at: i64,
    /// Input size of the first request (load estimate).
    pub initial_input_bytes: f64,
    /// `checked_at_max` of the quota the choice was based on.
    pub quota_checked_at: i64,
}

/// Outcome of [`StickySessionRouter::resolve`].
#[derive(Debug, Clone, PartialEq)]
pub struct StickyRouteResolution {
    /// Account to use.
    pub account_id: String,
    /// The assignment now on record.
    pub assignment: StickyRouteAssignment,
    /// No assignment existed before.
    pub created: bool,
    /// The session moved to a different account.
    pub migrated: bool,
}

/// Quota inputs for routing: the quota policy plus the optional killswitch.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct StickyPolicy {
    /// Minimum-remaining and freshness policy.
    pub quota: QuotaPolicy,
    /// Killswitch; its thresholds raise the reserve when enabled.
    pub killswitch: Option<KillswitchConfig>,
}

impl StickyPolicy {
    fn reserve(&self, account_id: &str, window: ReserveWindow) -> f64 {
        let quota = match window {
            ReserveWindow::Standard(name) => self.quota.minimum_remaining(name),
            ReserveWindow::Scoped => 0.0,
        };
        let Some(killswitch) = self.killswitch.as_ref().filter(|k| k.enabled) else {
            return quota;
        };
        let account = (account_id != STICKY_ROUTING_MAIN_ACCOUNT_ID).then_some(account_id);
        let thresholds = killswitch.thresholds_for(account);
        let kill = match window {
            ReserveWindow::Standard(name) => thresholds.window(name),
            ReserveWindow::Scoped => thresholds.scoped,
        };
        quota.max(kill)
    }
}

#[derive(Clone, Copy)]
enum ReserveWindow {
    Standard(QuotaWindowName),
    Scoped,
}

/// Fresh enough to route on: both standard windows, and the scoped window
/// for `model` when present, observed within the quota interval. Applies even
/// when general quota gating is disabled.
pub fn sticky_quota_snapshot_is_fresh(
    quota: Option<&QuotaSnapshot>,
    policy: &QuotaPolicy,
    now: i64,
    model: Option<&str>,
) -> bool {
    let max_age = policy.interval_ms();
    let Some(quota) = quota else {
        return false;
    };
    let standard = QuotaWindowName::ALL.iter().all(|name| {
        quota
            .window(*name)
            .is_some_and(|w| now - w.checked_at < max_age)
    });
    standard
        && quota
            .scoped_window_for_model(model)
            .is_none_or(|w| now - w.checked_at < max_age)
}

fn sustainable_window_weight(
    remaining: f64,
    reserve: f64,
    resets_at: Option<&str>,
    now: i64,
) -> f64 {
    let spendable = (remaining - reserve).max(0.0);
    if spendable <= 0.0 {
        return 0.0;
    }
    match resets_at.and_then(parse_iso_ms) {
        Some(reset) if reset > now => {
            let hours = ((reset - now) as f64 / 3_600_000.0).max(1.0 / 60.0);
            spendable / hours
        }
        _ => spendable,
    }
}

/// Quota-weighted desirability of `candidate` (0 = not routable): the
/// minimum over windows of spendable-percent per hour until reset.
pub fn sticky_route_candidate_weight(
    candidate: &StickyRouteCandidate,
    family: StickyRouteFamily,
    model: Option<&str>,
    policy: &StickyPolicy,
    now: i64,
) -> f64 {
    let Some(quota) = candidate.quota.as_ref() else {
        return 0.0;
    };
    if !sticky_quota_snapshot_is_fresh(Some(quota), &policy.quota, now, model) {
        return 0.0;
    }
    let mut weights = Vec::with_capacity(3);
    for name in QuotaWindowName::ALL {
        let Some(window) = quota
            .window(name)
            .filter(|w| w.remaining_percent.is_finite())
        else {
            return 0.0;
        };
        weights.push(sustainable_window_weight(
            window.remaining_percent,
            policy.reserve(&candidate.account_id, ReserveWindow::Standard(name)),
            window.resets_at.as_deref(),
            now,
        ));
    }
    if family == StickyRouteFamily::Fable
        && let Some(window) = quota
            .scoped_window_for_model(model)
            .filter(|w| w.remaining_percent.is_finite())
    {
        weights.push(sustainable_window_weight(
            window.remaining_percent,
            policy.reserve(&candidate.account_id, ReserveWindow::Scoped),
            window.resets_at.as_deref(),
            now,
        ));
    }
    weights.into_iter().fold(f64::INFINITY, f64::min)
}

/// A fresh quota reading says this candidate's Fable window is exhausted.
pub fn sticky_route_known_fable_exhausted(
    candidate: &StickyRouteCandidate,
    policy: &QuotaPolicy,
    now: i64,
) -> bool {
    const FABLE: Option<&str> = Some("claude-fable-5");
    let Some(quota) = candidate.quota.as_ref() else {
        return false;
    };
    quota.scoped_window_for_model(FABLE).is_some_and(|w| {
        sticky_quota_snapshot_is_fresh(Some(quota), policy, now, FABLE)
            && w.remaining_percent.is_finite()
            && w.remaining_percent <= 0.0
    })
}

/// Why a retained route stays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StickyRetainReason {
    /// Nothing is exhausted.
    NotExhausted,
    /// Quota is unknown.
    Unknown,
}

/// Which exhaustion forces migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StickyMigrateReason {
    /// Five-hour window, reset not imminent.
    FiveHour,
    /// Seven-day window.
    SevenDay,
    /// The model's scoped weekly window.
    ModelScoped,
}

/// What to do with a sticky route that just failed on quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StickyQuotaFailureDecision {
    /// Keep the route.
    Retain(StickyRetainReason),
    /// Five-hour exhaustion resetting within the grace window: wait.
    Hold {
        /// Seconds until the reset.
        retry_after_secs: u64,
    },
    /// Move the session.
    Migrate(StickyMigrateReason),
}

/// Decide what a quota failure on a sticky route means.
pub fn decide_sticky_quota_failure(
    quota: Option<&QuotaSnapshot>,
    model: Option<&str>,
    now: i64,
) -> StickyQuotaFailureDecision {
    let Some(quota) = quota else {
        return StickyQuotaFailureDecision::Retain(StickyRetainReason::Unknown);
    };
    let exhausted = |remaining: f64| remaining.is_finite() && remaining <= 0.0;
    if quota
        .scoped_window_for_model(model)
        .is_some_and(|w| exhausted(w.remaining_percent))
    {
        return StickyQuotaFailureDecision::Migrate(StickyMigrateReason::ModelScoped);
    }
    if quota
        .seven_day
        .as_ref()
        .is_some_and(|w| exhausted(w.remaining_percent))
    {
        return StickyQuotaFailureDecision::Migrate(StickyMigrateReason::SevenDay);
    }
    if let Some(five) = quota
        .five_hour
        .as_ref()
        .filter(|w| exhausted(w.remaining_percent))
    {
        if let Some(reset) = five.resets_at.as_deref().and_then(parse_iso_ms)
            && reset > now
            && reset - now <= STICKY_ROUTING_SHORT_RESET_GRACE_MS
        {
            return StickyQuotaFailureDecision::Hold {
                retry_after_secs: (((reset - now) as f64) / 1000.0).ceil().max(1.0) as u64,
            };
        }
        return StickyQuotaFailureDecision::Migrate(StickyMigrateReason::FiveHour);
    }
    StickyQuotaFailureDecision::Retain(StickyRetainReason::NotExhausted)
}

/// `retry_after` plus 0–20 s of jitter derived deterministically from the
/// session id, so every session of a pool does not retry in the same second.
pub fn sticky_retry_after_with_jitter(session_id: &str, retry_after_secs: f64) -> u64 {
    let digest = sha2::Sha256::digest(session_id.as_bytes());
    let hash = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    (retry_after_secs.ceil().max(1.0) as u64) + u64::from(hash % 21)
}

/// The terminal answer when a complete sticky pool has no eligible route —
/// returned instead of silently falling through to an account the router
/// deliberately excluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StickyNoRoute {
    /// 401 for an authentication cause, 429 otherwise.
    pub status: u16,
    /// Anthropic error type (`authentication_error` / `rate_limit_error`).
    pub error_type: &'static str,
    /// User-facing message (no credential material).
    pub message: String,
    /// `retry-after` seconds for a 429.
    pub retry_after_secs: Option<u64>,
}

impl StickyNoRoute {
    /// The Anthropic-shaped JSON error body.
    pub fn body(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "error",
            "error": { "type": self.error_type, "message": self.message }
        })
    }
}

/// Build the no-route answer. `main_needs_relogin` is
/// [`crate::backoff::is_permanent_refresh_error`] of the main account's
/// refresh record; `reauth_labels` names fallback accounts needing re-login.
pub fn sticky_no_route(
    main_needs_relogin: bool,
    reauth_labels: &[String],
    route_quotas: &[QuotaSnapshot],
    model: Option<&str>,
    now: i64,
) -> StickyNoRoute {
    let model_name = model.and_then(|m| {
        route_quotas
            .iter()
            .find_map(|q| q.scoped_window_for_model(Some(m)))
            .map(|w| w.model_name.clone())
    });
    let auth_message = if main_needs_relogin {
        Some(match &model_name {
            Some(name) => format!(
                "Main Claude OAuth account requires re-login, and no fallback OAuth account is currently routable for {name}."
            ),
            None => "Main Claude OAuth account requires re-login, and no fallback OAuth account is currently routable."
                .to_owned(),
        })
    } else if !reauth_labels.is_empty() {
        let scope = model_name
            .as_ref()
            .map(|n| format!(" for {n}"))
            .unwrap_or_default();
        Some(format!(
            "No OAuth account is currently routable{scope}. Fallback Claude OAuth accounts require re-login: {}.",
            reauth_labels.join(", ")
        ))
    } else {
        None
    };
    if let Some(message) = auth_message {
        return StickyNoRoute {
            status: 401,
            error_type: "authentication_error",
            message,
            retry_after_secs: None,
        };
    }
    let scoped_blocked = model.is_some()
        && !route_quotas.is_empty()
        && route_quotas
            .iter()
            .all(|q| q.model_scope_is_exhausted(model));
    let retry_after = killswitch_retry_after_secs(
        route_quotas.iter().map(Some),
        now,
        if scoped_blocked { model } else { None },
    );
    let reason = match (&model_name, scoped_blocked) {
        (Some(name), true) => format!("{name} weekly limit reached, no routable OAuth accounts."),
        _ => "No OAuth account currently satisfies sticky-balanced quota policy.".to_owned(),
    };
    StickyNoRoute {
        status: 429,
        error_type: "rate_limit_error",
        message: format!(
            "{reason} Retry in {}m {}s.",
            retry_after / 60,
            retry_after % 60
        ),
        retry_after_secs: Some(retry_after),
    }
}

/// Routing mode (anthropic-auth `routing.ts`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RoutingMode {
    /// Main account first; fallbacks only when policy or errors require.
    #[default]
    MainFirst,
    /// Usable fallbacks before the main account.
    FallbackFirst,
    /// Quota-weighted sticky assignment per session.
    StickyBalanced,
}

impl RoutingMode {
    /// Parse a mode name; unknown values yield `None`.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "main-first" => Some(Self::MainFirst),
            "fallback-first" => Some(Self::FallbackFirst),
            "sticky-balanced" => Some(Self::StickyBalanced),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Arguments to [`StickySessionRouter::resolve`].
#[derive(Debug, Clone, Copy)]
pub struct StickyResolveRequest<'a> {
    /// Host session id (hashed before persistence). Empty → no routing.
    pub session_id: &'a str,
    /// Family of the requested model.
    pub family: StickyRouteFamily,
    /// Requested model.
    pub model_id: Option<&'a str>,
    /// Model affinity is keyed on; defaults to `model_id`. Pass the
    /// user-selected model to keep an internal recovery model from moving
    /// the session.
    pub affinity_model_id: Option<&'a str>,
    /// Routable candidates.
    pub candidates: &'a [StickyRouteCandidate],
    /// Accounts an existing assignment may stay on.
    pub retain_account_ids: &'a HashSet<String>,
    /// Quota inputs.
    pub policy: &'a StickyPolicy,
    /// Request size (load estimate).
    pub input_bytes: u64,
    /// Seed a cold session onto this account when it is eligible.
    pub preferred_account_id: Option<&'a str>,
    /// Never assign to these.
    pub exclude_account_ids: Option<&'a HashSet<String>>,
}

#[cfg(feature = "store")]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StickyRouteState {
    version: u8,
    updated_at: i64,
    assignments: std::collections::BTreeMap<String, StickyRouteAssignment>,
}

#[cfg(feature = "store")]
impl StickyRouteState {
    fn empty(now: i64) -> Self {
        Self {
            version: 1,
            updated_at: now,
            assignments: std::collections::BTreeMap::new(),
        }
    }
}

#[cfg(feature = "store")]
fn session_key(session_id: &str) -> String {
    sha2::Sha256::digest(session_id.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `<stem>-routing-state.json` beside the account store.
pub fn sticky_routing_state_path(account_store_path: &std::path::Path) -> std::path::PathBuf {
    let name = account_store_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("accounts.json");
    let stem = name.strip_suffix(".json").unwrap_or(name);
    account_store_path.with_file_name(format!("{stem}-routing-state.json"))
}

/// File-backed sticky router shared by every process on the machine.
#[cfg(feature = "store")]
#[derive(Debug)]
pub struct StickySessionRouter {
    path: std::path::PathBuf,
    assignment_ttl_ms: i64,
}

#[cfg(feature = "store")]
const STATE_MAX_BYTES: u64 = 16 * 1024 * 1024;

#[cfg(feature = "store")]
struct RouterLock(std::fs::File);

#[cfg(feature = "store")]
impl Drop for RouterLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.0);
    }
}

#[cfg(feature = "store")]
impl StickySessionRouter {
    /// A router persisting at `path` (see [`sticky_routing_state_path`]).
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            path: path.into(),
            assignment_ttl_ms: STICKY_ROUTING_ASSIGNMENT_TTL_MS,
        }
    }

    /// Override the idle expiry.
    pub fn with_assignment_ttl_ms(mut self, ttl_ms: i64) -> Self {
        self.assignment_ttl_ms = ttl_ms;
        self
    }

    fn lock(&self) -> crate::Result<RouterLock> {
        use crate::error::Error;
        let name = self
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("routing-state.json");
        let lock_path = self.path.with_file_name(format!("{name}.flock"));
        if let Some(parent) = lock_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if std::fs::symlink_metadata(&lock_path).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(Error::StoreIsSymlink);
        }
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&lock_path)?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match fs2::FileExt::try_lock_exclusive(&file) {
                Ok(()) => return Ok(RouterLock(file)),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        return Err(Error::Protocol(
                            "timed out acquiring sticky routing state lock".into(),
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn read_state(&self, now: i64) -> crate::Result<StickyRouteState> {
        use crate::error::Error;
        let bytes = match crate::file_security::read_bounded_regular(
            &self.path,
            STATE_MAX_BYTES,
            false,
            "sticky routing state",
        ) {
            Ok(bytes) => bytes,
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(StickyRouteState::empty(now));
            }
            Err(error) => return Err(error),
        };
        let value: serde_json::Value =
            crate::file_security::parse_json_redacted(&bytes, "sticky routing state")?;
        let invalid = || Error::Protocol("invalid sticky routing state".into());
        if value.get("version").and_then(serde_json::Value::as_u64) != Some(1) {
            return Err(invalid());
        }
        let Some(raw) = value
            .get("assignments")
            .and_then(serde_json::Value::as_object)
        else {
            return Err(invalid());
        };
        // Tolerant per entry: one malformed assignment must not strand the rest.
        let assignments = raw
            .iter()
            .filter_map(|(key, assignment)| {
                serde_json::from_value::<StickyRouteAssignment>(assignment.clone())
                    .ok()
                    .map(|mut a| {
                        a.initial_input_bytes = a.initial_input_bytes.max(0.0);
                        (key.clone(), a)
                    })
            })
            .collect();
        Ok(StickyRouteState {
            version: 1,
            updated_at: value
                .get("updatedAt")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0),
            assignments,
        })
    }

    fn prune(&self, state: &mut StickyRouteState, now: i64) {
        let cutoff = now - self.assignment_ttl_ms;
        state.assignments.retain(|_, a| a.last_seen_at >= cutoff);
        if state.assignments.len() <= STICKY_ROUTING_MAX_ASSIGNMENTS {
            return;
        }
        let mut by_recency: Vec<(String, i64)> = state
            .assignments
            .iter()
            .map(|(k, a)| (k.clone(), a.last_seen_at))
            .collect();
        by_recency.sort_by_key(|entry| std::cmp::Reverse(entry.1));
        for (key, _) in by_recency.into_iter().skip(STICKY_ROUTING_MAX_ASSIGNMENTS) {
            state.assignments.remove(&key);
        }
    }

    fn write_state(&self, state: &mut StickyRouteState, now: i64) -> crate::Result<()> {
        self.prune(state, now);
        state.version = 1;
        state.updated_at = now;
        let mut body = serde_json::to_vec(state)?;
        body.push(b'\n');
        crate::file_security::write_private_atomic(&self.path, &body)
    }

    fn matches_affinity(
        assignment: &StickyRouteAssignment,
        request: &StickyResolveRequest<'_>,
    ) -> bool {
        match request.affinity_model_id.or(request.model_id) {
            Some(model) => assignment.affinity_model_id.as_deref() == Some(model),
            None => assignment.family == request.family,
        }
    }

    fn retainable(assignment: &StickyRouteAssignment, request: &StickyResolveRequest<'_>) -> bool {
        Self::matches_affinity(assignment, request)
            && request.retain_account_ids.contains(&assignment.account_id)
            && !request
                .exclude_account_ids
                .is_some_and(|ex| ex.contains(&assignment.account_id))
    }

    fn select<'c>(
        state: &StickyRouteState,
        candidates: &[&'c StickyRouteCandidate],
        request: &StickyResolveRequest<'_>,
        now: i64,
    ) -> Option<&'c StickyRouteCandidate> {
        let mut pool: Vec<&StickyRouteCandidate> = candidates.to_vec();
        if request.family == StickyRouteFamily::Opus {
            let depleted: Vec<_> = pool
                .iter()
                .copied()
                .filter(|c| sticky_route_known_fable_exhausted(c, &request.policy.quota, now))
                .collect();
            if !depleted.is_empty() {
                pool = depleted;
            }
        }
        let weighted: Vec<(&StickyRouteCandidate, f64)> = pool
            .iter()
            .map(|c| {
                (
                    *c,
                    sticky_route_candidate_weight(
                        c,
                        request.family,
                        request.model_id,
                        request.policy,
                        now,
                    ),
                )
            })
            .filter(|(_, w)| *w > 0.0)
            .collect();
        if weighted.is_empty() && pool.iter().all(|c| c.quota.is_none()) {
            return pool.iter().copied().min_by(|a, b| {
                a.order
                    .cmp(&b.order)
                    .then_with(|| a.account_id.cmp(&b.account_id))
            });
        }
        let mut pending: std::collections::HashMap<&str, f64> = std::collections::HashMap::new();
        for assignment in state.assignments.values() {
            let Some((candidate, _)) = weighted
                .iter()
                .find(|(c, _)| c.account_id == assignment.account_id)
            else {
                continue;
            };
            if let Some(quota) = &candidate.quota
                && assignment.quota_checked_at != quota.checked_at_max()
            {
                continue;
            }
            *pending.entry(candidate.account_id.as_str()).or_default() +=
                assignment.initial_input_bytes;
        }
        weighted
            .into_iter()
            .map(|(c, w)| {
                let load = pending.get(c.account_id.as_str()).copied().unwrap_or(0.0)
                    + request.input_bytes as f64;
                (c, load / w.max(MIN_WEIGHT))
            })
            .min_by(|(a, sa), (b, sb)| {
                sa.total_cmp(sb)
                    .then_with(|| a.order.cmp(&b.order))
                    .then_with(|| a.account_id.cmp(&b.account_id))
            })
            .map(|(c, _)| c)
    }

    /// Resolve the account for a session at `now` (epoch ms). `Ok(None)`
    /// means no route: the caller must answer with [`sticky_no_route`]
    /// rather than falling through to an excluded account.
    pub fn resolve(
        &self,
        request: &StickyResolveRequest<'_>,
        now: i64,
    ) -> crate::Result<Option<StickyRouteResolution>> {
        if request.session_id.is_empty() {
            return Ok(None);
        }
        let key = session_key(request.session_id);
        let _lock = self.lock()?;
        let mut state = self.read_state(now)?;
        self.prune(&mut state, now);
        let current = state.assignments.get(&key).cloned();

        if let Some(mut current) = current.clone().filter(|c| Self::retainable(c, request)) {
            if now - current.last_seen_at >= STICKY_ROUTING_TOUCH_INTERVAL_MS
                || current.last_seen_at > now
            {
                current.last_seen_at = now;
                state.assignments.insert(key, current.clone());
                self.write_state(&mut state, now)?;
            }
            return Ok(Some(StickyRouteResolution {
                account_id: current.account_id.clone(),
                assignment: current,
                created: false,
                migrated: false,
            }));
        }

        let affinity_changed = current
            .as_ref()
            .is_some_and(|c| !Self::matches_affinity(c, request));
        if affinity_changed {
            state.assignments.remove(&key);
        }
        let candidates: Vec<&StickyRouteCandidate> = request
            .candidates
            .iter()
            .filter(|c| {
                !request
                    .exclude_account_ids
                    .is_some_and(|ex| ex.contains(&c.account_id))
            })
            .collect();
        let preferred = (!affinity_changed)
            .then_some(request.preferred_account_id)
            .flatten()
            .and_then(|id| {
                candidates.iter().copied().find(|c| {
                    c.account_id == id
                        && sticky_route_candidate_weight(
                            c,
                            request.family,
                            request.model_id,
                            request.policy,
                            now,
                        ) > 0.0
                })
            });
        let Some(selected) = preferred.or_else(|| Self::select(&state, &candidates, request, now))
        else {
            if current.is_some() {
                state.assignments.remove(&key);
                self.write_state(&mut state, now)?;
            }
            return Ok(None);
        };
        let assignment = StickyRouteAssignment {
            account_id: selected.account_id.clone(),
            family: request.family,
            affinity_model_id: request
                .affinity_model_id
                .or(request.model_id)
                .map(str::to_owned),
            assigned_at: now,
            last_seen_at: now,
            initial_input_bytes: request.input_bytes.max(1) as f64,
            quota_checked_at: selected
                .quota
                .as_ref()
                .map_or(0, QuotaSnapshot::checked_at_max),
        };
        state.assignments.insert(key, assignment.clone());
        self.write_state(&mut state, now)?;
        Ok(Some(StickyRouteResolution {
            account_id: selected.account_id.clone(),
            migrated: current
                .as_ref()
                .is_some_and(|c| c.account_id != selected.account_id),
            created: current.is_none(),
            assignment,
        }))
    }

    /// Forget a session's assignment (`/claude-routing reset`).
    pub fn clear(&self, session_id: &str, now: i64) -> crate::Result<()> {
        if session_id.is_empty() {
            return Ok(());
        }
        let key = session_key(session_id);
        let _lock = self.lock()?;
        let mut state = self.read_state(now)?;
        if state.assignments.remove(&key).is_some() {
            self.write_state(&mut state, now)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! Ports of opencode `sticky-routing.test.ts`.
    use super::*;
    use crate::quota::{QuotaWindow, ScopedQuotaWindow};

    // 2026-07-18T08:00:00Z
    const NOW: i64 = 1_784_361_600_000;

    fn iso(ms: i64) -> Option<String> {
        chrono::DateTime::from_timestamp_millis(ms)
            .map(|d| d.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
    }

    fn candidate(
        id: &str,
        order: i64,
        five: f64,
        seven: f64,
        fable: f64,
        reset_hours: f64,
    ) -> StickyRouteCandidate {
        let checked_at = NOW - 1_000;
        let resets_at = iso(NOW + (reset_hours * 3_600_000.0) as i64);
        StickyRouteCandidate {
            account_id: id.into(),
            order,
            quota: Some(QuotaSnapshot {
                checked_at: Some(checked_at),
                five_hour: Some(QuotaWindow {
                    used_percent: 100.0 - five,
                    remaining_percent: five,
                    resets_at: iso(NOW + 3 * 3_600_000),
                    checked_at,
                }),
                seven_day: Some(QuotaWindow {
                    used_percent: 100.0 - seven,
                    remaining_percent: seven,
                    resets_at: resets_at.clone(),
                    checked_at,
                }),
                scoped: Some(vec![ScopedQuotaWindow {
                    id: "claude-weekly-scoped-fable".into(),
                    title: "Fable only".into(),
                    model_id: None,
                    model_name: "Fable".into(),
                    used_percent: 100.0 - fable,
                    remaining_percent: fable,
                    resets_at,
                    checked_at,
                }]),
                ..Default::default()
            }),
        }
    }

    fn policy() -> StickyPolicy {
        StickyPolicy {
            quota: QuotaPolicy {
                minimum_remaining_five_hour: 1.0,
                minimum_remaining_seven_day: 1.0,
                ..QuotaPolicy::default()
            },
            killswitch: None,
        }
    }

    #[cfg(feature = "store")]
    fn router() -> (StickySessionRouter, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("sticky-routing-{}", uuid::Uuid::new_v4()));
        let path = sticky_routing_state_path(&dir.join("anthropic-auth.json"));
        (StickySessionRouter::new(&path), dir)
    }

    #[cfg(feature = "store")]
    fn ids(values: &[&str]) -> HashSet<String> {
        values.iter().map(|v| (*v).to_owned()).collect()
    }

    #[cfg(feature = "store")]
    fn request<'a>(
        session: &'a str,
        family: StickyRouteFamily,
        model: &'a str,
        candidates: &'a [StickyRouteCandidate],
        retain: &'a HashSet<String>,
        policy: &'a StickyPolicy,
        input_bytes: u64,
    ) -> StickyResolveRequest<'a> {
        StickyResolveRequest {
            session_id: session,
            family,
            model_id: Some(model),
            affinity_model_id: None,
            candidates,
            retain_account_ids: retain,
            policy,
            input_bytes,
            preferred_account_id: None,
            exclude_account_ids: None,
        }
    }

    #[test]
    fn weights_fable_accounts_by_spendable_quota_and_time_to_reset() {
        let policy = policy();
        let scarce = candidate("yiyi", 1, 97.0, 51.0, 13.0, 132.0);
        let abundant = candidate("ufuk2", 2, 100.0, 99.0, 98.0, 91.0);
        let fable = Some("claude-fable-5");
        let scarce_w =
            sticky_route_candidate_weight(&scarce, StickyRouteFamily::Fable, fable, &policy, NOW);
        let abundant_w =
            sticky_route_candidate_weight(&abundant, StickyRouteFamily::Fable, fable, &policy, NOW);
        assert!(abundant_w > scarce_w * 10.0, "{abundant_w} vs {scarce_w}");
    }

    #[test]
    fn freshness_applies_even_when_quota_gating_is_disabled() {
        let disabled = QuotaPolicy {
            enabled: false,
            ..QuotaPolicy::default()
        };
        let mut stale = candidate("main", 0, 100.0, 100.0, 100.0, 96.0)
            .quota
            .unwrap();
        stale.five_hour.as_mut().unwrap().checked_at = NOW - 6 * 60_000;
        stale.seven_day.as_mut().unwrap().checked_at = NOW - 6 * 60_000;
        assert!(!sticky_quota_snapshot_is_fresh(
            Some(&stale),
            &disabled,
            NOW,
            None
        ));
        let mut stale_scoped = candidate("main", 0, 100.0, 100.0, 0.0, 96.0).quota.unwrap();
        stale_scoped.scoped.as_mut().unwrap()[0].checked_at = NOW - 6 * 60_000;
        assert!(!sticky_quota_snapshot_is_fresh(
            Some(&stale_scoped),
            &policy().quota,
            NOW,
            Some("claude-fable-5")
        ));
    }

    #[cfg(feature = "store")]
    #[test]
    fn distributes_cold_fable_sessions_proportionally() {
        let (router, dir) = router();
        let policy = policy();
        let candidates = [
            candidate("yiyi", 0, 97.0, 51.0, 13.0, 132.0),
            candidate("ufuk2", 1, 100.0, 99.0, 98.0, 91.0),
        ];
        let retain = ids(&["yiyi", "ufuk2"]);
        let mut counts = std::collections::HashMap::new();
        for index in 0..12 {
            let session = format!("cold-session-{index}");
            let resolved = router
                .resolve(
                    &request(
                        &session,
                        StickyRouteFamily::Fable,
                        "claude-fable-5",
                        &candidates,
                        &retain,
                        &policy,
                        1_000_000,
                    ),
                    NOW,
                )
                .unwrap()
                .unwrap();
            *counts.entry(resolved.account_id).or_insert(0) += 1;
        }
        assert_eq!(counts.get("yiyi"), Some(&1));
        assert_eq!(counts.get("ufuk2"), Some(&11));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(feature = "store")]
    #[test]
    fn persists_an_assignment_hashed_and_keeps_it_sticky_when_weights_change() {
        let (router, dir) = router();
        let policy = policy();
        let retain = ids(&["scarce", "abundant"]);
        let first_pool = [
            candidate("scarce", 0, 90.0, 40.0, 10.0, 96.0),
            candidate("abundant", 1, 100.0, 99.0, 98.0, 96.0),
        ];
        let first = router
            .resolve(
                &request(
                    "session-1",
                    StickyRouteFamily::Fable,
                    "claude-fable-5",
                    &first_pool,
                    &retain,
                    &policy,
                    1_000_000,
                ),
                NOW,
            )
            .unwrap()
            .unwrap();
        assert_eq!(first.account_id, "abundant");
        assert!(first.created);
        let persisted = std::fs::read_to_string(&router.path).unwrap();
        assert!(!persisted.contains("session-1"));
        assert!(persisted.contains("abundant"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&router.path)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        let reloaded = StickySessionRouter::new(&router.path);
        let flipped = [
            candidate("scarce", 0, 100.0, 100.0, 100.0, 96.0),
            candidate("abundant", 1, 10.0, 10.0, 10.0, 96.0),
        ];
        let second = reloaded
            .resolve(
                &request(
                    "session-1",
                    StickyRouteFamily::Fable,
                    "claude-fable-5",
                    &flipped,
                    &retain,
                    &policy,
                    10,
                ),
                NOW + 1_000,
            )
            .unwrap()
            .unwrap();
        assert_eq!(second.account_id, "abundant");
        assert!(!second.created && !second.migrated);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(feature = "store")]
    #[test]
    fn reselects_on_a_model_change_across_and_within_families() {
        let (router, dir) = router();
        let policy = policy();
        let pool = [
            candidate("fable-depleted", 0, 100.0, 100.0, 0.0, 96.0),
            candidate("fable-rich", 1, 100.0, 100.0, 100.0, 96.0),
        ];
        let retain = ids(&["fable-depleted", "fable-rich"]);
        let fable = router
            .resolve(
                &request(
                    "model-change",
                    StickyRouteFamily::Fable,
                    "claude-fable-5-1",
                    &pool,
                    &retain,
                    &policy,
                    10_000,
                ),
                NOW,
            )
            .unwrap()
            .unwrap();
        assert_eq!(fable.account_id, "fable-rich");
        let opus = router
            .resolve(
                &request(
                    "model-change",
                    StickyRouteFamily::Opus,
                    "claude-opus-5",
                    &pool,
                    &retain,
                    &policy,
                    10_000,
                ),
                NOW,
            )
            .unwrap()
            .unwrap();
        assert_eq!(opus.account_id, "fable-depleted");
        assert!(opus.migrated);
        assert_eq!(
            opus.assignment.affinity_model_id.as_deref(),
            Some("claude-opus-5")
        );

        // Same family, different model: re-select on current quota.
        let first_pool = [
            candidate("first", 0, 100.0, 100.0, 100.0, 96.0),
            candidate("second", 1, 100.0, 100.0, 0.0, 96.0),
        ];
        let retain2 = ids(&["first", "second"]);
        let first = router
            .resolve(
                &request(
                    "same-family",
                    StickyRouteFamily::Fable,
                    "claude-fable-5",
                    &first_pool,
                    &retain2,
                    &policy,
                    10_000,
                ),
                NOW,
            )
            .unwrap()
            .unwrap();
        assert_eq!(first.account_id, "first");
        let second_pool = [
            candidate("first", 0, 100.0, 100.0, 0.0, 96.0),
            candidate("second", 1, 100.0, 100.0, 100.0, 96.0),
        ];
        let changed = router
            .resolve(
                &request(
                    "same-family",
                    StickyRouteFamily::Fable,
                    "claude-fable-5-1",
                    &second_pool,
                    &retain2,
                    &policy,
                    10_000,
                ),
                NOW,
            )
            .unwrap()
            .unwrap();
        assert_eq!(changed.account_id, "second");
        assert!(changed.migrated);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(feature = "store")]
    #[test]
    fn retains_affinity_when_only_an_internal_recovery_model_changes() {
        let (router, dir) = router();
        let policy = policy();
        let pool = [
            candidate("original", 0, 100.0, 100.0, 100.0, 96.0),
            candidate("alternative", 1, 100.0, 100.0, 0.0, 96.0),
        ];
        let retain = ids(&["original", "alternative"]);
        let mut base = request(
            "recovery",
            StickyRouteFamily::Fable,
            "claude-fable-5-1",
            &pool,
            &retain,
            &policy,
            10_000,
        );
        base.affinity_model_id = Some("claude-fable-5-1");
        router.resolve(&base, NOW).unwrap().unwrap();
        let mut recovery = request(
            "recovery",
            StickyRouteFamily::Opus,
            "claude-opus-4-8",
            &pool,
            &retain,
            &policy,
            10_000,
        );
        recovery.affinity_model_id = Some("claude-fable-5-1");
        let resolved = router.resolve(&recovery, NOW).unwrap().unwrap();
        assert_eq!(resolved.account_id, "original");
        assert!(!resolved.created && !resolved.migrated);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(feature = "store")]
    #[test]
    fn reallocates_a_legacy_assignment_without_affinity() {
        let (router, dir) = router();
        let policy = policy();
        let original = candidate("original", 0, 100.0, 100.0, 100.0, 96.0);
        let alternative = candidate("alternative", 1, 100.0, 100.0, 0.0, 96.0);
        let pool = [original.clone(), alternative.clone()];
        let retain = ids(&["original", "alternative"]);
        let base = request(
            "legacy",
            StickyRouteFamily::Fable,
            "claude-fable-5-1",
            &pool,
            &retain,
            &policy,
            10_000,
        );
        assert_eq!(
            router.resolve(&base, NOW).unwrap().unwrap().account_id,
            "original"
        );

        let mut state: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&router.path).unwrap()).unwrap();
        for assignment in state["assignments"].as_object_mut().unwrap().values_mut() {
            assignment
                .as_object_mut()
                .unwrap()
                .remove("affinityModelId");
        }
        std::fs::write(&router.path, state.to_string()).unwrap();

        let swapped = [
            StickyRouteCandidate {
                quota: alternative.quota.clone(),
                ..original.clone()
            },
            StickyRouteCandidate {
                quota: original.quota.clone(),
                ..alternative.clone()
            },
        ];
        let changed = router
            .resolve(
                &request(
                    "legacy",
                    StickyRouteFamily::Fable,
                    "claude-fable-5-1",
                    &swapped,
                    &retain,
                    &policy,
                    10_000,
                ),
                NOW + 1_000,
            )
            .unwrap()
            .unwrap();
        assert_eq!(changed.account_id, "alternative");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(feature = "store")]
    #[test]
    fn excluded_and_expired_assignments_migrate() {
        let (router, dir) = router();
        let policy = policy();
        let pool = [
            candidate("a", 0, 100.0, 100.0, 100.0, 96.0),
            candidate("b", 1, 90.0, 90.0, 90.0, 96.0),
        ];
        let retain = ids(&["a", "b"]);
        let base = request(
            "s",
            StickyRouteFamily::General,
            "claude-sonnet-4-6",
            &pool,
            &retain,
            &policy,
            10,
        );
        assert_eq!(router.resolve(&base, NOW).unwrap().unwrap().account_id, "a");
        let exclude = ids(&["a"]);
        let excluded = StickyResolveRequest {
            exclude_account_ids: Some(&exclude),
            ..base
        };
        let moved = router.resolve(&excluded, NOW).unwrap().unwrap();
        assert_eq!(moved.account_id, "b");
        assert!(moved.migrated);

        // An idle assignment expires even while the router lives.
        let short = StickySessionRouter::new(&router.path).with_assignment_ttl_ms(1_000);
        let fresh = short.resolve(&base, NOW + 10_000).unwrap().unwrap();
        assert!(fresh.created);
        router.clear("s", NOW + 10_001).unwrap();
        assert!(
            router
                .resolve(&base, NOW + 10_002)
                .unwrap()
                .unwrap()
                .created
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(feature = "store")]
    #[test]
    fn unknown_quota_candidates() {
        let (router, dir) = router();
        let policy = policy();
        let unknown = StickyRouteCandidate {
            account_id: "unknown".into(),
            quota: None,
            order: 0,
        };
        let known = candidate("known", 1, 100.0, 100.0, 100.0, 96.0);
        let retain = ids(&["unknown", "known"]);
        // A known candidate wins cold selection over an unknown one.
        let mixed = [unknown.clone(), known];
        let r = router
            .resolve(
                &request(
                    "m",
                    StickyRouteFamily::General,
                    "claude-sonnet-4-6",
                    &mixed,
                    &retain,
                    &policy,
                    10,
                ),
                NOW,
            )
            .unwrap()
            .unwrap();
        assert_eq!(r.account_id, "known");
        // Every candidate unknown: ordered selection.
        let second_unknown = StickyRouteCandidate {
            account_id: "unknown-2".into(),
            quota: None,
            order: 5,
        };
        let all_unknown = [second_unknown, unknown];
        let r = router
            .resolve(
                &request(
                    "u",
                    StickyRouteFamily::General,
                    "claude-sonnet-4-6",
                    &all_unknown,
                    &retain,
                    &policy,
                    10,
                ),
                NOW,
            )
            .unwrap()
            .unwrap();
        assert_eq!(r.account_id, "unknown");
        // Every known quota exhausted: no escape to an exhausted candidate.
        let exhausted = [candidate("dead", 0, 0.0, 0.0, 0.0, 96.0)];
        assert!(
            router
                .resolve(
                    &request(
                        "x",
                        StickyRouteFamily::General,
                        "claude-sonnet-4-6",
                        &exhausted,
                        &retain,
                        &policy,
                        10
                    ),
                    NOW
                )
                .unwrap()
                .is_none()
        );
        assert_eq!(
            decide_sticky_quota_failure(None, None, NOW),
            StickyQuotaFailureDecision::Retain(StickyRetainReason::Unknown)
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn quota_failure_decisions() {
        let fable = Some("claude-fable-5");
        let scoped = candidate("a", 0, 100.0, 100.0, 0.0, 96.0).quota.unwrap();
        assert_eq!(
            decide_sticky_quota_failure(Some(&scoped), fable, NOW),
            StickyQuotaFailureDecision::Migrate(StickyMigrateReason::ModelScoped)
        );
        let weekly = candidate("a", 0, 100.0, 0.0, 100.0, 96.0).quota.unwrap();
        assert_eq!(
            decide_sticky_quota_failure(Some(&weekly), None, NOW),
            StickyQuotaFailureDecision::Migrate(StickyMigrateReason::SevenDay)
        );
        let mut five = candidate("a", 0, 0.0, 100.0, 100.0, 96.0).quota.unwrap();
        assert_eq!(
            decide_sticky_quota_failure(Some(&five), None, NOW),
            StickyQuotaFailureDecision::Migrate(StickyMigrateReason::FiveHour)
        );
        five.five_hour.as_mut().unwrap().resets_at = iso(NOW + 10 * 60_000);
        assert_eq!(
            decide_sticky_quota_failure(Some(&five), None, NOW),
            StickyQuotaFailureDecision::Hold {
                retry_after_secs: 600
            }
        );
        let healthy = candidate("a", 0, 50.0, 50.0, 50.0, 96.0).quota.unwrap();
        assert_eq!(
            decide_sticky_quota_failure(Some(&healthy), fable, NOW),
            StickyQuotaFailureDecision::Retain(StickyRetainReason::NotExhausted)
        );
    }

    #[test]
    fn retry_jitter_is_bounded_and_deterministic() {
        let a = sticky_retry_after_with_jitter("session-a", 30.0);
        assert_eq!(a, sticky_retry_after_with_jitter("session-a", 30.0));
        assert!((30..=50).contains(&a));
        assert!(sticky_retry_after_with_jitter("s", 0.0) >= 1);
    }

    #[test]
    fn no_route_reports_auth_before_quota() {
        let quotas = [candidate("a", 0, 100.0, 100.0, 0.0, 96.0).quota.unwrap()];
        let auth = sticky_no_route(true, &[], &quotas, Some("claude-fable-5"), NOW);
        assert_eq!(auth.status, 401);
        assert!(auth.message.contains("for Fable"));
        let relogin = sticky_no_route(false, &["work".into()], &quotas, None, NOW);
        assert!(relogin.message.contains("require re-login: work."));
        let scoped = sticky_no_route(false, &[], &quotas, Some("claude-fable-5"), NOW);
        assert_eq!(scoped.status, 429);
        assert!(scoped.message.starts_with("Fable weekly limit reached"));
        assert_eq!(scoped.retry_after_secs, Some(96 * 3600 + 60));
        assert_eq!(scoped.body()["error"]["type"], "rate_limit_error");
    }

    #[test]
    fn families_and_modes() {
        assert_eq!(
            sticky_route_family_for_model("claude-opus-4-8"),
            StickyRouteFamily::Opus
        );
        assert_eq!(
            sticky_route_family_for_model("claude-sonnet-4-6"),
            StickyRouteFamily::General
        );
        assert_eq!(
            RoutingMode::parse(" Sticky-Balanced "),
            Some(RoutingMode::StickyBalanced)
        );
        assert_eq!(RoutingMode::parse("nope"), None);
        assert_eq!(RoutingMode::default(), RoutingMode::MainFirst);
    }
}
