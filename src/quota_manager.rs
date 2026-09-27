//! Per-account quota cache with poll de-duplication, per-account backoff and
//! identity fencing — a sans-I/O port of anthropic-auth's `QuotaManager`
//! (upstream `b504bc8`).
//!
//! The TypeScript manager splits a "main" account from "fallback" accounts;
//! the shared Rust store has no such split, so every account is keyed by its
//! store id and fenced by a *lineage* (the provider account identity behind
//! that id, e.g. [`crate::token::TokenAccount::uuid`]). The upstream custody
//! fixes that are not custody-specific are kept:
//!
//! * **Identity fencing** (0677fd0, 733e19b, fallback lineage): a lineage
//!   change drops the cache, the backoff, the in-flight poll and the
//!   poll-attempt record; header observations and poll completions from the
//!   old lineage are discarded instead of being stamped onto the new one.
//! * **Header-only staleness** (a456ebd): model-scoped windows come only from
//!   the usage poll, so an entry that has only ever seen headers stays due
//!   for a poll — at most once per interval, because a usage 401/403 arms no
//!   backoff (0677fd0).
//! * **Physical polls only** (0dda779): the poll-attempt bound is recorded by
//!   [`QuotaManager::mark_poll_dispatched`], called immediately before the
//!   HTTP request; a contender that lost the cross-process lock, was backed
//!   off, or was superseded never counts.
//! * **Snapshot-bound ordering** (ef1afb4): persisted seeds are ordered by the
//!   snapshot's own window stamps, never by an unbound side timestamp.
//!
//! The caller owns I/O: call [`QuotaManager::begin_poll`], acquire any
//! cross-process lock, call [`QuotaManager::mark_poll_dispatched`], perform
//! the `GET`, then report through [`QuotaManager::complete_poll`].

use std::collections::HashMap;

use crate::backoff::{
    FailureFacts,
    OperationError,
    build_quota_operation_error,
    is_quota_auth_failure,
    quota_backoff_active,
};
use crate::quota::{
    QuotaFieldSource,
    QuotaPolicy,
    QuotaSnapshot,
    merge_header_quota_snapshot,
    merge_poll_completion_with_newer_headers,
};

/// A cached snapshot and when it is next due.
#[derive(Debug, Clone, PartialEq)]
pub struct QuotaEntry {
    /// The snapshot.
    pub quota: QuotaSnapshot,
    /// Earliest next poll, epoch ms.
    pub refresh_after: i64,
    /// Observation time, epoch ms (last-write-wins across responses: the
    /// headers carry no authoritative server ordering).
    pub checked_at: i64,
}

/// Permission to perform one physical poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PollTicket {
    /// Account the poll is for.
    pub account_id: String,
    generation: u64,
    id: u64,
}

/// What [`QuotaManager::begin_poll`] decided.
#[derive(Debug, Clone, PartialEq)]
pub enum PollDecision {
    /// Poll now with this ticket.
    Poll(PollTicket),
    /// A poll for this account is already in flight; wait for it.
    InFlight,
    /// Backed off; here is the cached snapshot.
    Cached(Box<QuotaSnapshot>),
    /// Backed off with nothing cached.
    BackedOff,
}

/// What [`QuotaManager::complete_poll`] did with a result.
#[derive(Debug, Clone, PartialEq)]
pub enum PollOutcome {
    /// The poll landed in the cache.
    Applied(QuotaEntry),
    /// The account's identity changed while the poll was in flight; the
    /// result was not cached (it is returned stamped with the ticket's
    /// account id for the caller's own use).
    Superseded(Option<QuotaSnapshot>),
    /// The poll failed. `backoff` is the armed backoff, `None` for an auth
    /// failure (401/403), which never arms quota backoff.
    Failed {
        /// The recorded failure, when one was armed.
        backoff: Option<OperationError>,
    },
}

#[derive(Debug, Default)]
struct AccountQuota {
    entry: Option<QuotaEntry>,
    /// `None` = never bound; `Some(None)` = bound to an unknown lineage.
    lineage: Option<Option<String>>,
    generation: u64,
    api_error: Option<OperationError>,
    inflight: Option<u64>,
    last_poll_attempt: Option<i64>,
}

impl AccountQuota {
    fn reset(&mut self) {
        self.generation += 1;
        self.entry = None;
        self.api_error = None;
        self.inflight = None;
        self.last_poll_attempt = None;
    }
}

/// The per-process quota cache.
#[derive(Debug, Default)]
pub struct QuotaManager {
    policy: QuotaPolicy,
    accounts: HashMap<String, AccountQuota>,
    next_ticket: u64,
}

impl QuotaManager {
    /// An empty manager under `policy`.
    pub fn new(policy: QuotaPolicy) -> Self {
        Self {
            policy,
            accounts: HashMap::new(),
            next_ticket: 0,
        }
    }

    /// The active policy.
    pub fn policy(&self) -> &QuotaPolicy {
        &self.policy
    }

    /// Replace the policy (e.g. after re-reading config).
    pub fn set_policy(&mut self, policy: QuotaPolicy) {
        self.policy = policy;
    }

    /// The cached entry for `account_id`.
    pub fn get(&self, account_id: &str) -> Option<&QuotaEntry> {
        self.accounts.get(account_id)?.entry.as_ref()
    }

    /// Bind `account_id` to `lineage`. A change from one *known* lineage to
    /// another clears everything held for the account and returns `true`.
    pub fn bind_lineage(&mut self, account_id: &str, lineage: Option<&str>) -> bool {
        let state = self.accounts.entry(account_id.to_owned()).or_default();
        let changed = matches!(
            (&state.lineage, lineage),
            (Some(previous), Some(new)) if previous.as_deref() != Some(new)
        );
        if changed {
            state.reset();
        }
        state.lineage = Some(lineage.map(str::to_owned));
        changed
    }

    fn accepts_observation(&mut self, account_id: &str, lineage: Option<&str>) -> bool {
        let state = self.accounts.entry(account_id.to_owned()).or_default();
        match &state.lineage {
            Some(bound) => bound.as_deref() == lineage,
            None => {
                state.lineage = Some(lineage.map(str::to_owned));
                true
            }
        }
    }

    /// Merge a header harvest observed for `account_id` under `lineage`.
    /// Returns `None` when the observation belongs to a superseded lineage.
    pub fn push_headers(
        &mut self,
        account_id: &str,
        lineage: Option<&str>,
        incoming: &QuotaSnapshot,
        now: i64,
    ) -> Option<&QuotaEntry> {
        if !self.accepts_observation(account_id, lineage) {
            return None;
        }
        let checked_at = incoming.checked_at.unwrap_or(now);
        let state = self.accounts.get_mut(account_id)?;
        let stamped = QuotaSnapshot {
            account_identity: Some(account_id.to_owned()),
            ..incoming.clone()
        };
        let quota = merge_header_quota_snapshot(state.entry.as_ref().map(|e| &e.quota), &stamped);
        let refresh_after = self.policy.next_refresh_at(Some(&quota), checked_at);
        state.entry = Some(QuotaEntry {
            quota,
            refresh_after,
            checked_at,
        });
        state.entry.as_ref()
    }

    /// Seed from persisted state (another process's fresh write, or boot).
    /// Ordering comes from the snapshot's own window stamps. A newer
    /// in-memory header entry over an older persisted poll is merged so the
    /// poll-owned fields are restored without regressing the headers.
    pub fn seed(
        &mut self,
        account_id: &str,
        lineage: Option<&str>,
        persisted: Option<&QuotaSnapshot>,
        persisted_error: Option<&OperationError>,
        now: i64,
    ) {
        if self.bind_lineage(account_id, lineage) {
            return;
        }
        let policy = self.policy.clone();
        let Some(state) = self.accounts.get_mut(account_id) else {
            return;
        };
        let persisted_checked = persisted.map_or(0, QuotaSnapshot::checked_at_max);
        match (persisted_error, &state.api_error) {
            (Some(error), current)
                if quota_backoff_active(Some(error), now)
                    && persisted_checked <= error.checked_at
                    && current
                        .as_ref()
                        .is_none_or(|c| error.checked_at >= c.checked_at) =>
            {
                state.api_error = Some(error.clone());
            }
            (_, Some(current)) if persisted_checked >= current.checked_at => state.api_error = None,
            _ => {}
        }
        let Some(persisted) = persisted else {
            return;
        };
        if persisted_checked <= 0 {
            return;
        }
        let seeded = QuotaSnapshot {
            account_identity: Some(account_id.to_owned()),
            ..persisted.clone()
        };
        match &state.entry {
            Some(current)
                if current.checked_at >= persisted_checked
                    && current.quota.source == Some(QuotaFieldSource::Headers)
                    && seeded.source == Some(QuotaFieldSource::Poll) =>
            {
                let quota = merge_header_quota_snapshot(Some(&seeded), &current.quota);
                let checked_at = current.checked_at;
                state.entry = Some(QuotaEntry {
                    refresh_after: policy.next_refresh_at(Some(&quota), checked_at),
                    quota,
                    checked_at,
                });
            }
            Some(current) if current.checked_at >= persisted_checked => {}
            _ => {
                state.entry = Some(QuotaEntry {
                    refresh_after: policy.next_refresh_at(Some(&seeded), persisted_checked),
                    quota: seeded,
                    checked_at: persisted_checked,
                });
            }
        }
    }

    /// Drop every account not in `configured` (a removed login must not keep
    /// serving its quota to a later account that reuses the id).
    pub fn retain_accounts<'a>(&mut self, configured: impl IntoIterator<Item = &'a str>) {
        let keep: std::collections::HashSet<&str> = configured.into_iter().collect();
        self.accounts.retain(|id, _| keep.contains(id.as_str()));
    }

    /// Forget everything about `account_id`; any in-flight poll is superseded.
    pub fn clear(&mut self, account_id: &str) {
        if let Some(state) = self.accounts.get_mut(account_id) {
            state.reset();
        }
    }

    /// Whether the account's quota poll is backed off at `now`.
    pub fn is_backed_off(&self, account_id: &str, now: i64) -> bool {
        self.accounts
            .get(account_id)
            .is_some_and(|s| quota_backoff_active(s.api_error.as_ref(), now))
    }

    /// The last armed quota failure for `account_id`.
    pub fn last_error(&self, account_id: &str) -> Option<&OperationError> {
        self.accounts.get(account_id)?.api_error.as_ref()
    }

    /// Clear an armed backoff (e.g. an explicit user reset).
    pub fn clear_backoff(&mut self, account_id: &str) -> bool {
        self.accounts
            .get_mut(account_id)
            .and_then(|s| s.api_error.take())
            .is_some()
    }

    /// Whether `account_id` is due for a poll at `now` (for `model`'s scoped
    /// window, when given).
    pub fn is_stale(&self, account_id: &str, model: Option<&str>, now: i64) -> bool {
        let Some(state) = self.accounts.get(account_id) else {
            return true;
        };
        let Some(entry) = &state.entry else {
            return true;
        };
        let interval = self.policy.interval_ms();
        if now >= entry.refresh_after {
            return true;
        }
        if entry
            .quota
            .scoped_window_for_model(model)
            .is_some_and(|w| now - w.checked_at >= interval)
        {
            return true;
        }
        // Header-only: never polled, so scoped limits are unknown. An empty
        // scoped array is a real poll result and does not qualify.
        entry.quota.source == Some(QuotaFieldSource::Headers)
            && entry.quota.scoped.is_none()
            && state
                .last_poll_attempt
                .is_none_or(|at| now - at >= interval)
    }

    /// Stale by time, or forced by the request counter.
    pub fn needs_refresh(
        &self,
        account_id: &str,
        request_count: u64,
        model: Option<&str>,
        now: i64,
    ) -> bool {
        self.is_stale(account_id, model, now)
            || self.policy.should_refresh_on_request_count(request_count)
    }

    /// Decide whether to poll `account_id` now.
    pub fn begin_poll(&mut self, account_id: &str, now: i64) -> PollDecision {
        let state = self.accounts.entry(account_id.to_owned()).or_default();
        if state.inflight.is_some() {
            return PollDecision::InFlight;
        }
        if quota_backoff_active(state.api_error.as_ref(), now) {
            return match &state.entry {
                Some(entry) => PollDecision::Cached(Box::new(entry.quota.clone())),
                None => PollDecision::BackedOff,
            };
        }
        self.next_ticket += 1;
        state.inflight = Some(self.next_ticket);
        PollDecision::Poll(PollTicket {
            account_id: account_id.to_owned(),
            generation: state.generation,
            id: self.next_ticket,
        })
    }

    fn current(&self, ticket: &PollTicket) -> bool {
        self.accounts
            .get(&ticket.account_id)
            .is_some_and(|s| s.generation == ticket.generation)
    }

    /// Record that the ticket's HTTP request is being sent now. Only this
    /// counts toward the header-only poll bound.
    pub fn mark_poll_dispatched(&mut self, ticket: &PollTicket, now: i64) {
        if !self.current(ticket) {
            return;
        }
        if let Some(state) = self.accounts.get_mut(&ticket.account_id) {
            state.last_poll_attempt = Some(now);
        }
    }

    /// Give up a ticket without polling (lost the cross-process lock,
    /// cancelled). Records nothing.
    pub fn abandon_poll(&mut self, ticket: PollTicket) {
        self.release(&ticket);
    }

    fn release(&mut self, ticket: &PollTicket) {
        if let Some(state) = self.accounts.get_mut(&ticket.account_id)
            && state.inflight == Some(ticket.id)
        {
            state.inflight = None;
        }
    }

    /// Report a poll result.
    pub fn complete_poll(
        &mut self,
        ticket: PollTicket,
        now: i64,
        result: std::result::Result<QuotaSnapshot, FailureFacts>,
    ) -> PollOutcome {
        self.release(&ticket);
        if !self.current(&ticket) {
            return PollOutcome::Superseded(result.ok().map(|quota| QuotaSnapshot {
                account_identity: Some(ticket.account_id.clone()),
                ..quota
            }));
        }
        let policy = self.policy.clone();
        let Some(state) = self.accounts.get_mut(&ticket.account_id) else {
            return PollOutcome::Superseded(None);
        };
        match result {
            Ok(polled) => {
                let polled = QuotaSnapshot {
                    account_identity: Some(ticket.account_id.clone()),
                    ..polled
                };
                let quota = merge_poll_completion_with_newer_headers(
                    state.entry.as_ref().map(|e| &e.quota),
                    &polled,
                );
                let entry = QuotaEntry {
                    refresh_after: policy.next_refresh_at(Some(&quota), now),
                    checked_at: quota.checked_at.unwrap_or(now),
                    quota,
                };
                state.entry = Some(entry.clone());
                state.api_error = None;
                PollOutcome::Applied(entry)
            }
            Err(facts) => {
                if is_quota_auth_failure(&facts) {
                    return PollOutcome::Failed { backoff: None };
                }
                let error = build_quota_operation_error(
                    &facts,
                    now,
                    Some(&ticket.account_id),
                    state.api_error.as_ref(),
                );
                state.api_error = Some(error.clone());
                PollOutcome::Failed {
                    backoff: Some(error),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Ports of core/opencode `quota-manager.test.ts` behaviors that are not
    //! tied to OpenCode's main/fallback split or to custody transport.
    use super::*;
    use crate::quota::normalize_quota_headers;

    const NOW: i64 = 1_700_000_000_000;
    const INTERVAL: i64 = crate::quota::DEFAULT_QUOTA_CHECK_INTERVAL_MS;

    fn headers(now: i64) -> QuotaSnapshot {
        normalize_quota_headers(
            &[
                ("anthropic-ratelimit-unified-5h-utilization", "0.5"),
                ("anthropic-ratelimit-unified-7d-utilization", "0.25"),
            ],
            now,
        )
    }

    fn poll(now: i64) -> QuotaSnapshot {
        QuotaSnapshot::from_usage_response(
            &serde_json::json!({
                "five_hour": { "utilization": 10 },
                "seven_day": { "utilization": 20 },
                "limits": [{ "kind": "weekly_scoped", "group": "weekly", "percent": 30,
                             "scope": { "model": { "display_name": "Fable" } } }]
            }),
            now,
        )
    }

    fn ticket(manager: &mut QuotaManager, account: &str, now: i64) -> PollTicket {
        match manager.begin_poll(account, now) {
            PollDecision::Poll(ticket) => ticket,
            other => panic!("expected a poll ticket, got {other:?}"),
        }
    }

    fn failure(status: u16) -> FailureFacts {
        FailureFacts {
            message: format!("Claude quota check failed: {status}"),
            status: Some(status),
            ..Default::default()
        }
    }

    #[test]
    fn a_header_only_entry_stays_due_for_its_first_usage_poll() {
        let mut manager = QuotaManager::default();
        manager
            .push_headers("a", Some("uuid-a"), &headers(NOW), NOW)
            .unwrap();
        assert!(manager.is_stale("a", None, NOW + 1));
        let t = ticket(&mut manager, "a", NOW + 1);
        manager.mark_poll_dispatched(&t, NOW + 1);
        assert!(matches!(
            manager.complete_poll(t, NOW + 2, Ok(poll(NOW + 2))),
            PollOutcome::Applied(_)
        ));
        assert!(!manager.is_stale("a", None, NOW + 3));
        // A later header push keeps the polled scoped windows.
        manager.push_headers("a", Some("uuid-a"), &headers(NOW + 4), NOW + 4);
        assert!(manager.get("a").unwrap().quota.scoped.is_some());
        assert!(!manager.is_stale("a", None, NOW + 5));
    }

    #[test]
    fn a_failed_first_poll_does_not_rearm_header_only_staleness_until_the_next_interval() {
        let mut manager = QuotaManager::default();
        manager.push_headers("a", None, &headers(NOW), NOW);
        let t = ticket(&mut manager, "a", NOW);
        manager.mark_poll_dispatched(&t, NOW);
        // A usage 403 arms no backoff…
        assert_eq!(
            manager.complete_poll(t, NOW, Err(failure(403))),
            PollOutcome::Failed { backoff: None }
        );
        assert!(!manager.is_backed_off("a", NOW));
        // …so the header-only rule alone must not repeat the poll every request.
        assert!(!manager.is_stale("a", None, NOW + 1_000));
        assert!(manager.is_stale("a", None, NOW + INTERVAL));
    }

    #[test]
    fn losing_the_cross_process_lock_does_not_count_as_a_poll_attempt() {
        let mut manager = QuotaManager::default();
        manager.push_headers("a", None, &headers(NOW), NOW);
        let t = ticket(&mut manager, "a", NOW);
        manager.abandon_poll(t);
        assert!(manager.is_stale("a", None, NOW + 1));
        assert!(matches!(
            manager.begin_poll("a", NOW + 1),
            PollDecision::Poll(_)
        ));
    }

    #[test]
    fn a_poll_attempt_for_a_previous_identity_does_not_delay_the_new_identity() {
        let mut manager = QuotaManager::default();
        manager.push_headers("a", Some("old"), &headers(NOW), NOW);
        let t = ticket(&mut manager, "a", NOW);
        manager.mark_poll_dispatched(&t, NOW);
        manager.abandon_poll(t);
        assert!(!manager.is_stale("a", None, NOW + 1));
        assert!(manager.bind_lineage("a", Some("new")));
        manager.push_headers("a", Some("new"), &headers(NOW + 2), NOW + 2);
        assert!(manager.is_stale("a", None, NOW + 3));
    }

    #[test]
    fn a_lineage_change_discards_stale_observations_and_superseded_polls() {
        let mut manager = QuotaManager::default();
        manager.push_headers("a", Some("old"), &headers(NOW), NOW);
        let t = ticket(&mut manager, "a", NOW);
        manager.bind_lineage("a", Some("new"));
        assert!(manager.get("a").is_none());
        // A late header harvest from the old login is dropped.
        assert!(
            manager
                .push_headers("a", Some("old"), &headers(NOW + 1), NOW + 1)
                .is_none()
        );
        // The old poll completes but lands nowhere.
        let outcome = manager.complete_poll(t, NOW + 2, Ok(poll(NOW + 2)));
        assert!(
            matches!(outcome, PollOutcome::Superseded(Some(ref q)) if q.account_identity.as_deref() == Some("a"))
        );
        assert!(manager.get("a").is_none());
        // A re-bind to the same lineage is not a change.
        assert!(!manager.bind_lineage("a", Some("new")));
        // An unknown lineage never counts as a change.
        assert!(!manager.bind_lineage("a", None));
    }

    #[test]
    fn a_completed_older_request_does_not_clear_a_newer_in_flight_poll() {
        let mut manager = QuotaManager::default();
        let old = ticket(&mut manager, "a", NOW);
        manager.clear("a");
        let newer = ticket(&mut manager, "a", NOW + 1);
        manager.complete_poll(old, NOW + 2, Ok(poll(NOW + 2)));
        assert_eq!(manager.begin_poll("a", NOW + 3), PollDecision::InFlight);
        assert!(matches!(
            manager.complete_poll(newer, NOW + 4, Ok(poll(NOW + 4))),
            PollOutcome::Applied(_)
        ));
    }

    #[test]
    fn transient_failures_back_off_only_the_failing_account() {
        let mut manager = QuotaManager::default();
        let t = ticket(&mut manager, "a", NOW);
        let PollOutcome::Failed {
            backoff: Some(error),
        } = manager.complete_poll(t, NOW, Err(failure(429)))
        else {
            panic!("429 must arm backoff");
        };
        assert_eq!(error.account_identity.as_deref(), Some("a"));
        assert_eq!(manager.begin_poll("a", NOW + 1), PollDecision::BackedOff);
        assert!(matches!(
            manager.begin_poll("b", NOW + 1),
            PollDecision::Poll(_)
        ));
        assert!(manager.clear_backoff("a"));
        assert!(matches!(
            manager.begin_poll("a", NOW + 1),
            PollDecision::Poll(_)
        ));
    }

    #[test]
    fn backed_off_polls_serve_the_cache() {
        let mut manager = QuotaManager::default();
        manager.push_headers("a", None, &headers(NOW), NOW);
        let t = ticket(&mut manager, "a", NOW);
        manager.complete_poll(t, NOW, Err(failure(503)));
        assert!(matches!(
            manager.begin_poll("a", NOW + 1),
            PollDecision::Cached(_)
        ));
    }

    #[test]
    fn poll_completion_preserves_newer_header_windows() {
        let mut manager = QuotaManager::default();
        let t = ticket(&mut manager, "a", NOW);
        manager.push_headers("a", None, &headers(NOW + 10), NOW + 10);
        let PollOutcome::Applied(entry) = manager.complete_poll(t, NOW + 20, Ok(poll(NOW))) else {
            panic!("expected applied");
        };
        assert_eq!(entry.quota.five_hour.as_ref().unwrap().used_percent, 50.0);
        assert!(entry.quota.scoped.is_some());
    }

    #[test]
    fn seeding_is_ordered_by_the_snapshot_itself() {
        let mut manager = QuotaManager::default();
        manager.push_headers("a", None, &headers(NOW + 1_000), NOW + 1_000);
        // An older persisted poll restores scoped fields without regressing
        // the newer header windows.
        manager.seed("a", None, Some(&poll(NOW)), None, NOW + 2_000);
        let entry = manager.get("a").unwrap();
        assert_eq!(entry.quota.five_hour.as_ref().unwrap().used_percent, 50.0);
        assert!(entry.quota.scoped.is_some());
        assert_eq!(entry.checked_at, NOW + 1_000);
        // A newer persisted snapshot replaces the cache.
        manager.seed("a", None, Some(&poll(NOW + 5_000)), None, NOW + 6_000);
        assert_eq!(
            manager
                .get("a")
                .unwrap()
                .quota
                .five_hour
                .as_ref()
                .unwrap()
                .used_percent,
            10.0
        );
        // An older header-sourced snapshot never replaces it.
        manager.seed("a", None, Some(&headers(NOW)), None, NOW + 7_000);
        assert_eq!(manager.get("a").unwrap().checked_at, NOW + 5_000);
    }

    #[test]
    fn seeding_adopts_active_persisted_backoff_and_clears_it_after_a_newer_snapshot() {
        let mut manager = QuotaManager::default();
        let error = build_quota_operation_error(&failure(429), NOW, Some("a"), None);
        manager.seed("a", None, None, Some(&error), NOW + 1);
        assert!(manager.is_backed_off("a", NOW + 1));
        manager.seed("a", None, Some(&poll(NOW + 2)), None, NOW + 3);
        assert!(!manager.is_backed_off("a", NOW + 3));
        manager.retain_accounts(["b"]);
        assert!(manager.get("a").is_none());
    }

    #[test]
    fn request_count_forces_a_refresh() {
        let mut manager = QuotaManager::new(QuotaPolicy {
            refresh_every_n_requests: 2,
            ..QuotaPolicy::default()
        });
        let t = ticket(&mut manager, "a", NOW);
        manager.complete_poll(t, NOW, Ok(poll(NOW)));
        assert!(!manager.needs_refresh("a", 1, None, NOW + 1));
        assert!(manager.needs_refresh("a", 2, None, NOW + 1));
    }
}
