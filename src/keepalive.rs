//! Keep idle accounts alive (doc 23 §6).
//!
//! A refresh token's own expiry rolls forward on every refresh, so an account
//! nobody uses for about a month dies. Until now the only thing keeping idle
//! accounts alive was an accident: a host's background loop rotating *every*
//! account every few hours whether or not it was used, which multiplies the
//! chances of two processes spending the same token.
//!
//! This replaces that with one deliberate pass:
//!
//! - **One owner per machine.** A pass runs only while it holds the store's
//!   top-level keep-alive lease ([`KeepAliveLease`], written under the store
//!   lock, with a TTL so a crashed owner does not wedge it). A second caller
//!   that finds the lease held does nothing.
//! - **Only accounts that need it.** An account is refreshed when it has no
//!   access token, or its refresh token expires within a threshold (default
//!   7 days), or (when known) its last successful refresh is older than a
//!   maximum age (default 14 days). It is never touched while it is in use:
//!   a live access token, a refresh claim in flight, a recent request, or a
//!   recent refresh all skip it.
//! - **One spend per account per pass**, through the ordinary claimed
//!   [`crate::OAuthClient::refresh_shared`] path, so the keep-alive is just
//!   another well-behaved peer.
//!
//! - **Never a login Claude Code is using.** A row linked to Claude Code's
//!   login (same account and organization) is skipped while Claude Code's
//!   access token is live: Claude Code keeps that chain alive itself.
//!
//! Nothing else in this crate rotates an idle account.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::account::Account;
use crate::store::AccountStore;

/// Default keep-alive lease TTL.
pub const KEEPALIVE_LEASE_TTL_SECS: i64 = 15 * 60;

/// Default: refresh when the refresh token expires within this many days.
pub const KEEPALIVE_REFRESH_EXPIRY_THRESHOLD_DAYS: i64 = 7;

/// Default: refresh when the last known successful refresh is this old.
pub const KEEPALIVE_MAX_REFRESH_AGE_DAYS: i64 = 14;

/// The store-level keep-alive lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeepAliveLease {
    /// Random owner id of the pass holding the lease (never a PID).
    pub owner: String,
    /// Lease expiry, epoch milliseconds.
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub until: DateTime<Utc>,
    /// The holder's PID; diagnostics only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder_pid: Option<u32>,
}

/// Outcome of trying to take the keep-alive lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeepAliveClaim {
    /// This caller holds the lease.
    Claimed,
    /// Another pass holds a live lease.
    Held {
        /// When it lapses.
        until: DateTime<Utc>,
        /// Its PID, when recorded.
        holder_pid: Option<u32>,
    },
}

impl AccountStore {
    /// Take the keep-alive lease for `owner` until `now + ttl` unless another
    /// owner holds a live one (in-memory form; persist with
    /// [`AccountStore::mutate`]).
    pub fn claim_keepalive(
        &mut self,
        owner: &str,
        now: DateTime<Utc>,
        ttl: Duration,
        holder_pid: Option<u32>,
    ) -> KeepAliveClaim {
        if let Some(lease) = &self.keepalive
            && lease.owner != owner
            && lease.until > now
        {
            return KeepAliveClaim::Held {
                until: lease.until,
                holder_pid: lease.holder_pid,
            };
        }
        self.keepalive = Some(KeepAliveLease {
            owner: owner.to_owned(),
            until: now + ttl,
            holder_pid,
        });
        KeepAliveClaim::Claimed
    }

    /// Release the keep-alive lease if `owner` still holds it.
    pub fn release_keepalive(&mut self, owner: &str) -> bool {
        if self.keepalive.as_ref().is_some_and(|l| l.owner == owner) {
            self.keepalive = None;
            return true;
        }
        false
    }
}

/// Tunables for a keep-alive pass.
#[derive(Debug, Clone)]
pub struct KeepAliveOptions {
    /// Refresh when the refresh token expires within this window.
    pub refresh_expiry_threshold: Duration,
    /// Refresh when the last known successful refresh is older than this.
    /// `None` disables the rule.
    pub max_refresh_age: Option<Duration>,
    /// An account used within this window is in use and skipped.
    pub recent_use_window: Duration,
    /// An account refreshed within this window is skipped.
    pub recent_refresh_window: Duration,
    /// Keep-alive lease TTL. A pass stops starting new refreshes a minute
    /// (or a third of the TTL, if shorter) before it lapses.
    pub lease_ttl: Duration,
    /// Pause between two refreshes in one pass (a random 0–100% is added).
    pub spacing: std::time::Duration,
    /// Options for each claimed refresh.
    #[cfg(feature = "client")]
    pub refresh: crate::refresh::SharedRefreshOptions,
}

impl Default for KeepAliveOptions {
    fn default() -> Self {
        Self {
            refresh_expiry_threshold: Duration::days(KEEPALIVE_REFRESH_EXPIRY_THRESHOLD_DAYS),
            max_refresh_age: Some(Duration::days(KEEPALIVE_MAX_REFRESH_AGE_DAYS)),
            recent_use_window: Duration::minutes(30),
            recent_refresh_window: Duration::hours(1),
            lease_ttl: Duration::seconds(KEEPALIVE_LEASE_TTL_SECS),
            spacing: std::time::Duration::from_secs(2),
            #[cfg(feature = "client")]
            refresh: crate::refresh::SharedRefreshOptions::default(),
        }
    }
}

/// Why an account is due for a keep-alive refresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepAliveReason {
    /// The row has no access token at all.
    NoAccessToken,
    /// The refresh token expires within the threshold.
    RefreshExpiring,
    /// The last successful refresh is older than the maximum age.
    Stale,
}

/// Why an account was left alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepAliveSkip {
    /// Disabled.
    Disabled,
    /// Not an OAuth account.
    NotOauth,
    /// No refresh token to spend.
    NoRefreshToken,
    /// The refresh token is recorded dead; only a re-login helps.
    DeadToken,
    /// The refresh token is past its own expiry; only a re-login helps.
    RefreshExpired,
    /// In use: a refresh claim is in flight or a request used it recently.
    InUse,
    /// Its access token is still live: a session may be using it.
    SessionLive,
    /// Refreshed within the recent-refresh window.
    RecentlyRefreshed,
    /// Nothing is close to expiring.
    NotDue,
    /// The pass ran out of lease time before reaching it.
    Deferred,
    /// Linked to Claude Code's login, whose access token is live: Claude
    /// Code keeps its own chain alive (one login per account).
    ClaudeCodeLive,
}

/// Whether `account` is due for a keep-alive refresh at `now`.
pub fn keepalive_verdict(
    account: &Account,
    now: DateTime<Utc>,
    options: &KeepAliveOptions,
) -> Result<KeepAliveReason, KeepAliveSkip> {
    if !account.enabled {
        return Err(KeepAliveSkip::Disabled);
    }
    let Some(tokens) = account.oauth() else {
        return Err(KeepAliveSkip::NotOauth);
    };
    if tokens.refresh.expose().trim().is_empty() {
        return Err(KeepAliveSkip::NoRefreshToken);
    }
    if account.refresh_token_is_dead() {
        return Err(KeepAliveSkip::DeadToken);
    }
    if tokens.is_refresh_expired(now) {
        return Err(KeepAliveSkip::RefreshExpired);
    }
    if account
        .refresh_lease
        .as_ref()
        .is_some_and(|l| l.until > now)
        || account
            .last_used_at
            .is_some_and(|used| now - used < options.recent_use_window)
    {
        return Err(KeepAliveSkip::InUse);
    }
    if account
        .last_refreshed_at
        .is_some_and(|refreshed| now - refreshed < options.recent_refresh_window)
    {
        return Err(KeepAliveSkip::RecentlyRefreshed);
    }
    if tokens.access.expose().trim().is_empty() {
        return Ok(KeepAliveReason::NoAccessToken);
    }
    if !tokens.is_expired(now) {
        return Err(KeepAliveSkip::SessionLive);
    }
    if tokens
        .refresh_expires_at
        .is_some_and(|expires| expires - now < options.refresh_expiry_threshold)
    {
        return Ok(KeepAliveReason::RefreshExpiring);
    }
    if let (Some(max_age), Some(refreshed)) = (options.max_refresh_age, account.last_refreshed_at)
        && now - refreshed > max_age
    {
        return Ok(KeepAliveReason::Stale);
    }
    Err(KeepAliveSkip::NotDue)
}

/// The accounts a keep-alive pass would refresh at `now`, in store order.
pub fn keepalive_due(
    store: &AccountStore,
    now: DateTime<Utc>,
    options: &KeepAliveOptions,
) -> Vec<(String, KeepAliveReason)> {
    store
        .accounts
        .iter()
        .filter_map(|account| {
            keepalive_verdict(account, now, options)
                .ok()
                .map(|reason| (account.id.clone(), reason))
        })
        .collect()
}

/// What happened to the keep-alive lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeepAliveLeaseOutcome {
    /// This pass held the lease and did the work.
    Acquired,
    /// Another pass holds the lease; nothing was done.
    Held {
        /// When it lapses.
        until: DateTime<Utc>,
        /// Its PID, when recorded.
        holder_pid: Option<u32>,
    },
    /// There is no store file; nothing to keep alive.
    NoStore,
}

/// One failed keep-alive refresh.
#[cfg(feature = "client")]
#[derive(Debug, Clone)]
pub struct KeepAliveFailure {
    /// The store row.
    pub account_id: String,
    /// The failure class.
    pub failure: crate::refresh::RefreshFailure,
    /// The redacted error text.
    pub message: String,
}

/// Result of one keep-alive pass. Carries ids and verdicts, never tokens.
#[cfg(feature = "client")]
#[derive(Debug, Clone)]
pub struct KeepAliveReport {
    /// The lease outcome; only [`KeepAliveLeaseOutcome::Acquired`] did work.
    pub lease: KeepAliveLeaseOutcome,
    /// Rows this pass refreshed (one token spent each).
    pub refreshed: Vec<(String, KeepAliveReason)>,
    /// Rows a peer had already rotated; adopted without spending.
    pub adopted: Vec<String>,
    /// Rows whose refresh failed.
    pub failed: Vec<KeepAliveFailure>,
    /// Rows left alone, and why.
    pub skipped: Vec<(String, KeepAliveSkip)>,
}

#[cfg(feature = "client")]
impl KeepAliveReport {
    fn empty(lease: KeepAliveLeaseOutcome) -> Self {
        Self {
            lease,
            refreshed: Vec::new(),
            adopted: Vec::new(),
            failed: Vec::new(),
            skipped: Vec::new(),
        }
    }
}

#[cfg(feature = "client")]
impl crate::oauth::OAuthClient {
    /// Run one keep-alive pass over the store at `path` (see the module
    /// docs). `now` decides which accounts are due and dates the lease.
    pub async fn keep_alive_once(
        &self,
        path: &std::path::Path,
        now: DateTime<Utc>,
        options: &KeepAliveOptions,
    ) -> crate::Result<KeepAliveReport> {
        use crate::refresh::{RefreshSource, classify_refresh_failure};

        if std::fs::symlink_metadata(path).is_err() {
            return Ok(KeepAliveReport::empty(KeepAliveLeaseOutcome::NoStore));
        }
        let owner = uuid::Uuid::new_v4().to_string();
        let claim = AccountStore::mutate(path, |store| {
            Ok(store.claim_keepalive(&owner, now, options.lease_ttl, Some(std::process::id())))
        })?;
        if let KeepAliveClaim::Held { until, holder_pid } = claim {
            return Ok(KeepAliveReport::empty(KeepAliveLeaseOutcome::Held {
                until,
                holder_pid,
            }));
        }
        let started = std::time::Instant::now();
        let ttl_ms = options.lease_ttl.num_milliseconds().max(0);
        let budget = std::time::Duration::from_millis(
            u64::try_from(ttl_ms - (ttl_ms / 3).min(60_000)).unwrap_or(0),
        );

        let mut report = KeepAliveReport::empty(KeepAliveLeaseOutcome::Acquired);
        let result = async {
            let snapshot = AccountStore::read_locked(path, |store| Ok(store.clone()))?;
            let claude_code = self.claude_code_files().and_then(|files| {
                crate::credentials::read_claude_code_login(&files, Some(&snapshot))
            });
            let mut first = true;
            for account in &snapshot.accounts {
                if let Err(skip) = keepalive_verdict(account, now, options) {
                    report.skipped.push((account.id.clone(), skip));
                    continue;
                }
                if let Some(login) = &claude_code
                    && crate::credentials::is_linked(account, &login.identity)
                    && !login.tokens.is_expired(now)
                {
                    report
                        .skipped
                        .push((account.id.clone(), KeepAliveSkip::ClaudeCodeLive));
                    continue;
                }
                if started.elapsed() >= budget {
                    report
                        .skipped
                        .push((account.id.clone(), KeepAliveSkip::Deferred));
                    continue;
                }
                if !first && !options.spacing.is_zero() {
                    tokio::time::sleep(jittered(options.spacing)).await;
                }
                first = false;
                // Re-read under the lock: a peer may have used or rotated the
                // row since the snapshot.
                let current =
                    AccountStore::read_locked(path, |store| Ok(store.get(&account.id).cloned()))?;
                let Some(current) = current else {
                    continue;
                };
                let reason = match keepalive_verdict(&current, now, options) {
                    Ok(reason) => reason,
                    Err(skip) => {
                        report.skipped.push((current.id.clone(), skip));
                        continue;
                    }
                };
                let Some(tokens) = current.oauth() else {
                    continue;
                };
                match self.refresh_shared(path, tokens, &options.refresh).await {
                    Ok(outcome) if outcome.source == RefreshSource::Refreshed => {
                        report.refreshed.push((current.id.clone(), reason));
                    }
                    Ok(_) => report.adopted.push(current.id.clone()),
                    Err(error) => {
                        let failure = classify_refresh_failure(&error);
                        let message = crate::token::redact_secrets(&error.to_string());
                        // A dead verdict is already recorded by the refresh
                        // path; anything else is noted against this token so
                        // an operator can see why the account was not kept
                        // alive. Bound to the token, it clears on rotation.
                        // A busy Claude Code link says nothing about this
                        // token either: it is retried on the next pass.
                        if failure != crate::refresh::RefreshFailure::Revoked
                            && !matches!(error, crate::Error::LinkBusy { .. })
                        {
                            let _ = AccountStore::mutate(path, |store| {
                                Ok(store.record_refresh_error(
                                    &current.id,
                                    &tokens.refresh,
                                    &format!("keep-alive refresh failed: {message}"),
                                ))
                            });
                        }
                        report.failed.push(KeepAliveFailure {
                            account_id: current.id.clone(),
                            failure,
                            message,
                        });
                    }
                }
            }
            Ok::<(), crate::Error>(())
        }
        .await;
        let released = AccountStore::mutate(path, |store| Ok(store.release_keepalive(&owner)));
        result?;
        released?;
        Ok(report)
    }
}

/// Run one keep-alive pass over `store_path` with the production endpoints
/// (client id and API base from the environment) and default options.
#[cfg(feature = "client")]
pub async fn keep_alive_once(
    store_path: &std::path::Path,
    now: DateTime<Utc>,
) -> crate::Result<KeepAliveReport> {
    crate::oauth::OAuthClient::new(crate::endpoints::Endpoints::from_env())
        .keep_alive_once(store_path, now, &KeepAliveOptions::default())
        .await
}

#[cfg(feature = "client")]
fn jittered(base: std::time::Duration) -> std::time::Duration {
    let mut byte = [0u8; 1];
    let extra = if getrandom::fill(&mut byte).is_ok() {
        u32::from(byte[0])
    } else {
        128
    };
    base + base * extra / 255
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::token::{AccessToken, Credential, OAuthTokens, RefreshToken};

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000 + secs, 0).unwrap()
    }

    const DAY: i64 = 86_400;

    fn row(id: &str, access_expires: i64, refresh_expires: Option<i64>) -> Account {
        Account::new(
            id,
            Credential::Oauth(OAuthTokens {
                access: AccessToken::new(format!("sk-ant-oat01-{id}-aaaaaaaaaaaaaaaaaaaa")),
                refresh: RefreshToken::new(format!("sk-ant-ort01-{id}-aaaaaaaaaaaaaaaaaaaa")),
                expires_at: at(access_expires),
                refresh_expires_at: refresh_expires.map(at),
                scopes: vec!["user:inference".into()],
                account: None,
                organization: None,
            }),
        )
    }

    #[test]
    fn only_idle_accounts_near_expiry_or_without_access_are_due() {
        let options = KeepAliveOptions::default();
        let now = at(0);
        let expiring = row("expiring", -10, Some(3 * DAY));
        let far = row("far", -10, Some(20 * DAY));
        let live = row("live", 3600, Some(DAY));
        let mut no_access = row("no-access", -10, Some(20 * DAY));
        if let Credential::Oauth(t) = &mut no_access.credential {
            t.access = AccessToken::new("");
        }
        let mut used = row("used", -10, Some(DAY));
        used.last_used_at = Some(at(-60));
        let mut refreshed = row("refreshed", -10, Some(DAY));
        refreshed.last_refreshed_at = Some(at(-60));
        let mut stale = row("stale", -10, None);
        stale.last_refreshed_at = Some(at(-15 * DAY));
        let mut dead = row("dead", -10, Some(DAY));
        let dead_refresh = dead.oauth().unwrap().refresh.clone();
        dead.dead_refresh_fingerprint =
            Some(crate::token::token_fingerprint(dead_refresh.expose()));
        let mut claimed = row("claimed", -10, Some(DAY));
        claimed.refresh_lease = Some(crate::account::RefreshLease {
            id: "x".into(),
            until: at(10),
            token_fingerprint: "f".into(),
            holder_pid: None,
            claimed_at: None,
        });
        let gone = row("gone", -10, Some(-1));
        let mut disabled = row("disabled", -10, Some(DAY));
        disabled.enabled = false;

        let store = AccountStore {
            accounts: vec![
                expiring, far, live, no_access, used, refreshed, stale, dead, claimed, gone,
                disabled,
            ],
            ..AccountStore::default()
        };
        assert_eq!(
            keepalive_due(&store, now, &options),
            vec![
                ("expiring".to_owned(), KeepAliveReason::RefreshExpiring),
                ("no-access".to_owned(), KeepAliveReason::NoAccessToken),
                ("stale".to_owned(), KeepAliveReason::Stale),
            ]
        );
        let verdict = |id: &str| keepalive_verdict(store.get(id).unwrap(), now, &options);
        assert_eq!(verdict("far"), Err(KeepAliveSkip::NotDue));
        assert_eq!(verdict("live"), Err(KeepAliveSkip::SessionLive));
        assert_eq!(verdict("used"), Err(KeepAliveSkip::InUse));
        assert_eq!(verdict("claimed"), Err(KeepAliveSkip::InUse));
        assert_eq!(verdict("refreshed"), Err(KeepAliveSkip::RecentlyRefreshed));
        assert_eq!(verdict("dead"), Err(KeepAliveSkip::DeadToken));
        assert_eq!(verdict("gone"), Err(KeepAliveSkip::RefreshExpired));
        assert_eq!(verdict("disabled"), Err(KeepAliveSkip::Disabled));
    }

    #[test]
    fn the_lease_excludes_a_second_owner_until_it_lapses() {
        let mut store = AccountStore::default();
        let ttl = Duration::minutes(15);
        assert_eq!(
            store.claim_keepalive("a", at(0), ttl, Some(1)),
            KeepAliveClaim::Claimed
        );
        assert_eq!(
            store.claim_keepalive("b", at(60), ttl, Some(2)),
            KeepAliveClaim::Held {
                until: at(15 * 60),
                holder_pid: Some(1)
            }
        );
        assert!(!store.release_keepalive("b"));
        // A crashed owner does not wedge the machine.
        assert_eq!(
            store.claim_keepalive("b", at(15 * 60), ttl, Some(2)),
            KeepAliveClaim::Claimed
        );
        assert!(store.release_keepalive("b"));
        assert!(store.keepalive.is_none());
    }

    #[cfg(feature = "client")]
    mod pass {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        use super::*;
        use crate::endpoints::Endpoints;
        use crate::oauth::OAuthClient;

        /// A token endpoint that rotates to a fresh pair on every call after
        /// `delay`, recording each presented refresh token.
        async fn rotating_server(
            delay: std::time::Duration,
        ) -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
            let counter = Arc::new(AtomicUsize::new(0));
            let log = seen.clone();
            tokio::spawn(async move {
                while let Ok((mut stream, _)) = listener.accept().await {
                    let log = log.clone();
                    let counter = counter.clone();
                    tokio::spawn(async move {
                        let mut request = Vec::new();
                        let mut chunk = [0u8; 4096];
                        let start = loop {
                            let Ok(read) = stream.read(&mut chunk).await else {
                                return;
                            };
                            if read == 0 {
                                return;
                            }
                            request.extend_from_slice(&chunk[..read]);
                            if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                                let head =
                                    String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                                let length = head
                                    .lines()
                                    .find_map(|l| {
                                        l.strip_prefix("content-length:")
                                            .and_then(|v| v.trim().parse::<usize>().ok())
                                    })
                                    .unwrap_or(0);
                                if request.len() >= end + 4 + length {
                                    break end + 4;
                                }
                            }
                        };
                        let json: serde_json::Value =
                            serde_json::from_slice(&request[start..]).unwrap_or_default();
                        if let Some(refresh) = json["refresh_token"].as_str() {
                            log.lock().unwrap().push(refresh.to_owned());
                        }
                        tokio::time::sleep(delay).await;
                        let n = counter.fetch_add(1, Ordering::SeqCst);
                        let body = format!(
                            r#"{{"access_token":"sk-ant-oat01-rotated-{n}-aaaaaaaaaaaaaaaaaaaa","refresh_token":"sk-ant-ort01-rotated-{n}-aaaaaaaaaaaaaaaaaaaa","expires_in":28800,"refresh_token_expires_in":2592000,"scope":"user:inference user:profile"}}"#
                        );
                        let response = format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = stream.write_all(response.as_bytes()).await;
                    });
                }
            });
            (format!("http://{address}/v1/oauth/token"), seen)
        }

        fn store_path(tag: &str) -> std::path::PathBuf {
            let dir = std::env::temp_dir().join(format!(
                "anthropic-keepalive-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            dir.join("accounts.json")
        }

        fn real_row(id: &str, access_in: Duration, refresh_in: Duration) -> Account {
            let now = Utc::now();
            Account::new(
                id,
                Credential::Oauth(OAuthTokens {
                    access: AccessToken::new(format!("sk-ant-oat01-{id}-aaaaaaaaaaaaaaaaaaaa")),
                    refresh: RefreshToken::new(format!("sk-ant-ort01-{id}-aaaaaaaaaaaaaaaaaaaa")),
                    expires_at: now + access_in,
                    refresh_expires_at: Some(now + refresh_in),
                    scopes: vec!["user:inference".into()],
                    account: None,
                    organization: None,
                }),
            )
        }

        fn seed(path: &std::path::Path) {
            let mut no_access = real_row("no-access", Duration::hours(-1), Duration::days(20));
            if let Credential::Oauth(t) = &mut no_access.credential {
                t.access = AccessToken::new("");
            }
            let store = AccountStore {
                accounts: vec![
                    real_row("expiring", Duration::hours(-1), Duration::days(3)),
                    no_access,
                    real_row("in-use", Duration::hours(4), Duration::days(2)),
                    real_row("healthy", Duration::hours(-1), Duration::days(25)),
                ],
                ..AccountStore::default()
            };
            store.save(path).unwrap();
        }

        fn client(url: &str) -> OAuthClient {
            let mut endpoints = Endpoints::prod();
            endpoints.token_url = url.to_owned();
            OAuthClient::new(endpoints)
        }

        fn fast() -> KeepAliveOptions {
            KeepAliveOptions {
                spacing: std::time::Duration::ZERO,
                ..KeepAliveOptions::default()
            }
        }

        #[tokio::test]
        async fn one_pass_refreshes_each_due_account_once_and_nothing_else() {
            let (url, seen) = rotating_server(std::time::Duration::ZERO).await;
            let path = store_path("one-pass");
            seed(&path);
            let report = client(&url)
                .keep_alive_once(&path, Utc::now(), &fast())
                .await
                .unwrap();
            assert_eq!(report.lease, KeepAliveLeaseOutcome::Acquired);
            assert_eq!(
                report.refreshed,
                vec![
                    ("expiring".to_owned(), KeepAliveReason::RefreshExpiring),
                    ("no-access".to_owned(), KeepAliveReason::NoAccessToken),
                ]
            );
            assert!(report.failed.is_empty());
            assert!(
                report
                    .skipped
                    .contains(&("in-use".to_owned(), KeepAliveSkip::SessionLive))
            );
            assert!(
                report
                    .skipped
                    .contains(&("healthy".to_owned(), KeepAliveSkip::NotDue))
            );
            assert_eq!(
                *seen.lock().unwrap(),
                vec![
                    "sk-ant-ort01-expiring-aaaaaaaaaaaaaaaaaaaa".to_owned(),
                    "sk-ant-ort01-no-access-aaaaaaaaaaaaaaaaaaaa".to_owned(),
                ]
            );
            let store = AccountStore::load(&path).unwrap();
            assert!(store.keepalive.is_none(), "the lease is released");
            assert!(store.get("expiring").unwrap().last_refreshed_at.is_some());
            // A second pass right after finds nothing due.
            let again = client(&url)
                .keep_alive_once(&path, Utc::now(), &fast())
                .await
                .unwrap();
            assert!(again.refreshed.is_empty());
            assert_eq!(seen.lock().unwrap().len(), 2);
            std::fs::remove_dir_all(path.parent().unwrap()).ok();
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn two_concurrent_passes_do_the_work_once() {
            let (url, seen) = rotating_server(std::time::Duration::from_millis(400)).await;
            let path = store_path("concurrent");
            seed(&path);
            let now = Utc::now();
            let barrier = Arc::new(tokio::sync::Barrier::new(2));
            let run = |barrier: Arc<tokio::sync::Barrier>| {
                let path = path.clone();
                let client = client(&url);
                tokio::spawn(async move {
                    barrier.wait().await;
                    client.keep_alive_once(&path, now, &fast()).await.unwrap()
                })
            };
            let (a, b) = tokio::join!(run(barrier.clone()), run(barrier.clone()));
            let reports = [a.unwrap(), b.unwrap()];
            let acquired = reports
                .iter()
                .filter(|r| r.lease == KeepAliveLeaseOutcome::Acquired)
                .count();
            let held = reports
                .iter()
                .filter(|r| matches!(r.lease, KeepAliveLeaseOutcome::Held { .. }))
                .count();
            assert_eq!((acquired, held), (1, 1), "{reports:?}");
            let refreshed: usize = reports.iter().map(|r| r.refreshed.len()).sum();
            assert_eq!(refreshed, 2);
            let presented = seen.lock().unwrap().clone();
            assert_eq!(presented.len(), 2, "each due token is spent exactly once");
            let unique: std::collections::HashSet<_> = presented.iter().collect();
            assert_eq!(unique.len(), 2);
            assert!(AccountStore::load(&path).unwrap().keepalive.is_none());
            std::fs::remove_dir_all(path.parent().unwrap()).ok();
        }

        #[tokio::test]
        async fn a_failed_keepalive_refresh_is_reported_and_noted_on_the_token() {
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            tokio::spawn(async move {
                while let Ok((mut stream, _)) = listener.accept().await {
                    let mut chunk = [0u8; 8192];
                    let _ = stream.read(&mut chunk).await;
                    let body = r#"{"error":"server_error"}"#;
                    let response = format!(
                        "HTTP/1.1 503 X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                }
            });
            let path = store_path("failed");
            AccountStore {
                accounts: vec![real_row("expiring", Duration::hours(-1), Duration::days(3))],
                ..AccountStore::default()
            }
            .save(&path)
            .unwrap();
            let report = client(&format!("http://{address}/v1/oauth/token"))
                .keep_alive_once(&path, Utc::now(), &fast())
                .await
                .unwrap();
            assert!(report.refreshed.is_empty());
            assert_eq!(report.failed.len(), 1);
            assert_eq!(
                report.failed[0].failure,
                crate::refresh::RefreshFailure::Error
            );
            let row = AccountStore::load(&path).unwrap();
            let row = row.get("expiring").unwrap();
            assert!(!row.refresh_token_is_dead());
            assert!(
                row.current_error()
                    .is_some_and(|e| e.starts_with("keep-alive refresh failed"))
            );
            std::fs::remove_dir_all(path.parent().unwrap()).ok();
        }

        #[tokio::test]
        async fn a_row_linked_to_a_live_claude_code_login_is_left_to_claude_code() {
            let (url, seen) = rotating_server(std::time::Duration::ZERO).await;
            let path = store_path("claude-code");
            let identify = |mut account: Account| {
                if let Credential::Oauth(t) = &mut account.credential {
                    t.account = Some(crate::token::TokenAccount {
                        uuid: "acct-ka".into(),
                        email_address: None,
                    });
                    t.organization = Some(crate::token::TokenOrganization {
                        uuid: "org-ka".into(),
                    });
                }
                account
            };
            // Both rows are due (refresh token expiring); only `linked` is
            // Claude Code's account.
            AccountStore {
                accounts: vec![
                    identify(real_row("linked", Duration::hours(-1), Duration::days(3))),
                    real_row("other", Duration::hours(-1), Duration::days(3)),
                ],
                ..AccountStore::default()
            }
            .save(&path)
            .unwrap();
            let dir = path.parent().unwrap();
            let credentials = dir.join(".credentials.json");
            let write = |path: &std::path::Path, value: serde_json::Value| {
                std::fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
                }
            };
            write(
                &credentials,
                serde_json::json!({ "claudeAiOauth": {
                    "accessToken": "sk-ant-oat01-claude-code-live-aaaaaaaaaaaa",
                    "refreshToken": "sk-ant-ort01-claude-code-live-aaaaaaaaaaaa",
                    "expiresAt": (Utc::now() + Duration::hours(5)).timestamp_millis(),
                    "scopes": ["user:inference"]
                }}),
            );
            write(
                &dir.join(".claude.json"),
                serde_json::json!({ "oauthAccount": {
                    "accountUuid": "acct-ka", "organizationUuid": "org-ka"
                }}),
            );
            let before = std::fs::read(&credentials).unwrap();
            let report = client(&url)
                .native_publish(crate::credentials::NativePublish::At(credentials.clone()))
                .keep_alive_once(&path, Utc::now(), &fast())
                .await
                .unwrap();
            assert!(
                report
                    .skipped
                    .contains(&("linked".to_owned(), KeepAliveSkip::ClaudeCodeLive)),
                "{report:?}"
            );
            assert_eq!(
                report.refreshed,
                vec![("other".to_owned(), KeepAliveReason::RefreshExpiring)]
            );
            assert_eq!(
                *seen.lock().unwrap(),
                vec!["sk-ant-ort01-other-aaaaaaaaaaaaaaaaaaaa".to_owned()]
            );
            assert_eq!(std::fs::read(&credentials).unwrap(), before);
            std::fs::remove_dir_all(dir).ok();
        }

        #[tokio::test]
        async fn a_missing_store_is_a_no_op() {
            let (url, seen) = rotating_server(std::time::Duration::ZERO).await;
            let path = store_path("missing").join("absent.json");
            let report = client(&url)
                .keep_alive_once(&path, Utc::now(), &fast())
                .await
                .unwrap();
            assert_eq!(report.lease, KeepAliveLeaseOutcome::NoStore);
            assert!(seen.lock().unwrap().is_empty());
            assert!(!path.exists());
        }
    }
}
