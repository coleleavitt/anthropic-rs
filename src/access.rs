//! One call from "which account?" to "here is a bearer": selection, reserve,
//! refresh, adoption and rotation over the shared store.
//!
//! This is the coarse entry point a host (the TypeScript plugin through the
//! napi binding, a CLI, a daemon) uses instead of re-implementing custody.
//! It returns an access token and non-secret metadata only; refresh tokens
//! stay inside the crate and the store.
//!
//! Selection order is the store's routing order (`current` first). An account
//! whose access token is live is used as-is. Otherwise each candidate in turn
//! is refreshed through [`crate::OAuthClient::refresh_shared`] (claimed,
//! store-custodied, fail-closed), so one dead login rotates to the next
//! instead of failing the request.

use std::path::Path;

use chrono::{DateTime, Utc};

use crate::account::{Account, QUOTA_OBSERVATION_MAX_AGE_SECS};
use crate::error::Error;
use crate::oauth::OAuthClient;
use crate::refresh::{
    RefreshFailure,
    RefreshSource,
    SharedRefreshOptions,
    classify_refresh_failure,
};
use crate::routing::refresh_exclusion;
use crate::store::AccountStore;

/// What the caller wants.
#[derive(Debug, Clone, Default)]
pub struct AccessRequest {
    /// Use only this account (matched by id, email or label,
    /// case-insensitively).
    pub account: Option<String>,
    /// When non-empty, only accounts matching one of these (id, email or
    /// label) are considered.
    pub allowlist: Vec<String>,
    /// Skip accounts whose fresh quota reading is at or above this
    /// percentage in either window (0–100).
    pub reserve_percent: Option<f64>,
}

/// How the returned access token was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessSource {
    /// The stored access token was live.
    Store,
    /// This call refreshed the account.
    Refreshed,
    /// A peer had already rotated the account; its session was adopted.
    Adopted,
}

/// A usable bearer. Holds the access token only, never the refresh token.
#[derive(Clone)]
pub struct AccessGrant {
    /// The access token to send as `Authorization: Bearer`.
    pub access_token: String,
    /// The store row it belongs to.
    pub account_id: String,
    /// The account email, when known.
    pub email: Option<String>,
    /// Access-token expiry.
    pub expires_at: DateTime<Utc>,
    /// How it was obtained.
    pub source: AccessSource,
}

impl std::fmt::Debug for AccessGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessGrant")
            .field("access_token", &"***")
            .field("account_id", &self.account_id)
            .field("email", &self.email)
            .field("expires_at", &self.expires_at)
            .field("source", &self.source)
            .finish()
    }
}

/// Failure class of [`get_access_token`], stable for bindings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessErrorKind {
    /// No account can serve: none configured, none matching, or every match
    /// disabled. A login is needed.
    AuthRequired,
    /// Every otherwise usable account is at or above the quota reserve.
    QuotaReserve,
    /// Every refreshable account's refresh token is dead or expired; a
    /// re-login is needed.
    InvalidGrant,
    /// The store or the request is unusable (unreadable store, bad option).
    Config,
    /// Retry later: rate limits, a refresh claim held elsewhere, transport
    /// errors, timeouts.
    Transient,
}

impl AccessErrorKind {
    /// The stable wire code (`auth_required`, `quota_reserve`,
    /// `invalid_grant`, `config`, `transient`).
    pub fn code(self) -> &'static str {
        match self {
            Self::AuthRequired => "auth_required",
            Self::QuotaReserve => "quota_reserve",
            Self::InvalidGrant => "invalid_grant",
            Self::Config => "config",
            Self::Transient => "transient",
        }
    }
}

/// A classified failure of [`get_access_token`]. The message is redacted.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{}: {message}", kind.code())]
pub struct AccessError {
    /// The failure class.
    pub kind: AccessErrorKind,
    /// Human-readable, secret-free detail.
    pub message: String,
}

impl AccessError {
    fn new(kind: AccessErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: crate::token::redact_secrets(&message.into()),
        }
    }

    /// Classify a crate error.
    pub fn from_error(error: &Error) -> Self {
        let kind = match error {
            Error::RefreshTokenRevoked { .. } | Error::RefreshTokenExpired => {
                AccessErrorKind::InvalidGrant
            }
            Error::NoUsableAccount(_) | Error::UnknownAccount(_) => AccessErrorKind::AuthRequired,
            Error::StoreIsSymlink
            | Error::InvalidJson { .. }
            | Error::Serde(_)
            | Error::WouldDeleteAllAccounts
            | Error::CustodyTombstone { .. }
            | Error::Config(_)
            | Error::Url(_) => AccessErrorKind::Config,
            other if other.is_invalid_grant() => AccessErrorKind::InvalidGrant,
            _ => AccessErrorKind::Transient,
        };
        Self::new(kind, error.to_string())
    }
}

/// Whether `account` answers to `selector` (id, email or label).
pub fn account_matches(account: &Account, selector: &str) -> bool {
    let selector = selector.trim();
    if selector.is_empty() {
        return false;
    }
    account.id == selector
        || account
            .email
            .as_deref()
            .is_some_and(|e| e.eq_ignore_ascii_case(selector))
        || account
            .oauth()
            .and_then(|t| t.account.as_ref())
            .and_then(|a| a.email_address.as_deref())
            .is_some_and(|e| e.eq_ignore_ascii_case(selector))
        || account
            .label
            .as_deref()
            .is_some_and(|l| l.eq_ignore_ascii_case(selector))
}

/// Whether a fresh quota reading puts `account` at or above
/// `reserve_percent` in either window. Stale or missing readings fail open.
pub fn at_quota_reserve(account: &Account, reserve_percent: f64, now: DateTime<Utc>) -> bool {
    let Some(quota) = &account.quota else {
        return false;
    };
    let Some(checked_at) = quota.checked_at else {
        return false;
    };
    if (now - checked_at).num_seconds() > QUOTA_OBSERVATION_MAX_AGE_SECS {
        return false;
    }
    [quota.five_hour_percent, quota.seven_day_percent]
        .into_iter()
        .flatten()
        .any(|p| p.is_finite() && p >= reserve_percent)
}

/// The candidate rows for `request`, in routing order, or the reason there
/// are none.
pub fn access_candidates<'a>(
    store: &'a AccountStore,
    request: &AccessRequest,
    now: DateTime<Utc>,
) -> Result<Vec<&'a Account>, AccessError> {
    if let Some(p) = request.reserve_percent
        && !(p.is_finite() && (0.0..=100.0).contains(&p))
    {
        return Err(AccessError::new(
            AccessErrorKind::Config,
            "reservePct must be between 0 and 100",
        ));
    }
    let matching: Vec<&Account> = store
        .accounts
        .iter()
        .filter(|a| {
            a.oauth()
                .is_some_and(|t| t.scopes.is_empty() || t.grants_inference())
        })
        .filter(|a| {
            request
                .account
                .as_deref()
                .is_none_or(|sel| account_matches(a, sel))
        })
        .filter(|a| {
            request.allowlist.is_empty() || request.allowlist.iter().any(|s| account_matches(a, s))
        })
        .collect();
    if matching.is_empty() {
        let what = match (&request.account, request.allowlist.is_empty()) {
            (Some(sel), _) => format!("no OAuth account matches {sel:?}"),
            (None, false) => "no OAuth account matches the allowlist".to_owned(),
            (None, true) => "no OAuth account in the shared store; log in first".to_owned(),
        };
        return Err(AccessError::new(AccessErrorKind::AuthRequired, what));
    }
    let enabled: Vec<&Account> = matching.iter().copied().filter(|a| a.enabled).collect();
    if enabled.is_empty() {
        return Err(AccessError::new(
            AccessErrorKind::AuthRequired,
            "every matching account is disabled",
        ));
    }
    let under_reserve: Vec<&Account> = match request.reserve_percent {
        Some(p) => enabled
            .iter()
            .copied()
            .filter(|a| !at_quota_reserve(a, p, now))
            .collect(),
        None => enabled.clone(),
    };
    if under_reserve.is_empty() {
        return Err(AccessError::new(
            AccessErrorKind::QuotaReserve,
            format!(
                "every matching account is at or above the {}% quota reserve",
                request.reserve_percent.unwrap_or_default()
            ),
        ));
    }
    let mut available: Vec<&Account> = under_reserve
        .iter()
        .copied()
        .filter(|a| a.is_available(now))
        .collect();
    if available.is_empty() {
        let quota_only = under_reserve.iter().all(|a| {
            matches!(
                a.unavailable_reason(now),
                Some(crate::Unavailable::QuotaExhausted(_))
            )
        });
        let soonest = under_reserve
            .iter()
            .filter_map(|a| a.rate_limited_until)
            .min();
        return Err(match (quota_only, soonest) {
            (true, _) => AccessError::new(
                AccessErrorKind::QuotaReserve,
                "every matching account has exhausted its plan window",
            ),
            (false, Some(until)) => AccessError::new(
                AccessErrorKind::Transient,
                format!("every matching account is rate-limited; the first frees up at {until}"),
            ),
            (false, None) => AccessError::new(
                AccessErrorKind::Transient,
                "no matching account is available right now",
            ),
        });
    }
    if let Some(current) = store.current.as_deref()
        && let Some(pos) = available.iter().position(|a| a.id == current)
    {
        let pinned = available.remove(pos);
        available.insert(0, pinned);
    }
    Ok(available)
}

fn grant(account: &Account, tokens: &crate::OAuthTokens, source: AccessSource) -> AccessGrant {
    AccessGrant {
        access_token: tokens.access.expose().to_owned(),
        account_id: account.id.clone(),
        email: account
            .email
            .clone()
            .or_else(|| tokens.account.as_ref()?.email_address.clone()),
        expires_at: tokens.expires_at,
        source,
    }
}

/// Resolve a usable access token from the store at `path`: the first
/// candidate with a live access token, else the first candidate that
/// refreshes (claimed, through the store), else a still-unexpired token that
/// was merely inside the refresh leeway.
pub async fn get_access_token(
    client: &OAuthClient,
    path: &Path,
    request: &AccessRequest,
    options: &SharedRefreshOptions,
) -> Result<AccessGrant, AccessError> {
    let now = Utc::now();
    let store = AccountStore::load_or_migrate_from(path, &[])
        .map_err(|e| AccessError::from_error(&e))?
        .store;
    let candidates = access_candidates(&store, request, now)?;

    for account in &candidates {
        if let Some(tokens) = account.oauth()
            && !tokens.access.expose().is_empty()
            && !tokens.needs_refresh(now)
        {
            return Ok(grant(account, tokens, AccessSource::Store));
        }
    }

    let mut errors: Vec<Error> = Vec::new();
    let mut refreshable = 0usize;
    for account in &candidates {
        let Some(tokens) = account.oauth() else {
            continue;
        };
        if refresh_exclusion(account, now).is_some() {
            continue;
        }
        refreshable += 1;
        match client.refresh_shared(path, tokens, options).await {
            Ok(outcome) => {
                let source = if outcome.source == RefreshSource::Refreshed {
                    AccessSource::Refreshed
                } else {
                    AccessSource::Adopted
                };
                let id = outcome
                    .account_id
                    .clone()
                    .unwrap_or_else(|| account.id.clone());
                let row = AccountStore::load_or_migrate_from(path, &[])
                    .ok()
                    .and_then(|l| l.store.get(&id).cloned())
                    .unwrap_or_else(|| (*account).clone());
                return Ok(AccessGrant {
                    account_id: id,
                    ..grant(&row, &outcome.tokens, source)
                });
            }
            Err(error) => errors.push(error),
        }
    }

    // Every refresh failed; a token merely inside the leeway still works.
    for account in &candidates {
        if let Some(tokens) = account.oauth()
            && !tokens.access.expose().is_empty()
            && !tokens.is_expired(now)
        {
            return Ok(grant(account, tokens, AccessSource::Store));
        }
    }

    if refreshable == 0 {
        return Err(AccessError::new(
            AccessErrorKind::InvalidGrant,
            "no matching account holds a usable refresh token (dead, expired or missing); \
             re-login is required",
        ));
    }
    let classes: Vec<RefreshFailure> = errors.iter().map(classify_refresh_failure).collect();
    if classes.iter().all(|c| *c == RefreshFailure::Revoked) {
        return Err(AccessError::new(
            AccessErrorKind::InvalidGrant,
            format!(
                "every matching account's refresh token is revoked or expired; re-login is required ({})",
                errors.first().map(ToString::to_string).unwrap_or_default()
            ),
        ));
    }
    // A configuration refusal (OAuth test mode and a non-loopback token URL)
    // will not heal with time: report it as `config`, not `transient`.
    if let Some(config) = errors.iter().find(|e| matches!(e, Error::Config(_))) {
        return Err(AccessError::from_error(config));
    }
    let transient = errors
        .iter()
        .find(|e| classify_refresh_failure(e) != RefreshFailure::Revoked)
        .map(AccessError::from_error)
        .map(|mut e| {
            e.kind = AccessErrorKind::Transient;
            e
        });
    Err(transient.unwrap_or_else(|| {
        AccessError::new(AccessErrorKind::Transient, "no account could be refreshed")
    }))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use chrono::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;
    use crate::account::QuotaObservation;
    use crate::endpoints::Endpoints;
    use crate::token::{AccessToken, Credential, OAuthTokens, RefreshToken};

    async fn token_server(status: u16, body: &'static str) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let counter = counter.clone();
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
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
                                break;
                            }
                        }
                    }
                    counter.fetch_add(1, Ordering::SeqCst);
                    let response = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        (format!("http://{address}/v1/oauth/token"), hits)
    }

    const ROTATED: &str = r#"{"access_token":"sk-ant-oat01-rotatedrotatedrotated00","refresh_token":"sk-ant-ort01-rotatedrotatedrotated00","expires_in":28800,"scope":"user:inference user:profile"}"#;
    const INVALID_GRANT: &str = r#"{"error":"invalid_grant"}"#;

    fn client(url: &str) -> OAuthClient {
        let mut endpoints = Endpoints::prod();
        endpoints.token_url = url.to_owned();
        OAuthClient::new(endpoints)
    }

    fn row(id: &str, access_in: Duration) -> Account {
        let mut account = Account::new(
            id,
            Credential::Oauth(OAuthTokens {
                access: AccessToken::new(format!("sk-ant-oat01-{id}-aaaaaaaaaaaaaaaaaa")),
                refresh: RefreshToken::new(format!("sk-ant-ort01-{id}-aaaaaaaaaaaaaaaaaa")),
                expires_at: Utc::now() + access_in,
                refresh_expires_at: Some(Utc::now() + Duration::days(20)),
                scopes: vec!["user:inference".into()],
                account: None,
                organization: None,
            }),
        );
        account.email = Some(format!("{id}@example.com"));
        account
    }

    fn store_at(tag: &str, accounts: Vec<Account>) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "anthropic-access-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("accounts.json");
        AccountStore {
            accounts,
            ..AccountStore::default()
        }
        .save(&path)
        .unwrap();
        path
    }

    /// Unit tests run in OAuth test mode: an expired seed against the
    /// production token URL is a `config` failure, the token is not spent,
    /// and the row is left as it was.
    #[tokio::test]
    async fn test_mode_refuses_a_production_refresh_as_config() {
        let path = store_at("testmode", vec![row("a", Duration::hours(-1))]);
        let error = get_access_token(
            &OAuthClient::new(Endpoints::prod()),
            &path,
            &AccessRequest::default(),
            &SharedRefreshOptions::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind, AccessErrorKind::Config, "{error}");
        let stored = AccountStore::load_or_migrate_from(&path, &[])
            .unwrap()
            .store;
        let a = stored.get("a").unwrap();
        assert_eq!(
            a.oauth().unwrap().refresh.expose(),
            "sk-ant-ort01-a-aaaaaaaaaaaaaaaaaa"
        );
        assert!(!a.refresh_token_is_dead());
    }

    #[tokio::test]
    async fn a_live_token_is_used_without_any_refresh() {
        let (url, hits) = token_server(200, ROTATED).await;
        let path = store_at("live", vec![row("a", Duration::hours(2))]);
        let grant = get_access_token(
            &client(&url),
            &path,
            &AccessRequest::default(),
            &SharedRefreshOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(grant.source, AccessSource::Store);
        assert_eq!(grant.account_id, "a");
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        assert!(!format!("{grant:?}").contains("sk-ant"));
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[tokio::test]
    async fn an_expired_token_is_refreshed_and_persisted() {
        let (url, hits) = token_server(200, ROTATED).await;
        let path = store_at("refresh", vec![row("a", Duration::hours(-1))]);
        let grant = get_access_token(
            &client(&url),
            &path,
            &AccessRequest::default(),
            &SharedRefreshOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(grant.source, AccessSource::Refreshed);
        assert_eq!(grant.access_token, "sk-ant-oat01-rotatedrotatedrotated00");
        assert_eq!(grant.email.as_deref(), Some("a@example.com"));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        let stored = AccountStore::load(&path).unwrap();
        assert_eq!(
            stored.get("a").unwrap().oauth().unwrap().refresh.expose(),
            "sk-ant-ort01-rotatedrotatedrotated00"
        );
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[tokio::test]
    async fn a_dead_login_rotates_to_the_next_and_all_dead_is_invalid_grant() {
        let (url, hits) = token_server(400, INVALID_GRANT).await;
        let path = store_at(
            "dead",
            vec![row("a", Duration::hours(-1)), row("b", Duration::hours(2))],
        );
        // `a` is expired and dead; `b` is live: `b` serves.
        let grant = get_access_token(
            &client(&url),
            &path,
            &AccessRequest::default(),
            &SharedRefreshOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(grant.account_id, "b");
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        // Only `a` allowed: its refresh is rejected -> invalid_grant.
        let error = get_access_token(
            &client(&url),
            &path,
            &AccessRequest {
                account: Some("a@example.com".into()),
                ..AccessRequest::default()
            },
            &SharedRefreshOptions::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind, AccessErrorKind::InvalidGrant, "{error}");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        // The second ask never reaches the endpoint.
        let again = get_access_token(
            &client(&url),
            &path,
            &AccessRequest {
                allowlist: vec!["a".into()],
                ..AccessRequest::default()
            },
            &SharedRefreshOptions::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(again.kind, AccessErrorKind::InvalidGrant);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn candidates_honour_allowlist_reserve_and_the_pin() {
        let now = Utc::now();
        let mut spent = row("spent", Duration::hours(2));
        spent.quota = Some(QuotaObservation {
            five_hour_percent: Some(95.0),
            seven_day_percent: Some(10.0),
            checked_at: Some(now),
        });
        let mut store = AccountStore {
            accounts: vec![
                row("a", Duration::hours(2)),
                row("b", Duration::hours(2)),
                spent,
            ],
            ..AccountStore::default()
        };
        store.current = Some("b".into());
        let ids = |r: &AccessRequest| -> Vec<String> {
            access_candidates(&store, r, now)
                .unwrap()
                .iter()
                .map(|a| a.id.clone())
                .collect()
        };
        assert_eq!(ids(&AccessRequest::default()), ["b", "a", "spent"]);
        assert_eq!(
            ids(&AccessRequest {
                reserve_percent: Some(90.0),
                ..AccessRequest::default()
            }),
            ["b", "a"]
        );
        let only_spent = AccessRequest {
            allowlist: vec!["SPENT@example.com".into()],
            reserve_percent: Some(90.0),
            ..AccessRequest::default()
        };
        assert_eq!(
            access_candidates(&store, &only_spent, now)
                .unwrap_err()
                .kind,
            AccessErrorKind::QuotaReserve
        );
        let nobody = AccessRequest {
            account: Some("ghost".into()),
            ..AccessRequest::default()
        };
        assert_eq!(
            access_candidates(&store, &nobody, now).unwrap_err().kind,
            AccessErrorKind::AuthRequired
        );
        let bad = AccessRequest {
            reserve_percent: Some(150.0),
            ..AccessRequest::default()
        };
        assert_eq!(
            access_candidates(&store, &bad, now).unwrap_err().kind,
            AccessErrorKind::Config
        );
        assert_eq!(
            access_candidates(&AccountStore::default(), &AccessRequest::default(), now)
                .unwrap_err()
                .kind,
            AccessErrorKind::AuthRequired
        );
    }
}
