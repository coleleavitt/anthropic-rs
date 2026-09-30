//! Node-API binding over the `anthropic` shared account store.
//!
//! The surface is coarse and asynchronous: a host asks for an access token
//! and gets one, with selection, reserve, refresh, adoption and rotation done
//! in Rust under the store's locks and claims. **Refresh tokens never cross
//! into JavaScript**: no return value carries one, and the only entry point
//! that accepts one ([`AnthropicAuth::import_oauth_account`]) moves it the
//! other way, into the store.
//!
//! Errors are thrown as JavaScript `Error`s whose message starts with one of
//! the codes `auth_required`, `quota_reserve`, `invalid_grant`, `config`,
//! `transient` (`"<code>: <detail>"`). The package loader (`index.js`)
//! rethrows them as `AnthropicAuthError` with the code on `.code`; napi's
//! async functions only carry the generic status, so the code travels in the
//! message.

// `deny`, not `forbid`: the `#[napi]` expansions carry their own
// `allow(unsafe_code)` for the N-API FFI glue. Hand-written code here has no
// `unsafe`.
#![deny(unsafe_code)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anthropic::access::{AccessErrorKind, AccessRequest, AccessSource};
use anthropic::keepalive::{
    KeepAliveLeaseOutcome,
    KeepAliveOptions,
    KeepAliveReason,
    KeepAliveSkip,
};
use anthropic::refresh::{RefreshFailure, SharedRefreshOptions};
use anthropic::{
    Account,
    AccountStore,
    Credential,
    Endpoints,
    OAuthClient,
    OAuthTokens,
    PkceVerifier,
    token,
};
use chrono::{DateTime, TimeZone, Utc};
use napi_derive::napi;

fn fail(kind: AccessErrorKind, message: impl AsRef<str>) -> napi::Error {
    napi::Error::new(
        napi::Status::GenericFailure,
        format!(
            "{}: {}",
            kind.code(),
            token::redact_secrets(message.as_ref())
        ),
    )
}

fn from_crate(error: &anthropic::Error) -> napi::Error {
    let classified = anthropic::access::AccessError::from_error(error);
    fail(classified.kind, classified.message)
}

fn config(message: impl AsRef<str>) -> napi::Error {
    fail(AccessErrorKind::Config, message)
}

fn ms(at: DateTime<Utc>) -> i64 {
    at.timestamp_millis()
}

fn from_ms(value: i64, field: &str) -> napi::Result<DateTime<Utc>> {
    Utc.timestamp_millis_opt(value).single().ok_or_else(|| {
        config(format!(
            "{field} is not a valid epoch-millisecond timestamp"
        ))
    })
}

/// Run blocking store I/O (file locks that may wait) off the event loop.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> napi::Result<T> + Send + 'static,
) -> napi::Result<T> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|e| fail(AccessErrorKind::Transient, format!("worker failed: {e}")))?
}

/// Where the binding reads and writes, and which endpoints it talks to. Every
/// field is optional; the defaults are the shared store
/// (`$ANTHROPIC_ACCOUNTS_FILE`, `$ANTHROPIC_ACCOUNTS_DIR/accounts.json`, else
/// `~/.anthropic-accounts/accounts.json`) and the production endpoints.
#[napi(object)]
#[derive(Default)]
pub struct AuthConfig {
    /// Store file path.
    pub store_path: Option<String>,
    /// OAuth token endpoint (tests point this at a mock server).
    pub token_url: Option<String>,
    /// Claude.ai authorize URL.
    pub authorize_url: Option<String>,
    /// Console authorize URL (login `mode: "console"`).
    pub console_authorize_url: Option<String>,
    /// OAuth redirect URI.
    pub redirect_uri: Option<String>,
    /// OAuth client id.
    pub client_id: Option<String>,
}

/// Quota reading, as percentages (0–100).
#[napi(object)]
pub struct QuotaInfo {
    /// Five-hour window utilisation.
    pub five_hour_percent: Option<f64>,
    /// Seven-day window utilisation.
    pub seven_day_percent: Option<f64>,
    /// When it was read (epoch ms).
    pub checked_at: Option<i64>,
}

/// One store row, non-secret fields only.
#[napi(object)]
pub struct AccountInfo {
    /// Store id.
    pub id: String,
    /// Display label.
    pub label: Option<String>,
    /// Account email.
    pub email: Option<String>,
    /// `"oauth"` or `"api_key"`.
    pub kind: String,
    /// Whether it participates in routing.
    pub enabled: bool,
    /// Whether it is the store's pinned `current` account.
    pub current: bool,
    /// Whether it can serve right now (enabled, not cooling down, not
    /// exhausted).
    pub available: bool,
    /// Whether its access token is live.
    pub access_live: bool,
    /// Access-token expiry (epoch ms).
    pub expires_at: Option<i64>,
    /// Refresh-token expiry, when known (epoch ms).
    pub refresh_expires_at: Option<i64>,
    /// Whether its current refresh token is recorded dead (re-login needed).
    pub refresh_dead: bool,
    /// The last error, only while it still describes the current token.
    pub last_error: Option<String>,
    /// Rate-limit cooldown end (epoch ms).
    pub rate_limited_until: Option<i64>,
    /// Last use (epoch ms).
    pub last_used_at: Option<i64>,
    /// Last successful refresh by a crate writer (epoch ms).
    pub last_refreshed_at: Option<i64>,
    /// Last quota reading.
    pub quota: Option<QuotaInfo>,
    /// Anthropic account uuid.
    pub account_uuid: Option<String>,
    /// Organization uuid.
    pub organization_uuid: Option<String>,
    /// Granted scopes.
    pub scopes: Vec<String>,
}

fn account_info(store: &AccountStore, account: &Account, now: DateTime<Utc>) -> AccountInfo {
    let tokens = account.oauth();
    AccountInfo {
        id: account.id.clone(),
        label: account.label.clone(),
        email: account
            .email
            .clone()
            .or_else(|| tokens?.account.as_ref()?.email_address.clone()),
        kind: match account.credential {
            Credential::Oauth(_) => "oauth".into(),
            Credential::ApiKey { .. } => "api_key".into(),
        },
        enabled: account.enabled,
        current: store.current.as_deref() == Some(account.id.as_str()),
        available: account.is_available(now),
        access_live: account.oauth_credential_is_live(now),
        expires_at: tokens.map(|t| ms(t.expires_at)),
        refresh_expires_at: tokens.and_then(|t| t.refresh_expires_at).map(ms),
        refresh_dead: account.refresh_token_is_dead(),
        last_error: account.current_error().map(str::to_owned),
        rate_limited_until: account.rate_limited_until.map(ms),
        last_used_at: account.last_used_at.map(ms),
        last_refreshed_at: account.last_refreshed_at.map(ms),
        quota: account.quota.as_ref().map(|q| QuotaInfo {
            five_hour_percent: q.five_hour_percent,
            seven_day_percent: q.seven_day_percent,
            checked_at: q.checked_at.map(ms),
        }),
        account_uuid: tokens
            .and_then(|t| t.account.as_ref())
            .map(|a| a.uuid.clone()),
        organization_uuid: tokens
            .and_then(|t| t.organization.as_ref())
            .map(|o| o.uuid.clone()),
        scopes: tokens.map(|t| t.scopes.clone()).unwrap_or_default(),
    }
}

/// Options for [`AnthropicAuth::get_access_token`].
#[napi(object)]
#[derive(Default)]
pub struct GetAccessTokenOptions {
    /// Use only this account (id, email or label).
    pub account: Option<String>,
    /// Consider only these accounts (ids, emails or labels).
    pub allowlist: Option<Vec<String>>,
    /// Skip accounts whose fresh quota reading is at or above this
    /// percentage (0–100) in either window.
    pub reserve_pct: Option<f64>,
}

/// A usable bearer. There is deliberately no refresh token here.
#[napi(object)]
pub struct AccessToken {
    /// Send as `Authorization: Bearer <accessToken>`.
    pub access_token: String,
    /// Store row it belongs to.
    pub account_id: String,
    /// Account email, when known.
    pub email: Option<String>,
    /// Access-token expiry (epoch ms).
    pub expires_at: i64,
    /// `"store"`, `"refreshed"` or `"adopted"`.
    pub source: String,
}

fn access_token_of(grant: anthropic::access::AccessGrant) -> AccessToken {
    AccessToken {
        access_token: grant.access_token,
        account_id: grant.account_id,
        email: grant.email,
        expires_at: ms(grant.expires_at),
        source: match grant.source {
            AccessSource::Store => "store",
            AccessSource::Refreshed => "refreshed",
            AccessSource::Adopted => "adopted",
        }
        .into(),
    }
}

/// Options for [`AnthropicAuth::mark_rate_limited`].
#[napi(object)]
pub struct MarkRateLimitedOptions {
    /// Store row.
    pub account_id: String,
    /// Cooldown end (epoch ms). Takes precedence over `retryAfterMs`.
    pub until: Option<i64>,
    /// Cooldown length from now, in ms (from `retry-after`).
    pub retry_after_ms: Option<i64>,
}

/// Options for [`AnthropicAuth::record_quota`].
#[napi(object)]
pub struct RecordQuotaOptions {
    /// Store row. Either this or `accessToken` identifies the account.
    pub account_id: Option<String>,
    /// The access token the reading was taken with (attributes the reading
    /// to exactly the row holding it).
    pub access_token: Option<String>,
    /// Five-hour window utilisation (0–100).
    pub five_hour_percent: Option<f64>,
    /// Seven-day window utilisation (0–100).
    pub seven_day_percent: Option<f64>,
    /// When it was read (epoch ms); defaults to now.
    pub checked_at: Option<i64>,
}

/// Options for [`AnthropicAuth::record_quota_headers`].
#[napi(object)]
pub struct RecordQuotaHeadersOptions {
    /// The access token the response was obtained with.
    pub access_token: String,
    /// Response headers (names case-insensitive).
    pub headers: HashMap<String, String>,
}

/// Options for [`AnthropicAuth::keep_alive_once`].
#[napi(object)]
#[derive(Default)]
pub struct KeepAliveOnceOptions {
    /// Refresh when the refresh token expires within this many days
    /// (default 7).
    pub threshold_days: Option<f64>,
    /// Pause between refreshes in ms (default 2000, jittered).
    pub spacing_ms: Option<u32>,
}

/// One account in a keep-alive report.
#[napi(object)]
pub struct KeepAliveEntry {
    /// Store row.
    pub account_id: String,
    /// Why it was refreshed / skipped, or the failure class.
    pub reason: String,
    /// Redacted failure detail.
    pub message: Option<String>,
}

/// Result of [`AnthropicAuth::keep_alive_once`]. Ids and verdicts only.
#[napi(object)]
pub struct KeepAliveResult {
    /// `"acquired"` (this pass did the work), `"held"` (another pass holds
    /// the machine-wide lease; nothing done) or `"no_store"`.
    pub lease: String,
    /// When the other pass's lease lapses (epoch ms), for `"held"`.
    pub held_until: Option<i64>,
    /// Accounts refreshed (one token spent each).
    pub refreshed: Vec<KeepAliveEntry>,
    /// Accounts a peer had already rotated.
    pub adopted: Vec<String>,
    /// Accounts whose refresh failed.
    pub failed: Vec<KeepAliveEntry>,
    /// Accounts left alone, and why.
    pub skipped: Vec<KeepAliveEntry>,
}

/// Options for [`AnthropicAuth::start_login`].
#[napi(object)]
#[derive(Default)]
pub struct StartLoginOptions {
    /// `"max"` (Claude.ai subscription, default) or `"console"`.
    pub mode: Option<String>,
    /// Pre-fill the login email.
    pub login_hint: Option<String>,
}

/// A login in progress. The PKCE verifier stays in Rust.
#[napi(object)]
pub struct LoginStart {
    /// Open this in a browser.
    pub url: String,
    /// The anti-CSRF state the redirect must echo.
    pub state: String,
    /// Pass to `completeLogin`.
    pub login_id: String,
}

/// Options for [`AnthropicAuth::complete_login`].
#[napi(object)]
pub struct CompleteLoginOptions {
    /// From `startLogin`.
    pub login_id: String,
    /// What the user pasted or the loopback received: `code#state`, the full
    /// redirect URL, a `code=…&state=…` query, or the bare code.
    pub callback: String,
    /// Label for the account (also used as its id when given).
    pub label: Option<String>,
    /// Pin it as the store's `current` account (default: only when nothing
    /// is pinned yet).
    pub set_current: Option<bool>,
}

/// Options for [`AnthropicAuth::import_oauth_account`].
#[napi(object)]
pub struct ImportOAuthAccountOptions {
    /// Label (and preferred id).
    pub label: Option<String>,
    /// Access token.
    pub access_token: String,
    /// Refresh token. Moves into the store; it is never returned.
    pub refresh_token: String,
    /// Access-token expiry (epoch ms).
    pub expires_at: i64,
    /// Refresh-token expiry (epoch ms), when known.
    pub refresh_expires_at: Option<i64>,
    /// Granted scopes.
    pub scopes: Option<Vec<String>>,
    /// Anthropic account uuid.
    pub account_uuid: Option<String>,
    /// Account email.
    pub email: Option<String>,
    /// Organization uuid.
    pub organization_uuid: Option<String>,
}

/// Result of [`AnthropicAuth::import_oauth_account`].
#[napi(object)]
pub struct ImportResult {
    /// The row that holds the login now.
    pub account_id: String,
    /// `"added"` (new row), `"already_present"` (the store holds this exact
    /// token) or `"kept"` (the store already holds this login with its own
    /// token; the store's copy wins and the import is discarded).
    pub status: String,
}

/// Options for [`AnthropicAuth::handle_unauthorized`].
#[napi(object)]
pub struct HandleUnauthorizedOptions {
    /// The access token the upstream answered 401 to.
    pub access_token: String,
}

/// Result of [`AnthropicAuth::handle_unauthorized`].
#[napi(object)]
pub struct UnauthorizedResult {
    /// Whether to re-send once with `token`.
    pub retry: bool,
    /// Why (safe to log).
    pub reason: String,
    /// The replacement bearer, when `retry`.
    pub token: Option<AccessToken>,
    /// The failure code, when re-authorization itself failed.
    pub failure_code: Option<String>,
}

struct PendingLogin {
    verifier: PkceVerifier,
    state: String,
    endpoints: Endpoints,
    started: Instant,
}

const LOGIN_TTL: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// A handle on one shared store.
#[napi]
pub struct AnthropicAuth {
    path: PathBuf,
    endpoints: Endpoints,
    console_authorize_url: String,
    logins: Arc<Mutex<HashMap<String, PendingLogin>>>,
}

impl AnthropicAuth {
    fn client(&self) -> OAuthClient {
        OAuthClient::new(self.endpoints.clone())
    }
}

#[napi]
impl AnthropicAuth {
    /// Open the store at `options.storePath` (default: the shared store).
    /// Validates the configuration; nothing is read until a method runs.
    #[napi(constructor)]
    pub fn new(options: Option<AuthConfig>) -> napi::Result<Self> {
        let cfg = options.unwrap_or_default();
        let path = match cfg.store_path.as_deref().map(str::trim) {
            Some("") => return Err(config_error("storePath is empty")),
            Some(path) => PathBuf::from(path),
            None => anthropic::default_store_path(),
        };
        let mut endpoints = Endpoints::from_env();
        let mut console_authorize_url = Endpoints::console().authorize_url;
        for (value, slot) in [
            (cfg.token_url, &mut endpoints.token_url),
            (cfg.authorize_url, &mut endpoints.authorize_url),
            (cfg.console_authorize_url, &mut console_authorize_url),
            (cfg.redirect_uri, &mut endpoints.redirect_uri),
            (cfg.client_id, &mut endpoints.client_id),
        ] {
            if let Some(value) = value {
                let value = value.trim().to_owned();
                if value.is_empty() {
                    return Err(config_error("an endpoint override is empty"));
                }
                *slot = value;
            }
        }
        for url in [
            &endpoints.token_url,
            &endpoints.authorize_url,
            &console_authorize_url,
        ] {
            url::Url::parse(url).map_err(|e| config(format!("invalid endpoint url: {e}")))?;
        }
        Ok(Self {
            path,
            endpoints,
            console_authorize_url,
            logins: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// The store file this handle uses.
    #[napi(getter)]
    pub fn store_path(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }

    /// Every row, non-secret fields only.
    #[napi]
    pub async fn list_accounts(&self) -> napi::Result<Vec<AccountInfo>> {
        let path = self.path.clone();
        blocking(move || {
            let store = AccountStore::load_or_migrate_from(&path, &[])
                .map_err(|e| from_crate(&e))?
                .store;
            let now = Utc::now();
            Ok(store
                .accounts
                .iter()
                .map(|a| account_info(&store, a, now))
                .collect())
        })
        .await
    }

    /// A usable access token: the first candidate whose token is live, else
    /// the first that refreshes (claimed, through the store), rotating past
    /// accounts that fail.
    #[napi]
    pub async fn get_access_token(
        &self,
        options: Option<GetAccessTokenOptions>,
    ) -> napi::Result<AccessToken> {
        let options = options.unwrap_or_default();
        let request = AccessRequest {
            account: options.account,
            allowlist: options.allowlist.unwrap_or_default(),
            reserve_percent: options.reserve_pct,
        };
        anthropic::access::get_access_token(
            &self.client(),
            &self.path,
            &request,
            &SharedRefreshOptions::default(),
        )
        .await
        .map(access_token_of)
        .map_err(|e| fail(e.kind, e.message))
    }

    /// Put an account into a rate-limit cooldown (and unpin it). Returns
    /// whether the account exists.
    #[napi]
    pub async fn mark_rate_limited(&self, options: MarkRateLimitedOptions) -> napi::Result<bool> {
        let until = match (options.until, options.retry_after_ms) {
            (Some(until), _) => from_ms(until, "until")?,
            (None, Some(after)) if after >= 0 => Utc::now() + chrono::Duration::milliseconds(after),
            _ => {
                return Err(config(
                    "markRateLimited needs `until` or a non-negative `retryAfterMs`",
                ));
            }
        };
        let path = self.path.clone();
        blocking(move || {
            AccountStore::mutate(&path, |store| {
                let Ok(account) = store.get_mut(&options.account_id) else {
                    return Ok(false);
                };
                account.mark_rate_limited(until);
                if store.current.as_deref() == Some(options.account_id.as_str()) {
                    store.current = None;
                }
                Ok(true)
            })
            .map_err(|e| from_crate(&e))
        })
        .await
    }

    /// Record a quota reading. Returns the account id it landed on, or null
    /// when no row matched or the reading had no percentage.
    #[napi]
    pub async fn record_quota(&self, options: RecordQuotaOptions) -> napi::Result<Option<String>> {
        let checked_at = match options.checked_at {
            Some(at) => from_ms(at, "checkedAt")?,
            None => Utc::now(),
        };
        let path = self.path.clone();
        blocking(move || {
            AccountStore::mutate(&path, |store| {
                Ok(match (&options.account_id, &options.access_token) {
                    (Some(id), _) => store
                        .record_quota(
                            id,
                            options.five_hour_percent,
                            options.seven_day_percent,
                            checked_at,
                        )
                        .then(|| id.clone()),
                    (None, Some(access)) => store.record_quota_for_access_token(
                        access,
                        options.five_hour_percent,
                        options.seven_day_percent,
                        checked_at,
                    ),
                    (None, None) => None,
                })
            })
            .map_err(|e| from_crate(&e))
        })
        .await
    }

    /// Record the unified rate-limit headers of a Messages response against
    /// the row holding `accessToken`. Returns the account id, or null.
    #[napi]
    pub async fn record_quota_headers(
        &self,
        options: RecordQuotaHeadersOptions,
    ) -> napi::Result<Option<String>> {
        let path = self.path.clone();
        blocking(move || {
            let now = Utc::now();
            let pairs: Vec<(String, String)> = options.headers.into_iter().collect();
            let snapshot = anthropic::normalize_quota_headers(&pairs, now.timestamp_millis());
            AccountStore::mutate(&path, |store| {
                Ok(store.record_quota_snapshot_for_access_token(
                    &options.access_token,
                    &snapshot,
                    now,
                ))
            })
            .map_err(|e| from_crate(&e))
        })
        .await
    }

    /// Record a successful use. Returns whether the account exists.
    #[napi]
    pub async fn mark_used(&self, account_id: String) -> napi::Result<bool> {
        self.update_row(account_id, |account| account.mark_used(Utc::now()))
            .await
    }

    /// Enable or disable an account. Returns whether it exists.
    #[napi]
    pub async fn set_account_enabled(
        &self,
        account_id: String,
        enabled: bool,
    ) -> napi::Result<bool> {
        let path = self.path.clone();
        blocking(move || {
            AccountStore::mutate(&path, |store| {
                let Ok(account) = store.get_mut(&account_id) else {
                    return Ok(false);
                };
                if enabled {
                    account.enabled = true;
                } else {
                    account.enabled = false;
                    if store.current.as_deref() == Some(account_id.as_str()) {
                        store.current = None;
                    }
                }
                Ok(true)
            })
            .map_err(|e| from_crate(&e))
        })
        .await
    }

    /// Remove an account (the final one too). Returns whether it existed.
    #[napi]
    pub async fn remove_account(&self, account_id: String) -> napi::Result<bool> {
        let path = self.path.clone();
        blocking(move || {
            AccountStore::mutate_allow_empty(&path, |store| Ok(store.remove(&account_id)))
                .map_err(|e| from_crate(&e))
        })
        .await
    }

    /// Reorder rows: the listed ids first, in order, then the rest.
    #[napi]
    pub async fn reorder_accounts(&self, ordered_ids: Vec<String>) -> napi::Result<()> {
        let path = self.path.clone();
        blocking(move || {
            AccountStore::mutate(&path, |store| {
                let mut rest = std::mem::take(&mut store.accounts);
                let mut ordered = Vec::with_capacity(rest.len());
                for id in &ordered_ids {
                    if let Some(pos) = rest.iter().position(|a| &a.id == id) {
                        ordered.push(rest.remove(pos));
                    }
                }
                ordered.extend(rest);
                store.accounts = ordered;
                Ok(())
            })
            .map_err(|e| from_crate(&e))
        })
        .await
    }

    /// Pin the preferred account.
    #[napi]
    pub async fn set_current(&self, account_id: String) -> napi::Result<()> {
        let path = self.path.clone();
        blocking(move || {
            AccountStore::mutate(&path, |store| store.set_current(&account_id))
                .map_err(|e| from_crate(&e))
        })
        .await
    }

    /// One keep-alive pass over idle accounts (machine-wide single owner).
    #[napi]
    pub async fn keep_alive_once(
        &self,
        options: Option<KeepAliveOnceOptions>,
    ) -> napi::Result<KeepAliveResult> {
        let options = options.unwrap_or_default();
        let mut keepalive = KeepAliveOptions::default();
        if let Some(days) = options.threshold_days {
            if !(days.is_finite() && days > 0.0) {
                return Err(config("thresholdDays must be a positive number"));
            }
            keepalive.refresh_expiry_threshold =
                chrono::Duration::milliseconds((days * 86_400_000.0) as i64);
        }
        if let Some(spacing) = options.spacing_ms {
            keepalive.spacing = std::time::Duration::from_millis(u64::from(spacing));
        }
        let report = self
            .client()
            .keep_alive_once(&self.path, Utc::now(), &keepalive)
            .await
            .map_err(|e| from_crate(&e))?;
        let (lease, held_until) = match report.lease {
            KeepAliveLeaseOutcome::Acquired => ("acquired", None),
            KeepAliveLeaseOutcome::Held { until, .. } => ("held", Some(ms(until))),
            KeepAliveLeaseOutcome::NoStore => ("no_store", None),
        };
        Ok(KeepAliveResult {
            lease: lease.into(),
            held_until,
            refreshed: report
                .refreshed
                .into_iter()
                .map(|(account_id, reason)| KeepAliveEntry {
                    account_id,
                    reason: reason_code(reason).into(),
                    message: None,
                })
                .collect(),
            adopted: report.adopted,
            failed: report
                .failed
                .into_iter()
                .map(|f| KeepAliveEntry {
                    account_id: f.account_id,
                    reason: match f.failure {
                        RefreshFailure::Revoked => "invalid_grant",
                        RefreshFailure::Refused | RefreshFailure::Error => "transient",
                    }
                    .into(),
                    message: Some(f.message),
                })
                .collect(),
            skipped: report
                .skipped
                .into_iter()
                .map(|(account_id, skip)| KeepAliveEntry {
                    account_id,
                    reason: skip_code(skip).into(),
                    message: None,
                })
                .collect(),
        })
    }

    /// Begin an OAuth PKCE login. The verifier stays in this process.
    #[napi]
    pub fn start_login(&self, options: Option<StartLoginOptions>) -> napi::Result<LoginStart> {
        let options = options.unwrap_or_default();
        let mut endpoints = self.endpoints.clone();
        match options.mode.as_deref() {
            None | Some("max") => {}
            Some("console") => endpoints.authorize_url = self.console_authorize_url.clone(),
            Some(other) => return Err(config(format!("unknown login mode {other:?}"))),
        }
        let login = anthropic::start_login(&endpoints).map_err(|e| from_crate(&e))?;
        let mut url = login.authorize_url;
        if let Some(hint) = options
            .login_hint
            .as_deref()
            .map(str::trim)
            .filter(|h| !h.is_empty())
        {
            url.query_pairs_mut().append_pair("login_hint", hint);
        }
        let login_id = uuid::Uuid::new_v4().to_string();
        let mut logins = self
            .logins
            .lock()
            .map_err(|_| fail(AccessErrorKind::Transient, "login table poisoned"))?;
        logins.retain(|_, pending| pending.started.elapsed() < LOGIN_TTL);
        logins.insert(
            login_id.clone(),
            PendingLogin {
                verifier: login.verifier,
                state: login.state.clone(),
                endpoints,
                started: Instant::now(),
            },
        );
        Ok(LoginStart {
            url: url.to_string(),
            state: login.state,
            login_id,
        })
    }

    /// Finish a login: verify the state, exchange the code, and store the
    /// account (updating the same login in place when it already exists).
    #[napi]
    pub async fn complete_login(&self, options: CompleteLoginOptions) -> napi::Result<AccountInfo> {
        let pending = self
            .logins
            .lock()
            .map_err(|_| fail(AccessErrorKind::Transient, "login table poisoned"))?
            .remove(&options.login_id)
            .filter(|p| p.started.elapsed() < LOGIN_TTL)
            .ok_or_else(|| {
                fail(
                    AccessErrorKind::AuthRequired,
                    "unknown or expired login; start a new one",
                )
            })?;
        let (code, state) = parse_callback(&options.callback, &pending.state)?;
        let code = anthropic::parse_redirect_code(&format!("{code}#{state}"), &pending.state)
            .map_err(|e| from_crate(&e))?;
        let client = OAuthClient::new(pending.endpoints);
        let tokens = client
            .exchange_code(&code, &pending.verifier, &pending.state)
            .await
            .map_err(|e| from_crate(&e))?;
        let label = options
            .label
            .map(|l| l.trim().to_owned())
            .filter(|l| !l.is_empty());
        let set_current = options.set_current;
        let path = self.path.clone();
        blocking(move || store_login(&path, tokens, label, set_current)).await
    }

    /// Move an OAuth credential a host still holds into the store (one-time
    /// migration). The store is the custodian: when it already holds this
    /// login, its copy wins and the import is discarded.
    #[napi(js_name = "importOAuthAccount")]
    pub async fn import_oauth_account(
        &self,
        options: ImportOAuthAccountOptions,
    ) -> napi::Result<ImportResult> {
        if !token::is_valid_access_token(&options.access_token)
            || !token::is_valid_refresh_token(&options.refresh_token)
        {
            return Err(config(
                "importOAuthAccount needs a well-formed access and refresh token",
            ));
        }
        let tokens = OAuthTokens {
            access: token::AccessToken::new(options.access_token),
            refresh: token::RefreshToken::new(options.refresh_token),
            expires_at: from_ms(options.expires_at, "expiresAt")?,
            refresh_expires_at: options
                .refresh_expires_at
                .map(|at| from_ms(at, "refreshExpiresAt"))
                .transpose()?,
            scopes: options.scopes.unwrap_or_default(),
            account: options.account_uuid.map(|uuid| token::TokenAccount {
                uuid,
                email_address: options.email.clone(),
            }),
            organization: options
                .organization_uuid
                .map(|uuid| token::TokenOrganization { uuid }),
        };
        let label = options.label.filter(|l| !l.trim().is_empty());
        let email = options.email;
        let path = self.path.clone();
        blocking(move || {
            let status = AccountStore::mutate(&path, |store| {
                if let Some(existing) = store.find_by_refresh_token(&tokens.refresh) {
                    return Ok(("already_present", existing.id.clone()));
                }
                let mut candidate = Account::new(
                    preferred_id(store, &tokens, label.as_deref()),
                    Credential::Oauth(tokens.clone()),
                );
                candidate.label = label.clone();
                if email.is_some() {
                    candidate.email = email.clone();
                }
                let incoming: std::collections::HashSet<String> =
                    anthropic::account_identities(&candidate)
                        .into_iter()
                        .collect();
                if let Some(existing) = store.accounts.iter().find(|a| {
                    anthropic::account_identities(a)
                        .iter()
                        .any(|k| incoming.contains(k))
                }) {
                    return Ok(("kept", existing.id.clone()));
                }
                let id = candidate.id.clone();
                store.accounts.push(candidate);
                if store.current.is_none() {
                    store.current = Some(id.clone());
                }
                Ok(("added", id))
            })
            .map_err(|e| from_crate(&e))?;
            Ok(ImportResult {
                account_id: status.1,
                status: status.0.into(),
            })
        })
        .await
    }

    /// Recover from an upstream 401 on a store credential: one claimed
    /// refresh of the row that owns `accessToken`; `retry` only when it
    /// produced a new bearer for the same account.
    #[napi]
    pub async fn handle_unauthorized(
        &self,
        options: HandleUnauthorizedOptions,
    ) -> napi::Result<UnauthorizedResult> {
        let recovery = self
            .client()
            .recover_unauthorized(
                &self.path,
                &options.access_token,
                &SharedRefreshOptions::default(),
            )
            .await
            .map_err(|e| from_crate(&e))?;
        let path = self.path.clone();
        let token = match recovery.outcome {
            Some(outcome) => {
                let id = outcome.account_id.clone().unwrap_or_default();
                let email = blocking(move || {
                    Ok(AccountStore::load_or_migrate_from(&path, &[])
                        .ok()
                        .and_then(|l| l.store.get(&id).and_then(|a| a.email.clone())))
                })
                .await?;
                Some(AccessToken {
                    access_token: outcome.tokens.access.expose().to_owned(),
                    account_id: outcome.account_id.unwrap_or_default(),
                    email: email.or_else(|| {
                        outcome
                            .tokens
                            .account
                            .as_ref()
                            .and_then(|a| a.email_address.clone())
                    }),
                    expires_at: ms(outcome.tokens.expires_at),
                    source: "refreshed".into(),
                })
            }
            None => None,
        };
        Ok(UnauthorizedResult {
            retry: recovery.decision.retry,
            reason: format!("{:?}", recovery.decision.reason),
            token,
            failure_code: recovery.failure.as_ref().map(|e| {
                anthropic::access::AccessError::from_error(e)
                    .kind
                    .code()
                    .to_owned()
            }),
        })
    }
}

impl AnthropicAuth {
    async fn update_row(
        &self,
        account_id: String,
        update: impl FnOnce(&mut Account) + Send + 'static,
    ) -> napi::Result<bool> {
        let path = self.path.clone();
        blocking(move || {
            AccountStore::mutate(&path, |store| match store.get_mut(&account_id) {
                Ok(account) => {
                    update(account);
                    Ok(true)
                }
                Err(_) => Ok(false),
            })
            .map_err(|e| from_crate(&e))
        })
        .await
    }
}

fn config_error(message: &str) -> napi::Error {
    config(message)
}

fn reason_code(reason: KeepAliveReason) -> &'static str {
    match reason {
        KeepAliveReason::NoAccessToken => "no_access_token",
        KeepAliveReason::RefreshExpiring => "refresh_expiring",
        KeepAliveReason::Stale => "stale",
    }
}

fn skip_code(skip: KeepAliveSkip) -> &'static str {
    match skip {
        KeepAliveSkip::Disabled => "disabled",
        KeepAliveSkip::NotOauth => "not_oauth",
        KeepAliveSkip::NoRefreshToken => "no_refresh_token",
        KeepAliveSkip::DeadToken => "dead_token",
        KeepAliveSkip::RefreshExpired => "refresh_expired",
        KeepAliveSkip::InUse => "in_use",
        KeepAliveSkip::SessionLive => "session_live",
        KeepAliveSkip::RecentlyRefreshed => "recently_refreshed",
        KeepAliveSkip::NotDue => "not_due",
        KeepAliveSkip::Deferred => "deferred",
    }
}

/// `(code, state)` from whatever the user pasted: a redirect URL, `code#state`,
/// a `code=…&state=…` query, or a bare code (then the pending state is
/// assumed; the exchange itself proves possession).
fn parse_callback(input: &str, pending_state: &str) -> napi::Result<(String, String)> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(fail(
            AccessErrorKind::AuthRequired,
            "the login callback is empty",
        ));
    }
    let from_pairs = |pairs: url::form_urlencoded::Parse<'_>| {
        let mut code = None;
        let mut state = None;
        for (key, value) in pairs {
            match key.as_ref() {
                "code" => code = Some(value.into_owned()),
                "state" => state = Some(value.into_owned()),
                _ => {}
            }
        }
        code.zip(state)
    };
    if let Ok(url) = url::Url::parse(trimmed)
        && let Some(found) = from_pairs(url.query_pairs())
    {
        return Ok(found);
    }
    if let Some((code, state)) = trimmed.rsplit_once('#')
        && !code.is_empty()
        && !state.is_empty()
    {
        return Ok((code.to_owned(), state.to_owned()));
    }
    if let Some(found) = from_pairs(url::form_urlencoded::parse(trimmed.as_bytes())) {
        return Ok(found);
    }
    if trimmed.contains(['=', '&', '?', '/', ' ']) {
        return Err(fail(
            AccessErrorKind::AuthRequired,
            "could not read a code from the login callback",
        ));
    }
    Ok((trimmed.to_owned(), pending_state.to_owned()))
}

fn preferred_id(store: &AccountStore, tokens: &OAuthTokens, label: Option<&str>) -> String {
    let email = tokens
        .account
        .as_ref()
        .and_then(|a| a.email_address.as_deref());
    store
        .login_account_id(
            label.or(email),
            label.is_some(),
            tokens.organization.as_ref().map(|o| o.uuid.as_str()),
            None,
        )
        .or_else(|| tokens.account.as_ref().map(|a| a.uuid.clone()))
        .unwrap_or_else(|| {
            let id = uuid::Uuid::new_v4().simple().to_string();
            format!("account-{}", &id[..8])
        })
}

fn store_login(
    path: &std::path::Path,
    tokens: OAuthTokens,
    label: Option<String>,
    set_current: Option<bool>,
) -> napi::Result<AccountInfo> {
    AccountStore::mutate(path, |store| {
        let id = preferred_id(store, &tokens, label.as_deref());
        let mut account = Account::new(id, Credential::Oauth(tokens));
        account.label = label.clone();
        let id = store.merge_login(account)?;
        if set_current.unwrap_or(store.current.is_none()) {
            store.current = Some(id.clone());
        }
        let now = Utc::now();
        store
            .get(&id)
            .map(|a| account_info(store, a, now))
            .ok_or(anthropic::Error::UnknownAccount(id))
    })
    .map_err(|e| from_crate(&e))
}
