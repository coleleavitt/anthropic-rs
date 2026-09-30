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
//! `invalid_token`, `store_corrupt`, `transient` (`"<code>: <detail>"`). The package loader (`index.js`)
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
use anthropic::revoke::RevokedRowDisposition;
use anthropic::{
    Account,
    AccountStore,
    Credential,
    Endpoints,
    NativePublish,
    OAuthClient,
    OAuthTokens,
    PkceVerifier,
    RevokeOutcome,
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

fn invalid_token(message: impl AsRef<str>) -> napi::Error {
    fail(AccessErrorKind::InvalidToken, message)
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
/// `~/.anthropic-accounts/accounts.json`) and `anthropic::Endpoints::from_env`
/// (production unless `ANTHROPIC_OAUTH_TOKEN_URL`,
/// `ANTHROPIC_OAUTH_REVOKE_URL`, `ANTHROPIC_OAUTH_AUTHORIZE_URL`,
/// `ANTHROPIC_OAUTH_CONSOLE_AUTHORIZE_URL`, `ANTHROPIC_OAUTH_REDIRECT_URI`,
/// `ANTHROPIC_OAUTH_USAGE_URL` or `CLAUDE_CODE_OAUTH_CLIENT_ID` override it).
/// With `ANTHROPIC_OAUTH_TEST_MODE=1`, any OAuth call to a non-loopback host
/// fails with code `config` before a byte is sent.
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
    /// Refresh-token revocation endpoint (tests point this at a mock).
    pub revoke_url: Option<String>,
    /// Profile endpoint used to fill a login's identity.
    pub profile_url: Option<String>,
    /// Legacy per-application stores to adopt (`~/.grok`, `~/.config/jfc`,
    /// …). Default: the crate's list, from the host's `HOME` / `GROK_HOME`,
    /// when the store is the default one; none for any other store. `[]`
    /// turns adoption off.
    pub legacy_paths: Option<Vec<String>>,
    /// `"auto"` (default) or `"off"`: publish a rotation to Claude Code's
    /// credential file when it still holds the spent refresh token.
    /// `ANTHROPIC_NATIVE_PUBLISH=0` also turns it off. In OAuth test mode it
    /// is off unless `nativeCredentialsPath` names the file.
    pub native_publish: Option<String>,
    /// Claude Code's credential file. Default: `$CLAUDE_SECURESTORAGE_CONFIG_DIR`
    /// / `$CLAUDE_CONFIG_DIR` / `~/.claude`, joined with `.credentials.json`.
    pub native_credentials_path: Option<String>,
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
    /// For `api_key` rows: the key's last four characters (never the key).
    pub api_key_suffix: Option<String>,
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
        api_key_suffix: match &account.credential {
            Credential::ApiKey { key } => Some(token::key_suffix(key.expose())),
            Credential::Oauth(_) => None,
        },
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
    /// Redirect URI for this login only (a loopback listener's), used for
    /// the authorize URL and the code exchange alike.
    pub redirect_uri: Option<String>,
    /// Anti-CSRF state for this login (one a loopback listener already
    /// expects): 8-512 URL-safe characters. Default: a fresh random one.
    pub state: Option<String>,
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

/// Options for [`AnthropicAuth::add_api_key`].
#[napi(object)]
pub struct AddApiKeyOptions {
    /// Label (and preferred id).
    pub label: Option<String>,
    /// The `sk-ant-api…` key. Moves into the store; it is only ever handed
    /// back by `getApiKey`.
    pub key: String,
}

/// Result of [`AnthropicAuth::add_api_key`].
#[napi(object)]
pub struct AddApiKeyResult {
    /// The row holding the key.
    pub account_id: String,
    /// `"added"` or `"already_present"` (a row already holds this key).
    pub status: String,
}

/// Options for [`AnthropicAuth::get_api_key`].
#[napi(object)]
#[derive(Default)]
pub struct GetApiKeyOptions {
    /// Use only this account (id or label).
    pub account: Option<String>,
    /// Consider only these accounts (ids or labels).
    pub allowlist: Option<Vec<String>>,
}

/// A static API key from the store. Send it as `x-api-key`; never log it.
#[napi(object)]
pub struct ApiKeyCredential {
    /// The key.
    pub api_key: String,
    /// Store row it belongs to.
    pub account_id: String,
    /// The row's label.
    pub label: Option<String>,
}

/// Options for [`AnthropicAuth::revoke_account`].
#[napi(object)]
pub struct RevokeAccountOptions {
    /// Store row.
    pub account_id: String,
    /// Keep the row, disabled with its token recorded dead, instead of
    /// removing it.
    pub disable: Option<bool>,
}

/// Result of [`AnthropicAuth::revoke_account`].
#[napi(object)]
pub struct RevokeAccountResult {
    /// Store row.
    pub account_id: String,
    /// `"revoked"`, `"already_inactive"`, or `"not_sent"` (the token was
    /// already recorded dead, so no request was needed).
    pub outcome: String,
    /// Whether the row was removed (else it was disabled).
    pub removed: bool,
}

/// Options for [`AnthropicAuth::exchange_code`].
#[napi(object)]
pub struct ExchangeCodeOptions {
    /// From `startLogin`.
    pub login_id: String,
    /// What the user pasted or the loopback received (as for `completeLogin`).
    pub callback: String,
}

/// A code exchanged without storing anything (the Console API-key mint).
/// The refresh token of the grant is dropped in Rust.
#[napi(object)]
pub struct ExchangedAccess {
    /// Bearer for the one follow-up call.
    pub access_token: String,
    /// Access-token expiry (epoch ms).
    pub expires_at: i64,
    /// Granted scopes.
    pub scopes: Vec<String>,
    /// Anthropic account uuid, when the grant carried one.
    pub account_uuid: Option<String>,
    /// Account email, when the grant carried one.
    pub email: Option<String>,
    /// Organization uuid, when the grant carried one.
    pub organization_uuid: Option<String>,
}

/// One row of [`AnthropicAuth::backfill_identities`].
#[napi(object)]
pub struct BackfillEntry {
    /// Store row.
    pub account_id: String,
    /// `"filled"`, `"not_oauth"`, `"already_identified"`,
    /// `"profile_unavailable"`, `"no_live_access_token"` or `"changed"`.
    pub status: String,
    /// The email written, for `"filled"`.
    pub email: Option<String>,
}

/// Options for [`AnthropicAuth::read_native_claude_oauth`] and
/// [`AnthropicAuth::import_native_claude_account`].
#[napi(object)]
#[derive(Default)]
pub struct NativeClaudeOptions {
    /// Claude Code's credential file (default: the handle's
    /// `nativeCredentialsPath`, else Claude Code's own path; in OAuth test
    /// mode only an explicit path is read).
    pub path: Option<String>,
    /// Label for an imported row (default `"Claude Code"`).
    pub label: Option<String>,
}

/// Non-secret facts about Claude Code's credential file.
#[napi(object)]
pub struct NativeClaudeInfo {
    /// The file read.
    pub path: String,
    /// Access-token expiry (epoch ms).
    pub expires_at: i64,
    /// Refresh-token expiry (epoch ms), when recorded.
    pub refresh_expires_at: Option<i64>,
    /// Granted scopes.
    pub scopes: Vec<String>,
    /// `subscriptionType`.
    pub subscription_type: Option<String>,
    /// `rateLimitTier`.
    pub rate_limit_tier: Option<String>,
    /// The store row holding the same refresh token, when there is one
    /// (then a store refresh is published back to this file).
    pub store_account_id: Option<String>,
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
    profile_url: String,
    test_mode: bool,
    legacy: Vec<PathBuf>,
    native_publish: NativePublish,
    native_path: Option<PathBuf>,
    logins: Arc<Mutex<HashMap<String, PendingLogin>>>,
}

impl AnthropicAuth {
    /// The OAuth client every refresh goes through: this handle's endpoints,
    /// test mode and native-publish policy.
    fn client(&self) -> OAuthClient {
        OAuthClient::new(self.endpoints.clone())
            .require_loopback(self.test_mode)
            .native_publish(self.native_publish.clone())
    }

    /// Fold the configured legacy stores into the store (append-only,
    /// locked; a no-op once every file is recorded in `migrated_from`).
    async fn adopt_legacy(&self) -> napi::Result<()> {
        if self.legacy.is_empty() {
            return Ok(());
        }
        let (path, legacy) = (self.path.clone(), self.legacy.clone());
        blocking(move || {
            AccountStore::adopt_legacy(&path, &legacy)
                .map(|_| ())
                .map_err(|e| from_crate(&e))
        })
        .await
    }

    /// Claude Code's credential file for an explicit read/import: `explicit`,
    /// else the handle's configured one; `None` in OAuth test mode without
    /// an explicit path (a test never reads the real file).
    fn native_file(&self, explicit: Option<String>) -> Option<PathBuf> {
        match explicit
            .map(|p| p.trim().to_owned())
            .filter(|p| !p.is_empty())
        {
            Some(path) => Some(PathBuf::from(path)),
            None => self.native_path.clone(),
        }
    }

    /// Fill an unidentified grant from the profile endpoint (best effort:
    /// a failure, or test mode refusing the host, leaves it as it is).
    async fn identify(&self, mut tokens: OAuthTokens) -> OAuthTokens {
        if tokens.account.as_ref().is_some_and(|a| !a.uuid.is_empty())
            || anthropic::endpoints::check_oauth_url(&self.profile_url, self.test_mode()).is_err()
        {
            return tokens;
        }
        let identity = anthropic::profile::fetch_oauth_account_identity_from(
            &anthropic::oauth::default_oauth_http_client(),
            &self.profile_url,
            tokens.access.expose(),
        )
        .await;
        if let Some(uuid) = identity.account_uuid {
            tokens.account = Some(token::TokenAccount {
                uuid,
                email_address: identity.email,
            });
            if let Some(org) = identity.organization_uuid {
                tokens.organization = Some(token::TokenOrganization { uuid: org });
            }
        }
        tokens
    }
}

/// The host's view of the environment, passed by `index.js` as a snapshot of
/// `process.env` (Bun's `process.env` writes do not reach the native
/// `getenv`, so the addon cannot rely on `std::env` alone). A snapshot value
/// wins; a key absent from it falls back to the process environment.
struct HostEnv(HashMap<String, String>);

impl HostEnv {
    fn get(&self, key: &str) -> Option<String> {
        self.0
            .get(key)
            .cloned()
            .or_else(|| std::env::var(key).ok())
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
    }

    /// `$ANTHROPIC_ACCOUNTS_FILE`, else `$ANTHROPIC_ACCOUNTS_DIR/accounts.json`,
    /// else `$HOME/.anthropic-accounts/accounts.json`, resolved through this
    /// view (the crate's `default_store_path` as the last resort).
    fn store_path(&self) -> PathBuf {
        if let Some(file) = self.get(anthropic::store::STORE_FILE_ENV) {
            return PathBuf::from(file);
        }
        if let Some(dir) = self.get(anthropic::store::STORE_DIR_ENV) {
            return PathBuf::from(dir).join(anthropic::store::STORE_FILE_NAME);
        }
        if let Some(home) = self.get("HOME") {
            return PathBuf::from(home)
                .join(anthropic::store::STORE_DIR_NAME)
                .join(anthropic::store::STORE_FILE_NAME);
        }
        anthropic::default_store_path()
    }
}

#[napi]
impl AnthropicAuth {
    /// Open the store at `options.storePath` (default: the shared store).
    /// Validates the configuration; nothing is read until a method runs.
    #[napi(constructor)]
    ///
    /// `env` is the loader's snapshot of `process.env` (see `index.js`); it
    /// feeds the same resolution as `Endpoints::from_env`.
    pub fn new(
        options: Option<AuthConfig>,
        env: Option<HashMap<String, String>>,
    ) -> napi::Result<Self> {
        let cfg = options.unwrap_or_default();
        let host = HostEnv(env.unwrap_or_default());
        let default_path = host.store_path();
        let path = match cfg.store_path.as_deref().map(str::trim) {
            Some("") => return Err(config_error("storePath is empty")),
            Some(path) => PathBuf::from(path),
            None => default_path.clone(),
        };
        // The crate's one endpoint resolver (ANTHROPIC_OAUTH_*_URL,
        // CLAUDE_CODE_OAUTH_CLIENT_ID, ANTHROPIC_BASE_URL) over the host's
        // environment; explicit options win over it.
        let mut endpoints = Endpoints::from_lookup(|key| host.get(key));
        let mut console_authorize_url =
            Endpoints::console_from_lookup(|key| host.get(key)).authorize_url;
        let mut profile_url = anthropic::profile::profile_url_from_lookup(|key| host.get(key));
        let test_mode = anthropic::endpoints::oauth_test_mode_value(
            host.get(anthropic::endpoints::OAUTH_TEST_MODE_ENV)
                .as_deref(),
        ) || anthropic::endpoints::oauth_test_mode();
        for (value, slot) in [
            (cfg.token_url, &mut endpoints.token_url),
            (cfg.authorize_url, &mut endpoints.authorize_url),
            (cfg.console_authorize_url, &mut console_authorize_url),
            (cfg.redirect_uri, &mut endpoints.redirect_uri),
            (cfg.client_id, &mut endpoints.client_id),
            (cfg.revoke_url, &mut endpoints.revoke_url),
            (cfg.profile_url, &mut profile_url),
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
            &endpoints.revoke_url,
            &console_authorize_url,
            &profile_url,
        ] {
            url::Url::parse(url).map_err(|e| config(format!("invalid endpoint url: {e}")))?;
        }
        // Legacy adoption is a machine-level migration into the default
        // store (the crate's and ckl's rule); any other store adopts only
        // what the caller lists.
        let legacy = match cfg.legacy_paths {
            Some(paths) => paths
                .into_iter()
                .map(|p| p.trim().to_owned())
                .filter(|p| !p.is_empty())
                .map(PathBuf::from)
                .collect(),
            None if path == default_path => {
                anthropic::store::legacy_store_paths_from_lookup(|key| host.get(key))
            }
            None => Vec::new(),
        };
        let explicit_native = cfg
            .native_credentials_path
            .map(|p| p.trim().to_owned())
            .filter(|p| !p.is_empty())
            .map(PathBuf::from);
        // Test mode never resolves Claude Code's real file: only an explicit
        // path is read or written.
        let native_path = explicit_native.clone().or_else(|| {
            (!test_mode)
                .then(|| anthropic::native_claude_credentials_path_from_lookup(|key| host.get(key)))
        });
        let publish_on = match cfg.native_publish.as_deref().map(str::trim) {
            None | Some("auto") => {
                NativePublish::from_lookup(|key| host.get(key)) == NativePublish::Auto
            }
            Some("off") => false,
            Some(other) => {
                return Err(config(format!(
                    "nativePublish must be \"auto\" or \"off\", not {other:?}"
                )));
            }
        };
        let native_publish = match (&native_path, publish_on) {
            (Some(file), true) => NativePublish::At(file.clone()),
            _ => NativePublish::Off,
        };
        Ok(Self {
            path,
            endpoints,
            console_authorize_url,
            profile_url,
            test_mode,
            legacy,
            native_publish,
            native_path,
            logins: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Whether this handle refuses OAuth calls to non-loopback hosts
    /// (`ANTHROPIC_OAUTH_TEST_MODE`, from the host env or the process env).
    #[napi(getter)]
    pub fn test_mode(&self) -> bool {
        self.test_mode || anthropic::endpoints::oauth_test_mode()
    }

    /// The store file this handle uses.
    #[napi(getter)]
    pub fn store_path(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }

    /// Every row, non-secret fields only.
    #[napi]
    pub async fn list_accounts(&self) -> napi::Result<Vec<AccountInfo>> {
        self.adopt_legacy().await?;
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
        self.adopt_legacy().await?;
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
        if let Some(redirect) = options
            .redirect_uri
            .as_deref()
            .map(str::trim)
            .filter(|r| !r.is_empty())
        {
            url::Url::parse(redirect).map_err(|e| config(format!("invalid redirectUri: {e}")))?;
            endpoints.redirect_uri = redirect.to_owned();
        }
        let login = match options.state {
            Some(state) => anthropic::start_login_with_state(&endpoints, state),
            None => anthropic::start_login(&endpoints),
        }
        .map_err(|e| from_crate(&e))?;
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
        let tokens = self.exchange(&options.login_id, &options.callback).await?;
        // Name the row after the signed-in account and let a re-login find
        // the row it supersedes, when the grant itself carried no identity.
        let tokens = self.identify(tokens).await;
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
            return Err(invalid_token(
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
        let tokens = if tokens.expires_at > Utc::now() {
            self.identify(tokens).await
        } else {
            tokens
        };
        self.import_tokens(tokens, options.label, options.email)
            .await
    }

    /// Exchange a login's code **without storing anything**: for the Console
    /// "create an API key" flow, whose grant is used once to mint a key. The
    /// grant's refresh token is dropped in Rust; only the access token and
    /// non-secret metadata are returned.
    #[napi]
    pub async fn exchange_code(
        &self,
        options: ExchangeCodeOptions,
    ) -> napi::Result<ExchangedAccess> {
        let tokens = self.exchange(&options.login_id, &options.callback).await?;
        Ok(ExchangedAccess {
            access_token: tokens.access.expose().to_owned(),
            expires_at: ms(tokens.expires_at),
            scopes: tokens.scopes.clone(),
            account_uuid: tokens.account.as_ref().map(|a| a.uuid.clone()),
            email: tokens
                .account
                .as_ref()
                .and_then(|a| a.email_address.clone()),
            organization_uuid: tokens.organization.as_ref().map(|o| o.uuid.clone()),
        })
    }

    /// Store a static API key as an `api_key` row. The key is validated
    /// (`sk-ant-api…`); `listAccounts` shows only its last four characters.
    #[napi]
    pub async fn add_api_key(&self, options: AddApiKeyOptions) -> napi::Result<AddApiKeyResult> {
        let key = options.key.trim().to_owned();
        if !token::is_valid_api_key(&key) {
            return Err(invalid_token(
                "addApiKey needs a well-formed Anthropic API key",
            ));
        }
        let label = options.label;
        let path = self.path.clone();
        blocking(move || {
            let (account_id, added) = AccountStore::mutate(&path, |store| {
                Ok(store.add_api_key(label.as_deref(), token::ApiKey::new(key)))
            })
            .map_err(|e| from_crate(&e))?;
            Ok(AddApiKeyResult {
                account_id,
                status: if added { "added" } else { "already_present" }.into(),
            })
        })
        .await
    }

    /// A static API key from an `api_key` row (id or label, pin first,
    /// enabled and not cooling down). Send it as `x-api-key`; never log it.
    #[napi]
    pub async fn get_api_key(
        &self,
        options: Option<GetApiKeyOptions>,
    ) -> napi::Result<ApiKeyCredential> {
        let options = options.unwrap_or_default();
        self.adopt_legacy().await?;
        let path = self.path.clone();
        blocking(move || {
            let request = AccessRequest {
                account: options.account,
                allowlist: options.allowlist.unwrap_or_default(),
                reserve_percent: None,
            };
            anthropic::access::get_api_key(&path, &request)
                .map(|grant| ApiKeyCredential {
                    api_key: grant.api_key,
                    account_id: grant.account_id,
                    label: grant.label,
                })
                .map_err(|e| fail(e.kind, e.message))
        })
        .await
    }

    /// Revoke an OAuth account's refresh token at the revoke endpoint, then
    /// remove the row (or, with `disable`, keep it disabled with the token
    /// recorded dead). A failed request changes nothing.
    #[napi]
    pub async fn revoke_account(
        &self,
        options: RevokeAccountOptions,
    ) -> napi::Result<RevokeAccountResult> {
        let disposition = if options.disable.unwrap_or(false) {
            RevokedRowDisposition::Disable
        } else {
            RevokedRowDisposition::Remove
        };
        let report = self
            .client()
            .revoke_account(
                &self.path,
                &options.account_id,
                disposition,
                &SharedRefreshOptions::default(),
            )
            .await
            .map_err(|e| from_crate(&e))?;
        Ok(RevokeAccountResult {
            account_id: report.account_id,
            outcome: match report.outcome {
                Some(RevokeOutcome::Revoked) => "revoked",
                Some(RevokeOutcome::AlreadyInactive) => "already_inactive",
                None => "not_sent",
            }
            .into(),
            removed: report.removed,
        })
    }

    /// Fill the identity (account uuid, email, organization) of OAuth rows
    /// that have none, from the profile endpoint with each row's live access
    /// token. Never spends a refresh token.
    #[napi]
    pub async fn backfill_identities(&self) -> napi::Result<Vec<BackfillEntry>> {
        let report = anthropic::profile::backfill_store_identities(
            &anthropic::oauth::default_oauth_http_client(),
            &self.profile_url,
            &self.path,
            self.test_mode(),
        )
        .await
        .map_err(|e| from_crate(&e))?;
        use anthropic::profile::{BackfillSkip, IdentityBackfill};
        Ok(report
            .into_iter()
            .map(|(account_id, result)| {
                let (status, email) = match result {
                    IdentityBackfill::Filled { email } => ("filled", email),
                    IdentityBackfill::Skipped(BackfillSkip::NotOauth) => ("not_oauth", None),
                    IdentityBackfill::Skipped(BackfillSkip::AlreadyIdentified) => {
                        ("already_identified", None)
                    }
                    IdentityBackfill::Skipped(BackfillSkip::ProfileUnavailable) => {
                        ("profile_unavailable", None)
                    }
                    IdentityBackfill::NoLiveAccessToken => ("no_live_access_token", None),
                    IdentityBackfill::Changed => ("changed", None),
                };
                BackfillEntry {
                    account_id,
                    status: status.into(),
                    email,
                }
            })
            .collect())
    }

    /// Non-secret facts about the credential Claude Code holds in its
    /// credential file, or `null` when there is none (or, in OAuth test
    /// mode, when no path is given). Unusable files (symlink, group/world
    /// readable, malformed) reject.
    #[napi(js_name = "readNativeClaudeOAuth")]
    pub async fn read_native_claude_oauth(
        &self,
        options: Option<NativeClaudeOptions>,
    ) -> napi::Result<Option<NativeClaudeInfo>> {
        let Some(file) = self.native_file(options.unwrap_or_default().path) else {
            return Ok(None);
        };
        let path = self.path.clone();
        blocking(move || {
            let Some(summary) =
                anthropic::read_native_claude_summary(Some(&file)).map_err(|e| native_error(&e))?
            else {
                return Ok(None);
            };
            let store_account_id = AccountStore::load_or_migrate_from(&path, &[])
                .ok()
                .and_then(|loaded| {
                    loaded
                        .store
                        .accounts
                        .iter()
                        .find(|a| {
                            a.oauth().is_some_and(|t| {
                                token::token_fingerprint(t.refresh.expose())
                                    == summary.refresh_fingerprint
                            })
                        })
                        .map(|a| a.id.clone())
                });
            Ok(Some(NativeClaudeInfo {
                path: summary.path.to_string_lossy().into_owned(),
                expires_at: summary.expires_at,
                refresh_expires_at: summary.refresh_expires_at,
                scopes: summary.scopes,
                subscription_type: summary.subscription_type,
                rate_limit_tier: summary.rate_limit_tier,
                store_account_id,
            }))
        })
        .await
    }

    /// Import the credential Claude Code holds in its credential file into
    /// the store (the tokens never reach JavaScript). The store's copy of the
    /// same login wins. From then on a store refresh of that token is
    /// published back to the file, so Claude Code's login stays alive.
    /// Rejects `auth_required` when there is no file (or, in OAuth test
    /// mode, no explicit path).
    #[napi]
    pub async fn import_native_claude_account(
        &self,
        options: Option<NativeClaudeOptions>,
    ) -> napi::Result<ImportResult> {
        let options = options.unwrap_or_default();
        let Some(file) = self.native_file(options.path) else {
            return Err(fail(
                AccessErrorKind::AuthRequired,
                "no Claude Code credential file to import (OAuth test mode reads only an explicit path)",
            ));
        };
        let imported = blocking(move || {
            match std::fs::symlink_metadata(&file) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(fail(
                        AccessErrorKind::AuthRequired,
                        "Claude Code has no credential file here",
                    ));
                }
                _ => {}
            }
            anthropic::import_native_claude_file(Some(&file)).map_err(|e| native_error(&e))
        })
        .await?;
        let tokens = if imported.tokens.expires_at > Utc::now() {
            self.identify(imported.tokens).await
        } else {
            imported.tokens
        };
        let label = options
            .label
            .map(|l| l.trim().to_owned())
            .filter(|l| !l.is_empty())
            .or_else(|| Some("Claude Code".to_owned()));
        self.import_tokens(tokens, label, None).await
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
    /// Take a pending login, verify the callback's state and exchange the
    /// code. Nothing is stored.
    async fn exchange(&self, login_id: &str, callback: &str) -> napi::Result<OAuthTokens> {
        let pending = self
            .logins
            .lock()
            .map_err(|_| fail(AccessErrorKind::Transient, "login table poisoned"))?
            .remove(login_id)
            .filter(|p| p.started.elapsed() < LOGIN_TTL)
            .ok_or_else(|| {
                fail(
                    AccessErrorKind::AuthRequired,
                    "unknown or expired login; start a new one",
                )
            })?;
        let (code, state) = parse_callback(callback, &pending.state)?;
        let code = anthropic::parse_redirect_code(&format!("{code}#{state}"), &pending.state)
            .map_err(|e| from_crate(&e))?;
        OAuthClient::new(pending.endpoints)
            .require_loopback(self.test_mode)
            .exchange_code(&code, &pending.verifier, &pending.state)
            .await
            .map_err(|e| from_crate(&e))
    }

    /// Store an imported OAuth credential: the store is the custodian, so a
    /// row that already holds this token or this login wins.
    async fn import_tokens(
        &self,
        tokens: OAuthTokens,
        label: Option<String>,
        email: Option<String>,
    ) -> napi::Result<ImportResult> {
        let label = label.filter(|l| !l.trim().is_empty());
        let email = email.or_else(|| tokens.account.as_ref()?.email_address.clone());
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

/// A native credential file that exists but cannot be used: malformed
/// tokens are `invalid_token`, everything else about the file is
/// `store_corrupt` (symlink, permissions, JSON) or the crate's class.
fn native_error(error: &anthropic::Error) -> napi::Error {
    match error {
        anthropic::Error::MalformedTokenResponse(_) => invalid_token(format!(
            "Claude Code's credential file holds no usable OAuth token: {error}"
        )),
        anthropic::Error::Protocol(_) => fail(
            AccessErrorKind::StoreCorrupt,
            format!("Claude Code's credential file is unusable: {error}"),
        ),
        other => from_crate(other),
    }
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
