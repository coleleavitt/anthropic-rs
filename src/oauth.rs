//! The OAuth authorization-code and refresh-token flows against the Anthropic
//! token endpoint: the wire request/response types, an authorize-URL builder,
//! the manual-paste redirect parser, and an async client.

#[cfg(all(feature = "client", feature = "store"))]
use std::path::Path;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::endpoints::{self, Endpoints, Scope};
#[cfg(feature = "client")]
use crate::error::redacted_response_body;
use crate::error::{Error, Result};
#[cfg(any(feature = "client", test))]
use crate::pkce::PkceVerifier;
use crate::pkce::{CODE_CHALLENGE_METHOD, PkcePair, constant_time_eq};
#[cfg(feature = "client")]
use crate::token::redact_secrets;
use crate::token::{self, AccessToken, OAuthTokens, RefreshToken, TokenAccount, TokenOrganization};

/// OAuth error codes that make a `400` response permanent (no retry can help).
#[cfg(feature = "client")]
const KNOWN_PERMANENT_OAUTH_ERRORS: [&str; 7] = [
    "invalid_grant",
    "invalid_client",
    "invalid_request",
    "unauthorized_client",
    "access_denied",
    "unsupported_grant_type",
    "invalid_scope",
];

/// Upper bound on any server-advised retry cooldown: 24 hours in milliseconds.
#[cfg(feature = "client")]
const MAX_RETRY_AFTER_MS: i64 = 24 * 60 * 60 * 1000;

/// The POST body sent to the token endpoint. One enum, two grants — the
/// `grant_type` discriminant is serialized inline.
#[derive(Clone, Serialize)]
#[serde(tag = "grant_type", rename_all = "snake_case")]
pub enum TokenRequest {
    /// Exchange an authorization code for tokens.
    AuthorizationCode {
        /// The authorization code returned to the redirect.
        code: String,
        /// The redirect URI used in the authorize request.
        redirect_uri: String,
        /// OAuth client id.
        client_id: String,
        /// The PKCE verifier matching the challenge sent at authorize time.
        code_verifier: String,
        /// The anti-CSRF state echoed back.
        state: String,
    },
    /// Renew an access token from a refresh token.
    RefreshToken {
        /// The refresh token.
        refresh_token: String,
        /// OAuth client id.
        client_id: String,
        /// Requested scopes (refresh set; excludes `org:create_api_key`).
        scope: String,
    },
}

impl std::fmt::Debug for TokenRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthorizationCode {
                redirect_uri,
                client_id,
                ..
            } => formatter
                .debug_struct("TokenRequest::AuthorizationCode")
                .field("code", &"***")
                .field("redirect_uri", redirect_uri)
                .field("client_id", client_id)
                .field("code_verifier", &"***")
                .field("state", &"***")
                .finish(),
            Self::RefreshToken {
                client_id, scope, ..
            } => formatter
                .debug_struct("TokenRequest::RefreshToken")
                .field("refresh_token", &"***")
                .field("client_id", client_id)
                .field("scope", scope)
                .finish(),
        }
    }
}

/// Raw token-endpoint response.
#[derive(Clone, Deserialize)]
pub struct TokenResponse {
    /// The new access token.
    pub access_token: String,
    /// A rotated refresh token, when the server issues one.
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// Lifetime of the access token in seconds.
    pub expires_in: i64,
    /// Lifetime of the refresh token in seconds, when reported.
    #[serde(default)]
    pub refresh_token_expires_in: Option<i64>,
    /// Space-separated granted scopes.
    #[serde(default)]
    pub scope: Option<String>,
    /// Token type (`Bearer`).
    #[serde(default)]
    pub token_type: Option<String>,
    /// Account descriptor.
    #[serde(default)]
    pub account: Option<TokenAccount>,
    /// Organization descriptor.
    #[serde(default)]
    pub organization: Option<TokenOrganization>,
}

impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TokenResponse")
            .field("access_token", &"***")
            .field("refresh_token", &self.refresh_token.as_ref().map(|_| "***"))
            .field("expires_in", &self.expires_in)
            .field("refresh_token_expires_in", &self.refresh_token_expires_in)
            .field("scope", &self.scope)
            .field("token_type", &self.token_type)
            .field("account", &self.account)
            .field("organization", &self.organization)
            .finish()
    }
}

/// Outcome of a refresh-token revocation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeOutcome {
    /// The server accepted the revocation request.
    Revoked,
    /// The token was already inactive or unknown.
    AlreadyInactive,
}

fn checked_token_expiry(
    now: DateTime<Utc>,
    seconds: i64,
    field: &'static str,
) -> Result<DateTime<Utc>> {
    let duration = Duration::try_seconds(seconds).ok_or(Error::MalformedTokenResponse(field))?;
    now.checked_add_signed(duration)
        .ok_or(Error::MalformedTokenResponse(field))
}

impl TokenResponse {
    /// Fold a response into stored [`OAuthTokens`], computing the absolute
    /// expiry from `now` and carrying prior refresh metadata forward when the
    /// response omits it (Claude Code CLI behavior). Validates token
    /// formats, a positive lifetime, and — when the server echoes scopes — that
    /// inference was granted.
    pub fn into_tokens(
        self,
        now: DateTime<Utc>,
        prior: Option<&OAuthTokens>,
    ) -> Result<OAuthTokens> {
        if !token::is_valid_access_token(&self.access_token) {
            return Err(Error::MalformedTokenResponse("access_token"));
        }
        let refresh = match self.refresh_token {
            Some(raw) if token::is_valid_refresh_token(&raw) => RefreshToken::new(raw),
            Some(_) => return Err(Error::MalformedTokenResponse("refresh_token")),
            None => prior
                .map(|tokens| tokens.refresh.clone())
                .ok_or(Error::MalformedTokenResponse("refresh_token"))?,
        };
        if self.expires_in <= 0 {
            return Err(Error::MalformedTokenResponse("expires_in"));
        }
        let expires_at = checked_token_expiry(now, self.expires_in, "expires_in")?;
        let refresh_expires_at = match self.refresh_token_expires_in {
            Some(seconds) if seconds > 0 => Some(checked_token_expiry(
                now,
                seconds,
                "refresh_token_expires_in",
            )?),
            Some(_) => {
                return Err(Error::MalformedTokenResponse("refresh_token_expires_in"));
            }
            None => prior.and_then(|tokens| tokens.refresh_expires_at),
        };
        let scopes: Vec<String> = self
            .scope
            .as_deref()
            .map(|s| s.split_whitespace().map(str::to_owned).collect())
            .unwrap_or_else(|| {
                prior
                    .map(|tokens| tokens.scopes.clone())
                    .unwrap_or_default()
            });
        if !scopes.is_empty() && !endpoints::grants_inference(&scopes) {
            return Err(Error::MalformedTokenResponse(
                "granted scopes lack user:inference",
            ));
        }
        Ok(OAuthTokens {
            access: AccessToken::new(self.access_token),
            refresh,
            expires_at,
            refresh_expires_at,
            scopes,
            account: self
                .account
                .or_else(|| prior.and_then(|tokens| tokens.account.clone())),
            organization: self
                .organization
                .or_else(|| prior.and_then(|tokens| tokens.organization.clone())),
        })
    }
}

/// Builds the browser authorization URL for a login attempt.
pub struct AuthorizeRequest<'a> {
    /// Endpoint set (authorize URL, client id, redirect).
    pub endpoints: &'a Endpoints,
    /// PKCE pair whose challenge is embedded in the URL.
    pub pkce: &'a PkcePair,
    /// Anti-CSRF state.
    pub state: &'a str,
    /// Scopes to request.
    pub scopes: &'a [Scope],
}

impl std::fmt::Debug for AuthorizeRequest<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorizeRequest")
            .field("endpoints", self.endpoints)
            .field("pkce", self.pkce)
            .field("state", &"***")
            .field("scopes", &self.scopes)
            .finish()
    }
}

impl AuthorizeRequest<'_> {
    /// Render the full authorization URL.
    pub fn to_url(&self) -> Result<url::Url> {
        let mut url = url::Url::parse(&self.endpoints.authorize_url)?;
        url.query_pairs_mut()
            .append_pair("code", "true")
            .append_pair("client_id", &self.endpoints.client_id)
            .append_pair("response_type", "code")
            .append_pair("redirect_uri", &self.endpoints.redirect_uri)
            .append_pair("scope", &endpoints::scope_param(self.scopes))
            .append_pair("code_challenge", &self.pkce.challenge)
            .append_pair("code_challenge_method", CODE_CHALLENGE_METHOD)
            .append_pair("state", self.state);
        Ok(url)
    }
}

/// Split a manual-paste redirect value (`code#state`) and CSRF-verify the
/// returned state against the locally generated one (constant-time). Returns
/// just the authorization code.
pub fn parse_redirect_code(pasted: &str, expected_state: &str) -> Result<String> {
    let (code, state) = pasted
        .trim()
        .rsplit_once('#')
        .ok_or(Error::InvalidRedirect)?;
    if !constant_time_eq(state.as_bytes(), expected_state.as_bytes()) {
        return Err(Error::StateMismatch);
    }
    Ok(code.to_owned())
}

/// Extract the error code from a token-endpoint error body, accepting both
/// `{"error":"invalid_grant"}` and `{"error":{"type":"invalid_grant"}}`.
#[cfg(any(feature = "client", test))]
pub(crate) fn parse_error_code(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let error = value.get("error")?;
    if let Some(code) = error.as_str() {
        return Some(code.to_owned());
    }
    error
        .get("type")
        .and_then(|t| t.as_str())
        .map(str::to_owned)
}

/// Parse a retry cooldown (ms) from `retry-after-ms` (preferred) or
/// `retry-after` (seconds), clamped to [`MAX_RETRY_AFTER_MS`].
#[cfg(feature = "client")]
pub(crate) fn parse_retry_after_ms(headers: &reqwest::header::HeaderMap) -> Option<i64> {
    if let Some(ms) = headers
        .get("retry-after-ms")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<i64>().ok())
    {
        return Some(ms.clamp(0, MAX_RETRY_AFTER_MS));
    }
    let secs = headers
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<i64>().ok())?;
    Some((secs.saturating_mul(1000)).clamp(0, MAX_RETRY_AFTER_MS))
}

/// Connect timeout of the client [`OAuthClient::new`] builds.
#[cfg(feature = "client")]
pub const OAUTH_HTTP_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Whole-request timeout of the client [`OAuthClient::new`] builds. Strictly
/// shorter than the 30 s refresh claim
/// ([`crate::refresh_claim::REFRESH_LEASE_TTL_SECS`]): a token POST that
/// outlived the claim would let a second process claim and present the same
/// refresh token, which revokes the family.
#[cfg(feature = "client")]
pub const OAUTH_HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

#[cfg(all(feature = "client", feature = "store"))]
const _: () = assert!(
    OAUTH_HTTP_TIMEOUT.as_secs() < crate::refresh_claim::REFRESH_LEASE_TTL_SECS as u64
        && OAUTH_HTTP_CONNECT_TIMEOUT.as_secs() < OAUTH_HTTP_TIMEOUT.as_secs()
);

/// The HTTP client [`OAuthClient::new`] uses: rustls, with
/// [`OAUTH_HTTP_CONNECT_TIMEOUT`] and [`OAUTH_HTTP_TIMEOUT`].
#[cfg(feature = "client")]
pub fn default_oauth_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(OAUTH_HTTP_CONNECT_TIMEOUT)
        .timeout(OAUTH_HTTP_TIMEOUT)
        .build()
        .unwrap_or_default()
}

/// Async client for the Anthropic OAuth token endpoint.
#[cfg(feature = "client")]
#[derive(Clone)]
pub struct OAuthClient {
    http: reqwest::Client,
    endpoints: Endpoints,
    require_loopback: bool,
    #[cfg(feature = "store")]
    native_publish: crate::credentials::NativePublish,
    #[cfg(feature = "store")]
    claude_code_backend: Option<crate::credentials::CredentialBackend>,
}

#[cfg(feature = "client")]
impl OAuthClient {
    /// Client with a fresh [`reqwest::Client`] bounded by
    /// [`OAUTH_HTTP_CONNECT_TIMEOUT`] and [`OAUTH_HTTP_TIMEOUT`].
    pub fn new(endpoints: Endpoints) -> Self {
        Self {
            http: default_oauth_http_client(),
            endpoints,
            require_loopback: false,
            #[cfg(feature = "store")]
            native_publish: crate::credentials::NativePublish::from_env(),
            #[cfg(feature = "store")]
            claude_code_backend: None,
        }
    }

    /// Client reusing a caller-provided [`reqwest::Client`] (shared pool).
    ///
    /// The caller's client may have no timeout; the shared refresh path
    /// ([`OAuthClient::refresh_shared`]) bounds its own token POST inside the
    /// claim regardless.
    pub fn with_http(http: reqwest::Client, endpoints: Endpoints) -> Self {
        Self {
            http,
            endpoints,
            require_loopback: false,
            #[cfg(feature = "store")]
            native_publish: crate::credentials::NativePublish::from_env(),
            #[cfg(feature = "store")]
            claude_code_backend: None,
        }
    }

    /// Force OAuth test mode for this client regardless of
    /// [`OAUTH_TEST_MODE_ENV`](endpoints::OAUTH_TEST_MODE_ENV): every OAuth call
    /// to a non-loopback host fails with [`Error::Config`] before a byte is
    /// sent. For hosts whose test-mode flag does not live in the process
    /// environment (a JS runtime's `process.env`, a config file). `false`
    /// leaves the environment in charge; it never turns test mode off.
    pub fn require_loopback(mut self, require: bool) -> Self {
        self.require_loopback = require;
        self
    }

    /// Whether (and where) a rotation this client commits through
    /// [`OAuthClient::refresh_shared`] is published to Claude Code's
    /// credential file (only ever when that file still holds the spent
    /// token). Default: [`NativePublish::from_env`](crate::credentials::NativePublish::from_env),
    /// i.e. `Auto` unless `ANTHROPIC_NATIVE_PUBLISH=0`; `Auto` is suppressed
    /// in OAuth test mode.
    #[cfg(feature = "store")]
    pub fn native_publish(mut self, policy: crate::credentials::NativePublish) -> Self {
        self.native_publish = policy;
        self
    }

    /// The native-publish policy (see [`OAuthClient::native_publish`]).
    #[cfg(feature = "store")]
    pub fn native_publish_policy(&self) -> &crate::credentials::NativePublish {
        &self.native_publish
    }

    /// Reach Claude Code's credentials through `backend` instead of the one
    /// the policy resolves (the file, or the Keychain on macOS when there is
    /// no `.credentials.json`; [`crate::credentials::CredentialBackend::from_lookup`]).
    /// For hosts that know better, and for tests of the Keychain backend
    /// against a fake `security`.
    #[cfg(feature = "store")]
    pub fn claude_code_backend(mut self, backend: crate::credentials::CredentialBackend) -> Self {
        self.claude_code_backend = Some(backend);
        self
    }

    /// The backend override (see [`OAuthClient::claude_code_backend`]).
    #[cfg(feature = "store")]
    pub fn claude_code_backend_override(&self) -> Option<&crate::credentials::CredentialBackend> {
        self.claude_code_backend.as_ref()
    }

    /// Whether this client is in OAuth test mode (forced, or from the
    /// environment).
    pub fn is_test_mode(&self) -> bool {
        self.require_loopback || endpoints::oauth_test_mode()
    }

    fn ensure_allowed(&self, url: &str) -> Result<()> {
        endpoints::check_oauth_url(url, self.is_test_mode())
    }

    /// The endpoint set this client targets.
    pub fn endpoints(&self) -> &Endpoints {
        &self.endpoints
    }

    /// Exchange an authorization code (already CSRF-checked via
    /// [`parse_redirect_code`]) for a token set.
    pub async fn exchange_code(
        &self,
        code: &str,
        verifier: &PkceVerifier,
        state: &str,
    ) -> Result<OAuthTokens> {
        let body = TokenRequest::AuthorizationCode {
            code: code.to_owned(),
            redirect_uri: self.endpoints.redirect_uri.clone(),
            client_id: self.endpoints.client_id.clone(),
            code_verifier: verifier.expose().to_owned(),
            state: state.to_owned(),
        };
        self.post_token(body, None).await
    }

    /// Renew a complete OAuth session, carrying prior refresh-token expiry,
    /// scopes, account, and organization metadata forward when the server omits
    /// them. Refuses to contact the endpoint after the refresh token expires.
    pub async fn refresh(&self, prior: &OAuthTokens) -> Result<OAuthTokens> {
        // A custody tombstone or an empty slot is not a refresh credential:
        // presenting it would at best burn a request and at worst leak the
        // vault marker upstream. Refuse locally, before any I/O.
        crate::token::ensure_not_custody_tombstone(prior.refresh.expose(), "anthropic")?;
        if prior.refresh.expose().trim().is_empty() {
            return Err(Error::ExpiredNoRefresh);
        }
        if prior.is_refresh_expired(Utc::now()) {
            return Err(Error::RefreshTokenExpired);
        }
        let body = TokenRequest::RefreshToken {
            refresh_token: prior.refresh.expose().to_owned(),
            client_id: self.endpoints.client_id.clone(),
            scope: endpoints::scope_param(&endpoints::REFRESH_SCOPES),
        };
        self.post_token(body, Some(prior)).await
    }

    /// Prepare any credential for request dispatch, proactively refreshing OAuth
    /// sessions when they are expired or inside the refresh leeway.
    pub async fn prepare_credential(
        &self,
        credential: &crate::token::Credential,
    ) -> Result<crate::token::Credential> {
        match credential {
            crate::token::Credential::ApiKey { .. } => {
                credential.validate_for_request(Utc::now())?;
                Ok(credential.clone())
            }
            crate::token::Credential::Oauth(tokens) => {
                if !tokens.needs_refresh(Utc::now()) {
                    credential.validate_for_request(Utc::now())?;
                    return Ok(credential.clone());
                }
                self.refresh(tokens)
                    .await
                    .map(crate::token::Credential::Oauth)
            }
        }
    }

    /// Prepare one account for request dispatch, refreshing its OAuth session
    /// when necessary and synchronizing any returned token metadata.
    pub async fn prepare_account(
        &self,
        account: &crate::account::Account,
    ) -> Result<crate::account::Account> {
        let credential = self.prepare_credential(&account.credential).await?;
        let mut prepared = account.clone();
        match credential {
            crate::token::Credential::Oauth(tokens) => prepared.replace_oauth_tokens(tokens)?,
            crate::token::Credential::ApiKey { key } => {
                prepared.credential = crate::token::Credential::ApiKey { key };
            }
        }
        Ok(prepared)
    }

    /// Resolve, refresh if needed, and persist the chosen account from a shared
    /// account store path.
    ///
    /// A refresh goes through [`OAuthClient::refresh_shared`]: the account's
    /// refresh lease is claimed before the token endpoint is called, a
    /// known-dead token is never presented, a peer's rotation is adopted
    /// instead of re-spending, and the rotation is committed to the store with
    /// compare-and-swap so the next reader never sees the spent token.
    #[cfg(feature = "store")]
    pub async fn prepare_account_in_store(
        &self,
        path: &Path,
        account_id: &str,
    ) -> Result<crate::account::Account> {
        let snapshot = crate::store::AccountStore::load_or_migrate_from(path, &[])?;
        let account = snapshot
            .store
            .get(account_id)
            .cloned()
            .ok_or_else(|| Error::UnknownAccount(account_id.to_owned()))?;
        let crate::token::Credential::Oauth(tokens) = &account.credential else {
            return self.prepare_account(&account).await;
        };
        if !tokens.needs_refresh(Utc::now()) {
            return self.prepare_account(&account).await;
        }
        let outcome = self
            .refresh_shared(
                path,
                tokens,
                &crate::refresh::SharedRefreshOptions::default(),
            )
            .await?;
        let reloaded = crate::store::AccountStore::load_or_migrate_from(path, &[])?;
        let persisted = reloaded
            .store
            .get(account_id)
            .cloned()
            .ok_or_else(|| Error::UnknownAccount(account_id.to_owned()))?;
        match &persisted.credential {
            crate::token::Credential::Oauth(stored)
                if stored.refresh == outcome.tokens.refresh
                    || !stored.needs_refresh(Utc::now()) =>
            {
                Ok(persisted)
            }
            _ => Err(Error::RefreshRefused(
                "oauth refresh outcome does not match the persisted account".into(),
            )),
        }
    }

    /// Pick the current shared-store account, refresh it if needed, and persist
    /// any rotated OAuth session back into the store.
    #[cfg(feature = "store")]
    pub async fn prepare_picked_account_in_store(
        &self,
        path: &Path,
        now: DateTime<Utc>,
    ) -> Result<crate::account::Account> {
        let snapshot = crate::store::AccountStore::load_or_migrate_from(path, &[])?;
        let account_id = snapshot.store.pick(now)?.id.clone();
        self.prepare_account_in_store(path, &account_id).await
    }

    /// Revoke a refresh token without modifying local credential state.
    pub async fn revoke(&self, refresh: &RefreshToken) -> Result<RevokeOutcome> {
        self.ensure_allowed(&self.endpoints.revoke_url)?;
        let response = self
            .http
            .post(&self.endpoints.revoke_url)
            .header("accept", endpoints::OAUTH_HTTP_ACCEPT)
            .header("user-agent", endpoints::OAUTH_HTTP_USER_AGENT)
            .json(&serde_json::json!({
                "token": refresh.expose(),
                "token_type_hint": "refresh_token",
                "client_id": &self.endpoints.client_id,
            }))
            .send()
            .await?;
        if response.status().is_success() {
            return Ok(RevokeOutcome::Revoked);
        }
        let retry_after_ms = parse_retry_after_ms(response.headers());
        let status = response.status().as_u16();
        let raw = redacted_response_body(response, &[refresh.expose()]).await;
        let error_code = parse_error_code(&raw);
        if status == 400
            && error_code
                .as_deref()
                .is_some_and(|code| code == "invalid_token" || code == "invalid_grant")
        {
            return Ok(RevokeOutcome::AlreadyInactive);
        }
        Err(Error::Endpoint {
            status,
            permanent: status == 400 || status == 401 || status == 403,
            error_code,
            retry_after_ms,
            body: redact_secrets(&raw),
        })
    }

    /// Fetch Claude.ai OAuth usage data.
    pub async fn usage(&self, access: &AccessToken) -> Result<serde_json::Value> {
        self.ensure_allowed(&self.endpoints.usage_url)?;
        let resp = self
            .http
            .get(&self.endpoints.usage_url)
            .header("authorization", format!("Bearer {}", access.expose()))
            .header("anthropic-beta", endpoints::OAUTH_BETA)
            .header("anthropic-version", endpoints::ANTHROPIC_VERSION)
            .header("content-type", "application/json")
            .send()
            .await?;
        let status = resp.status();
        if status.is_success() {
            return Ok(resp.json().await?);
        }
        let retry_after_ms = parse_retry_after_ms(resp.headers());
        let raw = redacted_response_body(resp, &[access.expose()]).await;
        let code = status.as_u16();
        Err(Error::Endpoint {
            status: code,
            permanent: code == 403,
            error_code: None,
            retry_after_ms,
            body: redact_secrets(&raw),
        })
    }

    async fn post_token(
        &self,
        body: TokenRequest,
        prior: Option<&OAuthTokens>,
    ) -> Result<OAuthTokens> {
        self.ensure_allowed(&self.endpoints.token_url)?;
        let resp = self
            .http
            .post(&self.endpoints.token_url)
            .header("accept", endpoints::OAUTH_HTTP_ACCEPT)
            .header("user-agent", endpoints::OAUTH_HTTP_USER_AGENT)
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        if status.is_success() {
            let token: TokenResponse = resp.json().await?;
            return token.into_tokens(Utc::now(), prior);
        }
        let retry_after_ms = parse_retry_after_ms(resp.headers());
        let secrets = match &body {
            TokenRequest::AuthorizationCode {
                code,
                code_verifier,
                state,
                ..
            } => vec![code.as_str(), code_verifier.as_str(), state.as_str()],
            TokenRequest::RefreshToken { refresh_token, .. } => {
                vec![refresh_token.as_str()]
            }
        };
        let raw = redacted_response_body(resp, &secrets).await;
        let error_code = parse_error_code(&raw);
        let code = status.as_u16();
        let permanent = code == 401
            || code == 403
            || (code == 400
                && error_code
                    .as_deref()
                    .is_some_and(|e| KNOWN_PERMANENT_OAUTH_ERRORS.contains(&e)));
        Err(Error::Endpoint {
            status: code,
            permanent,
            error_code,
            retry_after_ms,
            body: redact_secrets(&raw),
        })
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "client")]
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[cfg(feature = "client")]
    use tokio::net::TcpListener;

    use super::*;
    use crate::endpoints::AUTHORIZE_SCOPES;

    fn now() -> DateTime<Utc> {
        use chrono::TimeZone;
        Utc.timestamp_opt(1_700_000_000, 0).unwrap()
    }

    const VALID_ACCESS: &str = "sk-ant-oat01-abcdefghijklmnopqrstuvwxyz012345";
    const VALID_REFRESH: &str = "sk-ant-ort01-abcdefghijklmnopqrstuvwxyz012345";
    const NEW_REFRESH: &str = "sk-ant-ort01-ZZZZZZZZZZZZZZZZZZZZ99999";

    fn prior_tokens() -> OAuthTokens {
        OAuthTokens {
            access: AccessToken::new(VALID_ACCESS),
            refresh: RefreshToken::new(VALID_REFRESH),
            expires_at: now() + Duration::hours(1),
            refresh_expires_at: Some(now() + Duration::days(30)),
            scopes: vec!["user:profile".into(), "user:inference".into()],
            account: Some(TokenAccount {
                uuid: "account-id".into(),
                email_address: Some("user@example.com".into()),
            }),
            organization: Some(TokenOrganization {
                uuid: "organization-id".into(),
            }),
        }
    }

    #[test]
    fn token_request_serializes_grant_type_inline() {
        let req = TokenRequest::RefreshToken {
            refresh_token: "r".into(),
            client_id: "c".into(),
            scope: "user:inference".into(),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["grant_type"], "refresh_token");
        assert_eq!(json["refresh_token"], "r");
    }

    #[test]
    fn oauth_wire_types_redact_all_secrets_from_debug() {
        let request = TokenRequest::AuthorizationCode {
            code: "secret-code".into(),
            redirect_uri: "http://localhost/callback".into(),
            client_id: "client".into(),
            code_verifier: "secret-verifier".into(),
            state: "secret-state".into(),
        };
        let debug = format!("{request:?}");
        for secret in ["secret-code", "secret-verifier", "secret-state"] {
            assert!(!debug.contains(secret));
        }

        let response = TokenResponse {
            access_token: "secret-access".into(),
            refresh_token: Some("secret-refresh".into()),
            expires_in: 3600,
            refresh_token_expires_in: None,
            scope: None,
            token_type: None,
            account: None,
            organization: None,
        };
        let debug = format!("{response:?}");
        assert!(!debug.contains("secret-access"));
        assert!(!debug.contains("secret-refresh"));
    }

    #[test]
    fn into_tokens_keeps_prior_refresh_when_absent() {
        let prior = prior_tokens();
        let resp = TokenResponse {
            access_token: VALID_ACCESS.into(),
            refresh_token: None,
            expires_in: 3600,
            refresh_token_expires_in: None,
            scope: Some("user:profile user:inference".into()),
            token_type: Some("Bearer".into()),
            account: None,
            organization: None,
        };
        let tokens = resp.into_tokens(now(), Some(&prior)).unwrap();
        assert_eq!(tokens.refresh.expose(), VALID_REFRESH);
        assert_eq!(tokens.expires_at, now() + Duration::seconds(3600));
        assert_eq!(tokens.refresh_expires_at, prior.refresh_expires_at);
        assert_eq!(tokens.scopes, prior.scopes);
        assert_eq!(tokens.account, prior.account);
        assert_eq!(tokens.organization, prior.organization);
    }

    #[test]
    fn into_tokens_takes_rotated_refresh_when_present() {
        let prior = prior_tokens();
        let resp = TokenResponse {
            access_token: VALID_ACCESS.into(),
            refresh_token: Some(NEW_REFRESH.into()),
            expires_in: 3600,
            refresh_token_expires_in: None,
            scope: None,
            token_type: None,
            account: None,
            organization: None,
        };
        let tokens = resp.into_tokens(now(), Some(&prior)).unwrap();
        assert_eq!(tokens.refresh.expose(), NEW_REFRESH);
    }

    #[test]
    fn into_tokens_persists_reported_refresh_expiry() {
        let resp = TokenResponse {
            access_token: VALID_ACCESS.into(),
            refresh_token: Some(VALID_REFRESH.into()),
            expires_in: 3600,
            refresh_token_expires_in: Some(86_400),
            scope: Some("user:inference".into()),
            token_type: Some("Bearer".into()),
            account: None,
            organization: None,
        };
        let tokens = resp.into_tokens(now(), None).unwrap();
        assert_eq!(tokens.refresh_expires_at, Some(now() + Duration::days(1)));
    }

    #[test]
    fn into_tokens_rejects_scopes_without_inference() {
        let resp = TokenResponse {
            access_token: VALID_ACCESS.into(),
            refresh_token: Some(VALID_REFRESH.into()),
            expires_in: 3600,
            refresh_token_expires_in: None,
            scope: Some("user:profile user:mcp_servers".into()),
            token_type: None,
            account: None,
            organization: None,
        };
        let err = resp.into_tokens(now(), None).unwrap_err();
        assert!(matches!(err, Error::MalformedTokenResponse(_)));
    }

    /// A first exchange (no prior session) must carry a well-formed refresh
    /// token: an empty or missing one is refused, never stored.
    #[test]
    fn a_first_exchange_without_a_usable_refresh_token_is_refused() {
        for refresh in [Some(String::new()), Some("r".to_owned()), None] {
            let resp = TokenResponse {
                access_token: VALID_ACCESS.into(),
                refresh_token: refresh.clone(),
                expires_in: 3600,
                refresh_token_expires_in: None,
                scope: None,
                token_type: None,
                account: None,
                organization: None,
            };
            assert!(
                matches!(
                    resp.into_tokens(now(), None),
                    Err(Error::MalformedTokenResponse("refresh_token"))
                ),
                "{refresh:?}"
            );
        }
        let bad_access = TokenResponse {
            access_token: "a".into(),
            refresh_token: Some(VALID_REFRESH.into()),
            expires_in: 3600,
            refresh_token_expires_in: None,
            scope: None,
            token_type: None,
            account: None,
            organization: None,
        };
        assert!(matches!(
            bad_access.into_tokens(now(), None),
            Err(Error::MalformedTokenResponse("access_token"))
        ));
    }

    #[test]
    fn into_tokens_rejects_non_positive_lifetime() {
        let resp = TokenResponse {
            access_token: VALID_ACCESS.into(),
            refresh_token: Some(VALID_REFRESH.into()),
            expires_in: 0,
            refresh_token_expires_in: None,
            scope: None,
            token_type: None,
            account: None,
            organization: None,
        };
        assert!(matches!(
            resp.into_tokens(now(), None),
            Err(Error::MalformedTokenResponse("expires_in"))
        ));
    }

    #[test]
    fn authorize_url_carries_pkce_and_scopes() {
        let endpoints = Endpoints::prod();
        let pkce = PkcePair::from_verifier(PkceVerifier::new(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        ));
        let req = AuthorizeRequest {
            endpoints: &endpoints,
            pkce: &pkce,
            state: "the-state",
            scopes: &AUTHORIZE_SCOPES,
        };
        let url = req.to_url().unwrap();
        let pairs: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(pairs["client_id"], endpoints::CLIENT_ID);
        assert_eq!(pairs["response_type"], "code");
        assert_eq!(pairs["code_challenge_method"], "S256");
        assert_eq!(pairs["code_challenge"], pkce.challenge);
        assert_eq!(pairs["state"], "the-state");
        assert!(pairs["scope"].contains("user:inference"));
    }

    #[test]
    fn redirect_parse_splits_and_verifies_state() {
        assert_eq!(
            parse_redirect_code("thecode#thestate", "thestate").unwrap(),
            "thecode"
        );
        assert!(matches!(
            parse_redirect_code("thecode#wrong", "thestate"),
            Err(Error::StateMismatch)
        ));
        assert!(matches!(
            parse_redirect_code("nostate", "thestate"),
            Err(Error::InvalidRedirect)
        ));
    }

    #[test]
    fn error_code_parses_both_shapes() {
        assert_eq!(
            parse_error_code(r#"{"error":"invalid_grant"}"#).as_deref(),
            Some("invalid_grant")
        );
        assert_eq!(
            parse_error_code(r#"{"error":{"type":"invalid_client"}}"#).as_deref(),
            Some("invalid_client")
        );
        assert_eq!(parse_error_code("not json"), None);
    }

    #[cfg(feature = "client")]
    #[test]
    fn retry_after_prefers_ms_then_seconds() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("retry-after", "30".parse().unwrap());
        assert_eq!(parse_retry_after_ms(&headers), Some(30_000));
        headers.insert("retry-after-ms", "1500".parse().unwrap());
        assert_eq!(parse_retry_after_ms(&headers), Some(1_500));
    }

    #[cfg(feature = "client")]
    #[test]
    fn retry_after_is_clamped_to_a_day() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("retry-after-ms", "999999999999".parse().unwrap());
        assert_eq!(parse_retry_after_ms(&headers), Some(MAX_RETRY_AFTER_MS));
    }

    #[cfg(feature = "client")]
    async fn serve_once(
        status: u16,
        response_body: String,
    ) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let header_end = loop {
                let mut chunk = [0u8; 1024];
                let read = stream.read(&mut chunk).await.unwrap();
                assert!(read > 0);
                request.extend_from_slice(&chunk[..read]);
                if let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n")
                {
                    break position + 4;
                }
            };
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let lower = line.to_ascii_lowercase();
                    lower
                        .strip_prefix("content-length:")
                        .and_then(|value| value.trim().parse::<usize>().ok())
                })
                .unwrap_or_default();
            while request.len() < header_end + content_length {
                let mut chunk = [0u8; 1024];
                let read = stream.read(&mut chunk).await.unwrap();
                assert!(read > 0);
                request.extend_from_slice(&chunk[..read]);
            }
            let reason = if status == 200 { "OK" } else { "Bad Request" };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{response_body}",
                response_body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8(request).unwrap()
        });
        (format!("http://{address}"), handle)
    }

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn refresh_expiry_fails_locally_and_is_permanent() {
        let mut prior = prior_tokens();
        prior.refresh_expires_at = Some(Utc::now() - Duration::seconds(1));
        let mut endpoints = Endpoints::prod();
        endpoints.token_url = "http://127.0.0.1:1/must-not-be-called".into();
        let error = OAuthClient::new(endpoints)
            .refresh(&prior)
            .await
            .unwrap_err();
        assert!(matches!(error, Error::RefreshTokenExpired));
        assert!(error.is_permanent());
    }

    /// Test mode (always on in this crate's unit tests): a non-loopback OAuth
    /// host is refused with `Error::Config` before a connection is opened.
    /// `0.0.0.0` reaches a local listener on Linux but is not loopback, so the
    /// listener proves no byte left the client.
    #[cfg(feature = "client")]
    #[tokio::test]
    async fn test_mode_refuses_non_loopback_oauth_hosts_before_connecting() {
        let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = accepted.clone();
        let server = tokio::spawn(async move {
            while let Ok((_socket, _)) = listener.accept().await {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        });
        let mut endpoints = Endpoints::prod();
        endpoints.token_url = format!("http://0.0.0.0:{port}/v1/oauth/token");
        endpoints.revoke_url = format!("http://0.0.0.0:{port}/v1/oauth/token/revoke");
        endpoints.usage_url = format!("http://0.0.0.0:{port}/api/oauth/usage");
        let mut prior = prior_tokens();
        prior.expires_at = Utc::now() - Duration::seconds(5);
        prior.refresh_expires_at = Some(Utc::now() + Duration::days(30));
        for client in [
            OAuthClient::new(endpoints.clone()),
            OAuthClient::new(Endpoints::prod()),
        ] {
            let error = client.refresh(&prior).await.unwrap_err();
            assert!(matches!(error, Error::Config(_)), "{error}");
            assert!(error.is_permanent());
            assert!(!error.to_string().contains(VALID_REFRESH));
            let error = client
                .exchange_code("code", &PkceVerifier::new("v".repeat(43)), "state")
                .await
                .unwrap_err();
            assert!(matches!(error, Error::Config(_)), "{error}");
            let error = client.revoke(&prior.refresh).await.unwrap_err();
            assert!(matches!(error, Error::Config(_)), "{error}");
            let error = client.usage(&prior.access).await.unwrap_err();
            assert!(matches!(error, Error::Config(_)), "{error}");
            let error = client
                .prepare_credential(&crate::token::Credential::Oauth(prior.clone()))
                .await
                .unwrap_err();
            assert!(matches!(error, Error::Config(_)), "{error}");
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 0);
        server.abort();
    }

    #[cfg(feature = "client")]
    #[test]
    fn require_loopback_forces_test_mode_and_never_clears_it() {
        let client = OAuthClient::new(Endpoints::prod());
        // Unit tests always run in test mode (cfg(test)).
        assert!(client.is_test_mode());
        assert!(client.clone().require_loopback(false).is_test_mode());
        let forced = client.require_loopback(true);
        assert!(forced.is_test_mode());
        assert!(matches!(
            forced.ensure_allowed(endpoints::TOKEN_URL),
            Err(Error::Config(_))
        ));
        forced
            .ensure_allowed("http://127.0.0.1:9/v1/oauth/token")
            .unwrap();
    }

    // Port of auth-guards.test.ts: refresh refuses empty/whitespace and
    // custody-tombstone refresh tokens before any network I/O.
    #[cfg(feature = "client")]
    #[tokio::test]
    async fn refresh_refuses_empty_and_tombstone_refresh_tokens_locally() {
        let mut endpoints = Endpoints::prod();
        endpoints.token_url = "http://127.0.0.1:1/must-not-be-called".into();
        let client = OAuthClient::new(endpoints);
        for empty in ["", "   "] {
            let mut prior = prior_tokens();
            prior.refresh = RefreshToken::new(empty);
            let error = client.refresh(&prior).await.unwrap_err();
            assert!(
                matches!(error, Error::ExpiredNoRefresh),
                "{empty:?}: {error}"
            );
        }
        for tombstone in [
            "claustrum-tombstone:v1:anthropic",
            "claustrum-tombstone:v1:openai",
        ] {
            let mut prior = prior_tokens();
            prior.refresh = RefreshToken::new(tombstone);
            let error = client.refresh(&prior).await.unwrap_err();
            assert!(matches!(error, Error::CustodyTombstone { .. }), "{error}");
            assert!(error.is_permanent());
            assert!(!error.to_string().contains("claustrum-tombstone"));
        }
    }

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn prepare_credential_leaves_api_keys_and_fresh_oauth_unchanged() {
        let client = OAuthClient::new(Endpoints::prod());
        let api = crate::token::Credential::ApiKey {
            key: crate::token::ApiKey::new("sk-ant-api01-abcdefghijklmnopqrstuvwxyz012345"),
        };
        assert!(matches!(
            client.prepare_credential(&api).await.unwrap(),
            crate::token::Credential::ApiKey { .. }
        ));

        let oauth = crate::token::Credential::Oauth(OAuthTokens {
            access: AccessToken::new(VALID_ACCESS),
            refresh: RefreshToken::new(VALID_REFRESH),
            expires_at: Utc::now() + Duration::hours(1),
            refresh_expires_at: Some(Utc::now() + Duration::days(30)),
            scopes: vec!["user:profile".into(), "user:inference".into()],
            account: None,
            organization: None,
        });
        let prepared = client.prepare_credential(&oauth).await.unwrap();
        let crate::token::Credential::Oauth(tokens) = prepared else {
            unreachable!("expected oauth credential")
        };
        assert_eq!(tokens.access.expose(), VALID_ACCESS);
    }

    #[cfg(all(feature = "client", feature = "store"))]
    #[tokio::test]
    async fn prepare_picked_account_in_store_refreshes_and_persists_rotation() {
        let dir =
            std::env::temp_dir().join(format!("anthropic-prepare-store-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("accounts.json");
        let mut store = crate::store::AccountStore::default();
        store.upsert(crate::account::Account::new(
            "oauth",
            crate::token::Credential::Oauth(OAuthTokens {
                access: AccessToken::new(VALID_ACCESS),
                refresh: RefreshToken::new(VALID_REFRESH),
                expires_at: Utc::now() - Duration::seconds(5),
                refresh_expires_at: Some(Utc::now() + Duration::days(30)),
                scopes: vec!["user:profile".into(), "user:inference".into()],
                account: Some(TokenAccount {
                    uuid: "account-id".into(),
                    email_address: Some("user@example.com".into()),
                }),
                organization: Some(TokenOrganization {
                    uuid: "organization-id".into(),
                }),
            }),
        ));
        store.save(&path).unwrap();

        let (base_url, request) = serve_once(
            200,
            serde_json::json!({
                "access_token": "sk-ant-oat01-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
                "refresh_token": NEW_REFRESH,
                "expires_in": 3600,
                "scope": "user:profile user:inference",
                "account": {"uuid": "account-id", "email_address": "new@example.com"},
                "organization": {"uuid": "organization-id"}
            })
            .to_string(),
        )
        .await;
        let mut endpoints = Endpoints::prod();
        endpoints.token_url = format!("{base_url}/v1/oauth/token");
        let client = OAuthClient::new(endpoints);
        let prepared = client
            .prepare_picked_account_in_store(&path, Utc::now())
            .await
            .unwrap();
        assert_eq!(prepared.email.as_deref(), Some("new@example.com"));
        let crate::token::Credential::Oauth(tokens) = &prepared.credential else {
            unreachable!("expected oauth")
        };
        assert_eq!(tokens.refresh.expose(), NEW_REFRESH);
        let request = request.await.unwrap();
        assert!(request.contains(VALID_REFRESH));
        let reloaded = crate::store::AccountStore::load(&path).unwrap();
        let persisted = reloaded.get("oauth").unwrap();
        assert_eq!(persisted.email.as_deref(), Some("new@example.com"));
        let crate::token::Credential::Oauth(tokens) = &persisted.credential else {
            unreachable!("expected persisted oauth")
        };
        assert_eq!(tokens.refresh.expose(), NEW_REFRESH);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn revoke_sends_exact_native_request() {
        let (base_url, request) = serve_once(200, "{}".into()).await;
        let mut endpoints = Endpoints::prod();
        endpoints.revoke_url = format!("{base_url}/v1/oauth/token/revoke");
        let outcome = OAuthClient::new(endpoints)
            .revoke(&RefreshToken::new(VALID_REFRESH))
            .await
            .unwrap();
        assert_eq!(outcome, RevokeOutcome::Revoked);
        let request = request.await.unwrap();
        let (headers, body) = request.split_once("\r\n\r\n").unwrap();
        assert!(headers.starts_with("POST /v1/oauth/token/revoke HTTP/1.1"));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains(&format!("user-agent: {}", endpoints::OAUTH_HTTP_USER_AGENT)));
        assert!(lower.contains("accept: application/json, text/plain, */*"));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(body).unwrap(),
            serde_json::json!({
                "token": VALID_REFRESH,
                "token_type_hint": "refresh_token",
                "client_id": endpoints::CLIENT_ID,
            })
        );
    }

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn revoke_treats_an_inactive_token_as_success() {
        let (base_url, request) = serve_once(400, r#"{"error":"invalid_grant"}"#.into()).await;
        let mut endpoints = Endpoints::prod();
        endpoints.revoke_url = format!("{base_url}/v1/oauth/token/revoke");
        let outcome = OAuthClient::new(endpoints)
            .revoke(&RefreshToken::new(VALID_REFRESH))
            .await
            .unwrap();
        request.await.unwrap();
        assert_eq!(outcome, RevokeOutcome::AlreadyInactive);
    }

    /// A token endpoint that accepts the connection, reads the request and
    /// then never answers.
    #[cfg(feature = "client")]
    async fn stalling_server() -> String {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut chunk = [0u8; 4096];
                let _ = stream.read(&mut chunk).await;
                // Keep the socket open and silent.
                held.push(stream);
            }
        });
        format!("http://{address}")
    }

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn the_default_client_gives_up_before_the_refresh_claim_lapses() {
        let base = stalling_server().await;
        let mut endpoints = Endpoints::prod();
        endpoints.token_url = format!("{base}/v1/oauth/token");
        let mut prior = prior_tokens();
        prior.refresh_expires_at = Some(Utc::now() + Duration::days(30));
        let started = std::time::Instant::now();
        // 28 s: past the client's own timeout, inside the 30 s claim.
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(28),
            OAuthClient::new(endpoints).refresh(&prior),
        )
        .await
        .expect("the OAuth client must time out on its own, inside the refresh claim");
        let error = outcome.expect_err("a stalled token endpoint cannot succeed");
        assert!(
            matches!(error, Error::Http(ref e) if e.is_timeout()),
            "{error}"
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(28));
        assert!(!error.is_permanent());
    }
}
