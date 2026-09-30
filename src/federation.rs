//! Workload Identity Federation (OIDC assertion exchange) with a single-flight
//! in-memory access-token cache.

use std::ffi::OsString;
use std::future::Future;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::endpoints::{BASE_API_URL, BASE_URL_ENV, OAUTH_BETA};
use crate::error::{Error, Result};
use crate::token::AccessToken;

/// Native Claude Code WIF exchange beta.
pub const FEDERATION_BETA: &str = "oidc-federation-2026-04-01";
/// Maximum accepted OIDC assertion size.
pub const MAX_IDENTITY_TOKEN_BYTES: usize = 16 * 1024;
/// Required federation rule id environment variable.
pub const FEDERATION_RULE_ID_ENV: &str = "ANTHROPIC_FEDERATION_RULE_ID";
/// Required Anthropic organization id environment variable.
pub const ORGANIZATION_ID_ENV: &str = "ANTHROPIC_ORGANIZATION_ID";
/// Required service-account id environment variable.
pub const SERVICE_ACCOUNT_ID_ENV: &str = "ANTHROPIC_SERVICE_ACCOUNT_ID";
/// Optional workspace id environment variable.
pub const WORKSPACE_ID_ENV: &str = "ANTHROPIC_WORKSPACE_ID";
/// Projected OIDC assertion file environment variable.
pub const IDENTITY_TOKEN_FILE_ENV: &str = "ANTHROPIC_IDENTITY_TOKEN_FILE";
/// Inline OIDC assertion environment variable.
pub const IDENTITY_TOKEN_ENV: &str = "ANTHROPIC_IDENTITY_TOKEN";

const API_KEY_ENV: &str = "ANTHROPIC_API_KEY";
const AUTH_TOKEN_ENV: &str = "ANTHROPIC_AUTH_TOKEN";
const PROFILE_ENV: &str = "ANTHROPIC_PROFILE";
const ADVISORY_REFRESH_SECONDS: i64 = 120;
const MANDATORY_REFRESH_SECONDS: i64 = 30;
const WIF_USER_AGENT: &str = "anthropic-sdk-typescript/0.112.1 oidcFederationProvider";

/// IDs required to exchange an external OIDC assertion for an Anthropic token.
#[derive(Debug, Clone)]
pub struct FederationConfig {
    /// Federation rule configured in Claude Console.
    pub federation_rule_id: String,
    /// Anthropic organization receiving the token.
    pub organization_id: String,
    /// Optional service account receiving the short-lived token.
    pub service_account_id: Option<String>,
    /// Required when the rule spans multiple workspaces.
    pub workspace_id: Option<String>,
    /// Anthropic API origin.
    pub base_url: String,
}

impl FederationConfig {
    /// Production organization-level configuration.
    pub fn prod(federation_rule_id: impl Into<String>, organization_id: impl Into<String>) -> Self {
        Self {
            federation_rule_id: federation_rule_id.into(),
            organization_id: organization_id.into(),
            service_account_id: None,
            workspace_id: None,
            base_url: BASE_API_URL.to_owned(),
        }
    }

    /// Production configuration targeting a specific service account.
    pub fn for_service_account(
        federation_rule_id: impl Into<String>,
        organization_id: impl Into<String>,
        service_account_id: impl Into<String>,
    ) -> Self {
        Self {
            service_account_id: Some(service_account_id.into()),
            ..Self::prod(federation_rule_id, organization_id)
        }
    }

    fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("federation rule id", self.federation_rule_id.as_str()),
            ("organization id", self.organization_id.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(Error::Federation(format!("{name} is empty")));
            }
        }
        if self
            .service_account_id
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(Error::Federation("service account id is empty".into()));
        }
        let parsed = url::Url::parse(&self.base_url)?;
        if parsed.scheme() != "https" && !parsed.host_str().is_some_and(is_loopback_host) {
            return Err(Error::Federation(
                "base URL must use HTTPS unless it targets loopback".into(),
            ));
        }
        if !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(Error::Federation(
                "base URL must not contain credentials, a query, or a fragment".into(),
            ));
        }
        Ok(())
    }
}

fn is_loopback_host(host: &str) -> bool {
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// External OIDC assertion source. The contents are always redacted from
/// `Debug`; file-backed assertions are re-read for every exchange.
#[derive(Clone)]
pub enum IdentityTokenSource {
    /// Inline assertion supplied by the environment or caller.
    Inline(String),
    /// Projected assertion file.
    File(PathBuf),
}

impl IdentityTokenSource {
    /// Construct an inline assertion source after applying the size bound.
    pub fn inline(value: impl Into<String>) -> Result<Self> {
        let value = value.into().trim().to_owned();
        validate_assertion(&value)?;
        Ok(Self::Inline(value))
    }

    /// Construct a file-backed assertion source.
    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self::File(path.into())
    }

    /// Read a fresh assertion. File-backed sources are never cached.
    pub fn read(&self) -> Result<String> {
        match self {
            Self::Inline(value) => Ok(value.clone()),
            Self::File(path) => read_identity_token_file(path),
        }
    }
}

impl std::fmt::Debug for IdentityTokenSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inline(_) => formatter.write_str("IdentityTokenSource::Inline(***)"),
            Self::File(path) => formatter
                .debug_tuple("IdentityTokenSource::File")
                .field(path)
                .finish(),
        }
    }
}

/// Fully resolved official WIF environment configuration.
#[derive(Debug, Clone)]
pub struct FederationEnvironment {
    /// Exchange endpoint and Anthropic resource ids.
    pub config: FederationConfig,
    /// External assertion source.
    pub identity_token: IdentityTokenSource,
}

impl FederationEnvironment {
    /// Resolve official WIF environment variables.
    ///
    /// `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, and `ANTHROPIC_PROFILE`
    /// outrank federation even when set to the empty string, matching the
    /// official SDK precedence. No WIF variables returns `Ok(None)`; a partial
    /// WIF configuration is an error rather than a silent fall-through.
    pub fn from_env() -> Result<Option<Self>> {
        Self::from_lookup(|name| std::env::var_os(name))
    }

    fn from_lookup(mut get: impl FnMut(&str) -> Option<OsString>) -> Result<Option<Self>> {
        if [API_KEY_ENV, AUTH_TOKEN_ENV, PROFILE_ENV]
            .iter()
            .any(|name| get(name).is_some())
        {
            return Ok(None);
        }
        let rule = get_non_empty(&mut get, FEDERATION_RULE_ID_ENV);
        let organization = get_non_empty(&mut get, ORGANIZATION_ID_ENV);
        let service_account = get_non_empty(&mut get, SERVICE_ACCOUNT_ID_ENV);
        let workspace = get_non_empty(&mut get, WORKSPACE_ID_ENV);
        let inline = get_non_empty(&mut get, IDENTITY_TOKEN_ENV);
        let file = get_non_empty(&mut get, IDENTITY_TOKEN_FILE_ENV);
        let any = rule.is_some()
            || organization.is_some()
            || service_account.is_some()
            || workspace.is_some()
            || inline.is_some()
            || file.is_some();
        if !any {
            return Ok(None);
        }
        let federation_rule_id = required_env(rule, FEDERATION_RULE_ID_ENV)?;
        let organization_id = required_env(organization, ORGANIZATION_ID_ENV)?;
        let identity_token = match (inline, file) {
            (Some(value), _) => IdentityTokenSource::inline(value)?,
            (None, Some(path)) => IdentityTokenSource::file(path),
            (None, None) => {
                return Err(Error::Federation(format!(
                    "either {IDENTITY_TOKEN_ENV} or {IDENTITY_TOKEN_FILE_ENV} is required"
                )));
            }
        };
        let base_url = get_non_empty(&mut get, BASE_URL_ENV).unwrap_or_else(|| BASE_API_URL.into());
        let config = FederationConfig {
            federation_rule_id,
            organization_id,
            service_account_id: service_account,
            workspace_id: workspace,
            base_url,
        };
        config.validate()?;
        Ok(Some(Self {
            config,
            identity_token,
        }))
    }
}

fn get_non_empty(get: &mut impl FnMut(&str) -> Option<OsString>, name: &str) -> Option<String> {
    get(name)
        .and_then(|value| value.into_string().ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn required_env(value: Option<String>, name: &str) -> Result<String> {
    value.ok_or_else(|| Error::Federation(format!("{name} is required when WIF is configured")))
}

fn read_identity_token_file(path: &Path) -> Result<String> {
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(Error::Federation(
            "identity token path is not a regular file".into(),
        ));
    }
    if metadata.len() > MAX_IDENTITY_TOKEN_BYTES as u64 {
        return Err(Error::Federation(
            "identity token exceeds the 16 KiB assertion limit".into(),
        ));
    }
    let value = std::fs::read_to_string(path)?;
    let value = value.trim().to_owned();
    validate_assertion(&value)?;
    Ok(value)
}

fn validate_assertion(assertion: &str) -> Result<()> {
    if assertion.is_empty() {
        return Err(Error::Federation("identity token is empty".into()));
    }
    if assertion.len() > MAX_IDENTITY_TOKEN_BYTES {
        return Err(Error::Federation(
            "identity token exceeds the 16 KiB assertion limit".into(),
        ));
    }
    if assertion
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(Error::Federation(
            "identity token contains whitespace or control characters".into(),
        ));
    }
    Ok(())
}

/// Short-lived federated bearer credential.
#[derive(Clone)]
pub struct FederatedToken {
    /// Access token sent as `Authorization: Bearer`.
    pub access: AccessToken,
    /// Absolute access-token expiry.
    pub expires_at: DateTime<Utc>,
    /// Granted scope string when supplied by the endpoint.
    pub scope: Option<String>,
}

impl std::fmt::Debug for FederatedToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FederatedToken")
            .field("access", &self.access)
            .field("expires_at", &self.expires_at)
            .field("scope", &self.scope)
            .finish()
    }
}

#[derive(Serialize)]
struct ExchangeRequest<'a> {
    grant_type: &'static str,
    assertion: &'a str,
    federation_rule_id: &'a str,
    organization_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    service_account_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace_id: Option<&'a str>,
}

#[derive(Deserialize)]
struct ExchangeResponse {
    access_token: String,
    expires_in: i64,
    #[serde(default)]
    scope: Option<String>,
}

/// Reqwest-backed federation exchange with advisory/mandatory refresh windows.
pub struct FederationClient {
    http: reqwest::Client,
    config: FederationConfig,
    cached: Mutex<Option<FederatedToken>>,
}

impl FederationClient {
    /// Create a provider with a fresh HTTP pool.
    pub fn new(config: FederationConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            http: reqwest::Client::new(),
            config,
            cached: Mutex::new(None),
        })
    }

    /// Reuse a caller-provided HTTP pool.
    pub fn with_http(http: reqwest::Client, config: FederationConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            http,
            config,
            cached: Mutex::new(None),
        })
    }

    /// Resolve a bearer token using the current wall-clock time.
    /// `identity_token` is called only when an exchange is necessary and must
    /// return a fresh external assertion.
    pub async fn token<P, F>(&self, identity_token: P) -> Result<FederatedToken>
    where
        P: FnOnce() -> F,
        F: Future<Output = Result<String>>,
    {
        self.token_at(Utc::now(), identity_token).await
    }

    /// Resolve a bearer token at an explicit clock value. This deterministic
    /// form is intended for tests and callers with a trusted clock source.
    pub async fn token_at<P, F>(
        &self,
        now: DateTime<Utc>,
        identity_token: P,
    ) -> Result<FederatedToken>
    where
        P: FnOnce() -> F,
        F: Future<Output = Result<String>>,
    {
        let mut cached = self.cached.lock().await;
        if let Some(current) = cached.as_ref() {
            let remaining = current.expires_at - now;
            if remaining > Duration::seconds(ADVISORY_REFRESH_SECONDS) {
                return Ok(current.clone());
            }
            if remaining > Duration::seconds(MANDATORY_REFRESH_SECONDS) {
                match self.exchange(now, identity_token()).await {
                    Ok(refreshed) => {
                        *cached = Some(refreshed.clone());
                        return Ok(refreshed);
                    }
                    Err(_) => return Ok(current.clone()),
                }
            }
        }
        let refreshed = self.exchange(now, identity_token()).await?;
        *cached = Some(refreshed.clone());
        Ok(refreshed)
    }

    /// Resolve a token from an [`IdentityTokenSource`]. File-backed sources are
    /// re-read on every exchange.
    pub async fn token_from_source(&self, source: &IdentityTokenSource) -> Result<FederatedToken> {
        self.token(|| async { source.read() }).await
    }

    /// Drop the cached access token so the next call exchanges again.
    pub async fn invalidate(&self) {
        *self.cached.lock().await = None;
    }

    async fn exchange<F>(&self, now: DateTime<Utc>, assertion: F) -> Result<FederatedToken>
    where
        F: Future<Output = Result<String>>,
    {
        let assertion = assertion.await?;
        validate_assertion(&assertion)?;
        let url = format!(
            "{}/v1/oauth/token",
            self.config.base_url.trim_end_matches('/')
        );
        crate::endpoints::ensure_oauth_url_allowed(&url)?;
        let response = self
            .http
            .post(url)
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .header("anthropic-beta", format!("{OAUTH_BETA},{FEDERATION_BETA}"))
            .header("user-agent", WIF_USER_AGENT)
            .json(&ExchangeRequest {
                grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
                assertion: &assertion,
                federation_rule_id: &self.config.federation_rule_id,
                organization_id: &self.config.organization_id,
                service_account_id: self.config.service_account_id.as_deref(),
                workspace_id: self.config.workspace_id.as_deref(),
            })
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            return Err(Error::Endpoint {
                status: status.as_u16(),
                permanent: matches!(status.as_u16(), 400 | 401 | 403),
                error_code: None,
                retry_after_ms: None,
                body: "workload identity token exchange failed (response redacted)".into(),
            });
        }
        let body: ExchangeResponse = response.json().await?;
        if body.expires_in <= 0 {
            return Err(Error::Federation(
                "token response had invalid expires_in".into(),
            ));
        }
        if body.access_token.is_empty() || body.access_token.len() > MAX_IDENTITY_TOKEN_BYTES {
            return Err(Error::Federation(
                "token response had invalid access_token".into(),
            ));
        }
        let duration = Duration::try_seconds(body.expires_in)
            .ok_or_else(|| Error::Federation("token response expires_in overflowed".into()))?;
        let expires_at = now
            .checked_add_signed(duration)
            .ok_or_else(|| Error::Federation("token response expiry overflowed".into()))?;
        Ok(FederatedToken {
            access: AccessToken::new(body.access_token),
            expires_at,
            scope: body.scope,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use chrono::TimeZone;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    fn at(seconds: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(seconds, 0).unwrap()
    }

    fn lookup(values: HashMap<&'static str, &'static str>) -> impl FnMut(&str) -> Option<OsString> {
        move |name| values.get(name).map(OsString::from)
    }

    #[test]
    fn environment_requires_complete_wif_and_honors_higher_precedence() {
        let partial = HashMap::from([(FEDERATION_RULE_ID_ENV, "rule")]);
        assert!(FederationEnvironment::from_lookup(lookup(partial)).is_err());

        let complete = HashMap::from([
            (FEDERATION_RULE_ID_ENV, "rule"),
            (ORGANIZATION_ID_ENV, "org"),
            (SERVICE_ACCOUNT_ID_ENV, "service"),
            (IDENTITY_TOKEN_ENV, "header.payload.signature"),
        ]);
        let resolved = FederationEnvironment::from_lookup(lookup(complete))
            .unwrap()
            .unwrap();
        assert_eq!(
            resolved.config.service_account_id.as_deref(),
            Some("service")
        );

        let organization_level = HashMap::from([
            (FEDERATION_RULE_ID_ENV, "rule"),
            (ORGANIZATION_ID_ENV, "org"),
            (IDENTITY_TOKEN_ENV, "header.payload.signature"),
        ]);
        let resolved = FederationEnvironment::from_lookup(lookup(organization_level))
            .unwrap()
            .unwrap();
        assert!(resolved.config.service_account_id.is_none());

        let shadowed = HashMap::from([
            (API_KEY_ENV, ""),
            (FEDERATION_RULE_ID_ENV, "rule"),
            (ORGANIZATION_ID_ENV, "org"),
            (SERVICE_ACCOUNT_ID_ENV, "service"),
            (IDENTITY_TOKEN_ENV, "header.payload.signature"),
        ]);
        assert!(
            FederationEnvironment::from_lookup(lookup(shadowed))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn loopback_http_is_allowed_only_for_tests_and_local_development() {
        let mut config = FederationConfig::for_service_account("rule", "org", "service");
        config.base_url = "http://127.0.0.1:1234".into();
        assert!(config.validate().is_ok());
        config.base_url = "http://example.com".into();
        assert!(config.validate().is_err());
    }

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
                .find_map(|line| line.strip_prefix("content-length: "))
                .unwrap()
                .trim()
                .parse::<usize>()
                .unwrap();
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

    #[tokio::test]
    async fn exchange_body_and_native_headers_are_exact() {
        let (base_url, request) = serve_once(
            200,
            r#"{"access_token":"federated-access","expires_in":3600,"scope":"user:inference"}"#
                .into(),
        )
        .await;
        let mut config = FederationConfig::for_service_account("rule", "org", "service");
        config.workspace_id = Some("workspace".into());
        config.base_url = base_url;
        let client = FederationClient::new(config).unwrap();
        let token = client
            .token_at(at(1_700_000_000), || async {
                Ok("header.payload.signature".into())
            })
            .await
            .unwrap();
        assert_eq!(token.access.expose(), "federated-access");
        let request = request.await.unwrap();
        let (headers, body) = request.split_once("\r\n\r\n").unwrap();
        assert!(headers.starts_with("POST /v1/oauth/token HTTP/1.1"));
        let lower_headers = headers.to_ascii_lowercase();
        assert!(lower_headers.contains(&format!("anthropic-beta: {OAUTH_BETA},{FEDERATION_BETA}")));
        assert!(lower_headers.contains(&format!(
            "user-agent: {}",
            WIF_USER_AGENT.to_ascii_lowercase()
        )));
        let body: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": "header.payload.signature",
                "federation_rule_id": "rule",
                "organization_id": "org",
                "service_account_id": "service",
                "workspace_id": "workspace",
            })
        );
    }

    #[tokio::test]
    async fn exchange_errors_never_echo_the_assertion() {
        let assertion = "header.secret-payload.signature";
        let (base_url, request) = serve_once(
            400,
            format!(r#"{{"error":"invalid","assertion":"{assertion}"}}"#),
        )
        .await;
        let mut config = FederationConfig::for_service_account("rule", "org", "service");
        config.base_url = base_url;
        let client = FederationClient::new(config).unwrap();
        let error = client
            .token_at(at(1_700_000_000), || async { Ok(assertion.into()) })
            .await
            .unwrap_err();
        request.await.unwrap();
        assert!(!error.to_string().contains(assertion));
    }

    #[tokio::test]
    async fn concurrent_callers_share_one_cached_exchange() {
        let (base_url, request) = serve_once(
            200,
            r#"{"access_token":"federated-access","expires_in":3600}"#.into(),
        )
        .await;
        let mut config = FederationConfig::for_service_account("rule", "org", "service");
        config.base_url = base_url;
        let client = Arc::new(FederationClient::new(config).unwrap());
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let client = client.clone();
            tasks.push(tokio::spawn(async move {
                client
                    .token_at(at(1_700_000_000), || async {
                        Ok("header.payload.signature".into())
                    })
                    .await
                    .unwrap()
                    .access
                    .expose()
                    .to_owned()
            }));
        }
        for task in tasks {
            assert_eq!(task.await.unwrap(), "federated-access");
        }
        request.await.unwrap();
    }
}
