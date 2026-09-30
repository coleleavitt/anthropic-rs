//! Anthropic OAuth endpoints, client id, scopes, and header constants.
//!
//! Values mirror the Claude Code CLI production configuration. Runtime env
//! overrides mirror the CLI: `CLAUDE_CODE_OAUTH_CLIENT_ID` overrides the client
//! id. Every OAuth URL can also be overridden from the environment
//! ([`Endpoints::from_env`]); tests use this to point the whole OAuth surface at
//! a mock server or a dead loopback port.
//!
//! # Test mode
//!
//! With `ANTHROPIC_OAUTH_TEST_MODE=1` (and always in this crate's own unit
//! tests), every OAuth HTTP call to a host that is not loopback fails closed
//! with [`Error::Config`](crate::Error::Config) before any byte is sent. See
//! [`ensure_oauth_url_allowed`].

use std::fmt;

/// Production public OAuth client id (PKCE flow; no client secret).
pub const CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";

/// `anthropic-beta` value that opts an API request into OAuth bearer auth.
pub const OAUTH_BETA: &str = "oauth-2025-04-20";

/// `anthropic-version` sent on every Anthropic API request.
pub const ANTHROPIC_VERSION: &str = "2023-06-01";

/// OAuth token endpoint (authorization-code exchange and refresh grant).
pub const TOKEN_URL: &str = "https://platform.claude.com/v1/oauth/token";

/// Axios fingerprint emitted by native Claude Code's OAuth HTTP stack.
pub const OAUTH_HTTP_USER_AGENT: &str = "axios/1.15.2";

/// Native OAuth `Accept` header.
pub const OAUTH_HTTP_ACCEPT: &str = "application/json, text/plain, */*";

/// OAuth refresh-token revocation endpoint.
pub const REVOKE_URL: &str = "https://platform.claude.com/v1/oauth/token/revoke";

/// Authorize endpoint for Claude.ai subscription login.
pub const CLAUDE_AI_AUTHORIZE_URL: &str = "https://claude.com/cai/oauth/authorize";

/// Authorize endpoint for Console / API-key login.
pub const CONSOLE_AUTHORIZE_URL: &str = "https://platform.claude.com/oauth/authorize";

/// Manual (copy/paste) redirect target; the callback page shows `code#state`.
pub const MANUAL_REDIRECT_URL: &str = "https://platform.claude.com/oauth/code/callback";

/// Base Anthropic API origin.
pub const BASE_API_URL: &str = "https://api.anthropic.com";

/// Messages API path, appended to the API base.
pub const MESSAGES_PATH: &str = "/v1/messages";

/// Claude.ai OAuth usage endpoint.
pub const USAGE_URL: &str = "https://api.anthropic.com/api/oauth/usage";

/// Environment variable that overrides [`CLIENT_ID`] at runtime.
pub const CLIENT_ID_ENV: &str = "CLAUDE_CODE_OAUTH_CLIENT_ID";

/// Environment variable that overrides [`BASE_API_URL`] at runtime.
pub const BASE_URL_ENV: &str = "ANTHROPIC_BASE_URL";

/// Environment variable that overrides [`TOKEN_URL`] (exchange and refresh).
pub const TOKEN_URL_ENV: &str = "ANTHROPIC_OAUTH_TOKEN_URL";

/// Environment variable that overrides [`REVOKE_URL`].
pub const REVOKE_URL_ENV: &str = "ANTHROPIC_OAUTH_REVOKE_URL";

/// Environment variable that overrides [`CLAUDE_AI_AUTHORIZE_URL`].
pub const AUTHORIZE_URL_ENV: &str = "ANTHROPIC_OAUTH_AUTHORIZE_URL";

/// Environment variable that overrides [`CONSOLE_AUTHORIZE_URL`].
pub const CONSOLE_AUTHORIZE_URL_ENV: &str = "ANTHROPIC_OAUTH_CONSOLE_AUTHORIZE_URL";

/// Environment variable that overrides [`MANUAL_REDIRECT_URL`].
pub const REDIRECT_URI_ENV: &str = "ANTHROPIC_OAUTH_REDIRECT_URI";

/// Environment variable that overrides [`USAGE_URL`].
pub const USAGE_URL_ENV: &str = "ANTHROPIC_OAUTH_USAGE_URL";

/// Environment variable that overrides the profile endpoint
/// ([`crate::profile::PROFILE_URL`]) used for identity backfill.
pub const PROFILE_URL_ENV: &str = "ANTHROPIC_OAUTH_PROFILE_URL";

/// Environment variable that turns on OAuth test mode: any OAuth HTTP call to
/// a non-loopback host fails closed with
/// [`Error::Config`](crate::Error::Config). Any value other than empty, `0`,
/// `false`, `no` or `off` turns it on.
pub const OAUTH_TEST_MODE_ENV: &str = "ANTHROPIC_OAUTH_TEST_MODE";

/// A single OAuth scope. [`Scope::as_str`] yields the exact wire literal
/// (which contains colons), so this cannot rely on serde `rename_all`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    /// `org:create_api_key` — permits minting an `sk-ant-api01-*` key.
    OrgCreateApiKey,
    /// `user:profile` — read the account profile.
    UserProfile,
    /// `user:inference` — the scope that enables model inference; a session
    /// without it cannot be used to sample.
    UserInference,
    /// `user:sessions:claude_code`.
    UserSessionsClaudeCode,
    /// `user:mcp_servers`.
    UserMcpServers,
    /// `user:file_upload`.
    UserFileUpload,
}

impl Scope {
    /// The exact wire string for this scope.
    pub const fn as_str(self) -> &'static str {
        match self {
            Scope::OrgCreateApiKey => "org:create_api_key",
            Scope::UserProfile => "user:profile",
            Scope::UserInference => "user:inference",
            Scope::UserSessionsClaudeCode => "user:sessions:claude_code",
            Scope::UserMcpServers => "user:mcp_servers",
            Scope::UserFileUpload => "user:file_upload",
        }
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Scope set requested at authorization (includes `org:create_api_key`, in the
/// order the CLI sends them).
pub const AUTHORIZE_SCOPES: [Scope; 6] = [
    Scope::OrgCreateApiKey,
    Scope::UserProfile,
    Scope::UserInference,
    Scope::UserSessionsClaudeCode,
    Scope::UserMcpServers,
    Scope::UserFileUpload,
];

/// Scope set sent on the refresh grant (the CLI omits `org:create_api_key`).
pub const REFRESH_SCOPES: [Scope; 5] = [
    Scope::UserProfile,
    Scope::UserInference,
    Scope::UserSessionsClaudeCode,
    Scope::UserMcpServers,
    Scope::UserFileUpload,
];

/// Space-join a scope set into a `scope` query parameter / body field value.
pub fn scope_param(scopes: &[Scope]) -> String {
    scopes
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Whether a granted-scope list permits inference. A session that cannot infer
/// is unusable.
pub fn grants_inference<S: AsRef<str>>(granted: &[S]) -> bool {
    granted
        .iter()
        .any(|s| s.as_ref() == Scope::UserInference.as_str())
}

/// The concrete set of OAuth URLs plus the client id for a login attempt.
///
/// Grouping the endpoints as one value (rather than reading loose constants at
/// each call site) keeps a custom / staging deployment coherent: override the
/// client id or base once and the whole flow follows.
#[derive(Debug, Clone)]
pub struct Endpoints {
    /// OAuth public client id.
    pub client_id: String,
    /// Token endpoint (exchange + refresh).
    pub token_url: String,
    /// Refresh-token revocation endpoint.
    pub revoke_url: String,
    /// Browser authorize endpoint.
    pub authorize_url: String,
    /// Redirect URI registered for the flow.
    pub redirect_uri: String,
    /// OAuth usage endpoint.
    pub usage_url: String,
    /// Base Anthropic API origin, used by the Messages client.
    pub base_api_url: String,
}

impl Endpoints {
    /// The production Claude.ai subscription configuration.
    pub fn prod() -> Self {
        Self {
            client_id: CLIENT_ID.to_owned(),
            token_url: TOKEN_URL.to_owned(),
            revoke_url: REVOKE_URL.to_owned(),
            authorize_url: CLAUDE_AI_AUTHORIZE_URL.to_owned(),
            redirect_uri: MANUAL_REDIRECT_URL.to_owned(),
            usage_url: USAGE_URL.to_owned(),
            base_api_url: BASE_API_URL.to_owned(),
        }
    }

    /// The Console / API-key authorize variant.
    pub fn console() -> Self {
        Self {
            authorize_url: CONSOLE_AUTHORIZE_URL.to_owned(),
            ..Self::prod()
        }
    }

    /// Production configuration with every field that has an environment
    /// override replaced when that variable is set and non-empty:
    /// [`CLIENT_ID_ENV`], [`BASE_URL_ENV`], [`TOKEN_URL_ENV`],
    /// [`REVOKE_URL_ENV`], [`AUTHORIZE_URL_ENV`], [`REDIRECT_URI_ENV`] and
    /// [`USAGE_URL_ENV`]. This is the one place the environment is read for
    /// endpoints; bindings (napi) and hosts (ckl) build from it.
    pub fn from_env() -> Self {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// [`Endpoints::from_env`] for the Console / API-key flow: the authorize
    /// URL is [`CONSOLE_AUTHORIZE_URL`], or [`CONSOLE_AUTHORIZE_URL_ENV`] when
    /// set.
    pub fn console_from_env() -> Self {
        Self::console_from_lookup(|key| std::env::var(key).ok())
    }

    /// [`Endpoints::from_env`] over an arbitrary variable lookup (tests, or a
    /// host that carries its own environment map).
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let get = |key: &str| {
            lookup(key)
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
        };
        let mut endpoints = Self::prod();
        if let Some(id) = get(CLIENT_ID_ENV) {
            endpoints.client_id = id;
        }
        if let Some(base) = get(BASE_URL_ENV) {
            endpoints.base_api_url = base.trim_end_matches('/').to_owned();
        }
        for (key, slot) in [
            (TOKEN_URL_ENV, &mut endpoints.token_url),
            (REVOKE_URL_ENV, &mut endpoints.revoke_url),
            (AUTHORIZE_URL_ENV, &mut endpoints.authorize_url),
            (REDIRECT_URI_ENV, &mut endpoints.redirect_uri),
            (USAGE_URL_ENV, &mut endpoints.usage_url),
        ] {
            if let Some(value) = get(key) {
                *slot = value;
            }
        }
        endpoints
    }

    /// [`Endpoints::console_from_env`] over an arbitrary variable lookup.
    pub fn console_from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let console = lookup(CONSOLE_AUTHORIZE_URL_ENV)
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| CONSOLE_AUTHORIZE_URL.to_owned());
        Self {
            authorize_url: console,
            ..Self::from_lookup(lookup)
        }
    }

    /// The full Messages API URL for this endpoint set.
    pub fn messages_url(&self) -> String {
        format!("{}{MESSAGES_PATH}", self.base_api_url.trim_end_matches('/'))
    }
}

/// Whether a raw [`OAUTH_TEST_MODE_ENV`] value turns test mode on.
pub fn oauth_test_mode_value(value: Option<&str>) -> bool {
    value.is_some_and(|v| {
        let v = v.trim();
        !(v.is_empty()
            || v == "0"
            || v.eq_ignore_ascii_case("false")
            || v.eq_ignore_ascii_case("no")
            || v.eq_ignore_ascii_case("off"))
    })
}

/// Whether OAuth test mode is on: always in this crate's own unit tests, else
/// when [`OAUTH_TEST_MODE_ENV`] is set to a truthy value.
pub fn oauth_test_mode() -> bool {
    cfg!(test) || oauth_test_mode_value(std::env::var(OAUTH_TEST_MODE_ENV).ok().as_deref())
}

/// Whether `url` targets a loopback host (`localhost`, `127.0.0.0/8`, `::1`).
/// An unparsable URL is not loopback.
pub fn is_loopback_url(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    match parsed.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// The test-mode gate every OAuth HTTP call passes before sending a byte.
///
/// Outside test mode it allows everything. In test mode (see
/// [`oauth_test_mode`]) a URL whose host is not loopback is refused with
/// [`Error::Config`](crate::Error::Config), so a test that forgot to point an
/// endpoint at its mock can never present a fixture token to production.
pub fn ensure_oauth_url_allowed(url: &str) -> crate::Result<()> {
    check_oauth_url(url, oauth_test_mode())
}

/// [`ensure_oauth_url_allowed`] with test mode given explicitly.
pub fn check_oauth_url(url: &str, test_mode: bool) -> crate::Result<()> {
    if !test_mode || is_loopback_url(url) {
        return Ok(());
    }
    let host = url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_else(|| "<unparsable>".to_owned());
    Err(crate::Error::Config(format!(
        "oauth test mode ({OAUTH_TEST_MODE_ENV}) refuses non-loopback oauth host {host}"
    )))
}

impl Default for Endpoints {
    fn default() -> Self {
        Self::prod()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_param_joins_in_order_with_spaces() {
        assert_eq!(
            scope_param(&AUTHORIZE_SCOPES),
            "org:create_api_key user:profile user:inference \
             user:sessions:claude_code user:mcp_servers user:file_upload"
        );
        assert_eq!(
            scope_param(&REFRESH_SCOPES),
            "user:profile user:inference user:sessions:claude_code \
             user:mcp_servers user:file_upload"
        );
    }

    #[test]
    fn grants_inference_detects_the_inference_scope() {
        assert!(grants_inference(&["user:profile", "user:inference"]));
        assert!(!grants_inference(&["user:profile", "user:mcp_servers"]));
    }

    #[test]
    fn messages_url_joins_without_double_slash() {
        let mut e = Endpoints::prod();
        e.base_api_url = "https://api.example.com/".into();
        assert_eq!(e.messages_url(), "https://api.example.com/v1/messages");
    }

    fn lookup<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |key| {
            pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| (*v).to_owned())
        }
    }

    #[test]
    fn from_lookup_overrides_every_oauth_url() {
        let env = [
            (TOKEN_URL_ENV, "http://127.0.0.1:9/token"),
            (REVOKE_URL_ENV, "http://127.0.0.1:9/revoke"),
            (AUTHORIZE_URL_ENV, "http://127.0.0.1:9/authorize"),
            (CONSOLE_AUTHORIZE_URL_ENV, "http://127.0.0.1:9/console"),
            (REDIRECT_URI_ENV, "http://127.0.0.1:9/callback"),
            (USAGE_URL_ENV, "http://127.0.0.1:9/usage"),
            (CLIENT_ID_ENV, " test-client "),
            (BASE_URL_ENV, "http://127.0.0.1:9/"),
        ];
        let e = Endpoints::from_lookup(lookup(&env));
        assert_eq!(e.token_url, "http://127.0.0.1:9/token");
        assert_eq!(e.revoke_url, "http://127.0.0.1:9/revoke");
        assert_eq!(e.authorize_url, "http://127.0.0.1:9/authorize");
        assert_eq!(e.redirect_uri, "http://127.0.0.1:9/callback");
        assert_eq!(e.usage_url, "http://127.0.0.1:9/usage");
        assert_eq!(e.client_id, "test-client");
        assert_eq!(e.base_api_url, "http://127.0.0.1:9");
        let c = Endpoints::console_from_lookup(lookup(&env));
        assert_eq!(c.authorize_url, "http://127.0.0.1:9/console");
        assert_eq!(c.token_url, "http://127.0.0.1:9/token");
    }

    #[test]
    fn from_lookup_ignores_blank_values_and_defaults_to_prod() {
        let e = Endpoints::from_lookup(lookup(&[(TOKEN_URL_ENV, "  ")]));
        assert_eq!(e.token_url, TOKEN_URL);
        assert_eq!(e.revoke_url, REVOKE_URL);
        assert_eq!(e.authorize_url, CLAUDE_AI_AUTHORIZE_URL);
        let c = Endpoints::console_from_lookup(lookup(&[]));
        assert_eq!(c.authorize_url, CONSOLE_AUTHORIZE_URL);
    }

    #[test]
    fn test_mode_value_parsing() {
        for on in ["1", "true", "yes", "TRUE", " 1 "] {
            assert!(oauth_test_mode_value(Some(on)), "{on:?}");
        }
        for off in ["", " ", "0", "false", "No", "off"] {
            assert!(!oauth_test_mode_value(Some(off)), "{off:?}");
        }
        assert!(!oauth_test_mode_value(None));
        // This crate's own unit tests always run in test mode.
        assert!(oauth_test_mode());
    }

    #[test]
    fn test_mode_refuses_every_production_oauth_url() {
        for url in [
            TOKEN_URL,
            REVOKE_URL,
            USAGE_URL,
            "http://example.com/v1/oauth/token",
            "http://127.0.0.1.nip.io/token",
            "not a url",
        ] {
            let error = check_oauth_url(url, true).unwrap_err();
            assert!(matches!(error, crate::Error::Config(_)), "{url}: {error}");
            assert!(error.is_permanent());
            assert!(ensure_oauth_url_allowed(url).is_err(), "{url}");
        }
        for url in [
            "http://127.0.0.1:9/v1/oauth/token",
            "http://127.1.2.3:9/token",
            "http://localhost:8080/token",
            "http://[::1]:9/token",
        ] {
            check_oauth_url(url, true).unwrap();
        }
        check_oauth_url(TOKEN_URL, false).unwrap();
    }

    #[test]
    fn console_variant_only_changes_authorize_url() {
        let prod = Endpoints::prod();
        let console = Endpoints::console();
        assert_eq!(console.authorize_url, CONSOLE_AUTHORIZE_URL);
        assert_eq!(console.token_url, prod.token_url);
        assert_eq!(console.client_id, prod.client_id);
    }
}
