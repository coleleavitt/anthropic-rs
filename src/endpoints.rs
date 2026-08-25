//! Anthropic OAuth endpoints, client id, scopes, and header constants.
//!
//! Values mirror the Claude Code CLI production configuration. Runtime env
//! overrides mirror the CLI: `CLAUDE_CODE_OAUTH_CLIENT_ID` overrides the client
//! id.

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

    /// Production configuration with the client id and API base overridden from
    /// the environment when those variables are set and non-empty.
    pub fn from_env() -> Self {
        let mut endpoints = Self::prod();
        if let Some(id) = non_empty_env(CLIENT_ID_ENV) {
            endpoints.client_id = id;
        }
        if let Some(base) = non_empty_env(BASE_URL_ENV) {
            endpoints.base_api_url = base.trim_end_matches('/').to_owned();
        }
        endpoints
    }

    /// The full Messages API URL for this endpoint set.
    pub fn messages_url(&self) -> String {
        format!("{}{MESSAGES_PATH}", self.base_api_url.trim_end_matches('/'))
    }
}

fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
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

    #[test]
    fn console_variant_only_changes_authorize_url() {
        let prod = Endpoints::prod();
        let console = Endpoints::console();
        assert_eq!(console.authorize_url, CONSOLE_AUTHORIZE_URL);
        assert_eq!(console.token_url, prod.token_url);
        assert_eq!(console.client_id, prod.client_id);
    }
}
