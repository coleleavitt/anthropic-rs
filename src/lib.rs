//! A bare, reusable Anthropic SDK.
//!
//! Three layers, each usable on its own:
//!
//! 1. **Auth domain** — secret newtypes ([`AccessToken`], [`RefreshToken`],
//!    [`ApiKey`]), the [`Credential`] kind, [`OAuthTokens`] with expiry logic,
//!    PKCE ([`PkcePair`]), and the endpoint/scope constants. No I/O.
//! 2. **Shared account store** (`store` feature) — a multi-account credential
//!    file at `~/.anthropic-accounts/accounts.json`, deliberately *not* under
//!    any single application's config directory, so a coding agent, a build
//!    tool, and a one-off script all read the same login.
//! 3. **Clients** (`client` feature) — [`OAuthClient`] for the token endpoint
//!    and [`MessagesClient`] for the Messages API, plus an [`SseDecoder`] whose
//!    framing rules are testable without a network.
//! 4. **Request and routing policy** (pure, no I/O) — the Claude Code 2.1.260
//!    fingerprint ([`claude_code`], [`claude_version`], [`billing`]), model
//!    capabilities and refusal routes ([`models`]), thinking/cache/tool
//!    shaping ([`shaping`]), retry classification ([`retry`]), SSE stream
//!    signals ([`stream_signals`]), the model catalog ([`model_catalog`]) and
//!    profile identity ([`profile`]). With `store`: refresh leases and
//!    dead-token records ([`refresh_claim`]), pool selection ([`routing`]),
//!    and — with `client` — the fail-closed shared refresh ([`refresh`]) and
//!    the single-owner idle-account keep-alive ([`keepalive`]).
//!
//! # Auth-only consumers
//!
//! ```toml
//! anthropic = { version = "0.1", default-features = false }
//! ```
//!
//! links no HTTP client and touches no filesystem.
//!
//! # Example: resolve a credential and send one message
//!
//! ```no_run
//! # #[cfg(all(feature = "client", feature = "store"))]
//! # async fn run() -> anthropic::Result<()> {
//! use anthropic::{AccountStore, Endpoints, Message, MessagesClient, MessagesRequest};
//!
//! let loaded = AccountStore::load_or_migrate()?;
//! let account = loaded.store.pick(chrono::Utc::now())?;
//!
//! let client = MessagesClient::new(Endpoints::from_env());
//! let request =
//!     MessagesRequest::new("claude-sonnet-4-6", 1024, vec![Message::user("Say hello.")]);
//! let response = client.send(&account.credential, &request).await?;
//! println!("{}", response.text());
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(all(feature = "client", feature = "store"))]
pub mod access;
pub mod account;
pub mod billing;
pub mod cch;
pub mod claude_code;
pub mod claude_version;
#[cfg(feature = "store")]
pub mod credentials;
#[cfg(feature = "device")]
pub mod device;
pub mod endpoints;
pub mod error;
#[cfg(feature = "federation")]
pub mod federation;
#[cfg(feature = "store")]
mod file_security;
#[cfg(feature = "store")]
pub mod keepalive;
#[cfg(feature = "store")]
mod legacy;
pub mod messages;
pub mod model_catalog;
pub mod models;
pub mod oauth;
#[cfg(feature = "interactive-oauth")]
pub mod oauth_callback;
pub mod pkce;
pub mod profile;
pub mod request;
pub mod retry;
pub mod shaping;
pub mod stream_signals;
pub mod token;
// Claude Code 2.1.280 wire/model slice.
pub mod encrypted_content;
pub mod low_priority;

#[cfg(all(feature = "client", feature = "store"))]
pub mod refresh;
#[cfg(feature = "store")]
pub mod refresh_claim;
#[cfg(all(feature = "client", feature = "store"))]
pub mod revoke;
#[cfg(feature = "store")]
pub mod routing;
#[cfg(feature = "store")]
pub mod store;
#[cfg(feature = "store")]
pub mod unsaved;

// Auth/quota/routing slice (anthropic-auth b504bc8 + fork 33f12b2).
pub mod backoff;
pub mod killswitch;
pub mod quota;
pub mod quota_manager;
pub mod sticky_routing;

pub use account::{Account, QuotaObservation, RefreshLease, Unavailable};
pub use backoff::OperationError;
pub use cch::{
    CCH_PLACEHOLDER,
    CCH_SEED_2_1_233,
    build_cch_preimage,
    compute_cch,
    sign_request_body,
};
#[cfg(feature = "store")]
pub use credentials::{
    FileSecretStore,
    NATIVE_CLAUDE_KEYRING_SERVICE,
    NATIVE_PUBLISH_ENV,
    NativeClaudeCredentialSource,
    NativeClaudeImport,
    NativeOAuthSummary,
    NativePublish,
    NativePublishOutcome,
    NativeTrustedDeviceToken,
    SecretStore,
    discover_native_claude_credentials,
    import_native_claude_file,
    native_claude_credentials_path,
    native_claude_credentials_path_from_lookup,
    native_claude_keyring_account,
    native_claude_keyring_service,
    publish_native_rotation,
    read_native_claude_summary,
};
#[cfg(feature = "secure-store")]
pub use credentials::{KeyringSecretStore, import_native_claude_keyring};
#[cfg(feature = "device")]
pub use device::{
    AttestationPolicy,
    AttestationStatus,
    CoworkDeviceClient,
    CoworkDeviceKey,
    CoworkPlatform,
    CreateSessionBinding,
    DeviceId,
    DeviceIdentityStore,
    RegisteredCoworkDevice,
    TRUSTED_DEVICE_TOKEN_ENV,
    TrustedDeviceClient,
    TrustedDeviceEnrollment,
    TrustedDeviceToken,
    VerifiedLevel,
    build_bind_preimage,
    trusted_device_header,
    trusted_device_token_from_env,
};
pub use endpoints::{Endpoints, Scope};
pub use error::{Error, Result, RevocationOrigin};
#[cfg(feature = "federation")]
pub use federation::{
    FederatedToken,
    FederationClient,
    FederationConfig,
    FederationEnvironment,
    IdentityTokenSource,
};
#[cfg(feature = "store")]
pub use keepalive::{KeepAliveLease, KeepAliveOptions, keepalive_due};
#[cfg(all(feature = "client", feature = "store"))]
pub use keepalive::{KeepAliveReport, keep_alive_once};
pub use killswitch::{KillswitchConfig, KillswitchThresholds};
#[cfg(feature = "client")]
pub use messages::MessagesClient;
pub use messages::{
    ContentBlock,
    Message,
    MessagesRequest,
    MessagesResponse,
    Role,
    SseDecoder,
    SseEvent,
    Usage,
};
#[cfg(feature = "client")]
pub use oauth::OAuthClient;
pub use oauth::{
    AuthorizeRequest,
    RevokeOutcome,
    TokenRequest,
    TokenResponse,
    parse_redirect_code,
};
#[cfg(feature = "interactive-oauth")]
pub use oauth_callback::LoopbackLogin;
pub use pkce::{PkcePair, PkceVerifier, generate_state};
pub use quota::{QuotaPolicy, QuotaSnapshot, normalize_quota_headers};
pub use quota_manager::QuotaManager;
#[cfg(all(feature = "client", feature = "store"))]
pub use refresh::UnauthorizedRecovery;
#[cfg(all(feature = "client", feature = "store"))]
pub use refresh::{DeadRefreshTokens, RefreshSource, SharedRefreshOptions, SharedRefreshOutcome};
#[cfg(feature = "store")]
pub use refresh_claim::RefreshClaim;
pub use request::HeaderMutation;
pub use retry::{CredentialReceipt, RetryAfter401, decide_retry_after_401};
#[cfg(feature = "store")]
pub use sticky_routing::StickySessionRouter;
pub use sticky_routing::{RoutingMode, StickyRouteFamily};
#[cfg(feature = "store")]
pub use store::{
    AccountStore,
    LoadSource,
    Loaded,
    account_identities,
    default_store_path,
    store_dir,
};
pub use token::{
    AccessToken,
    ApiKey,
    AuthHeader,
    CUSTODY_TOMBSTONE_PREFIX,
    Credential,
    OAuthTokens,
    RefreshToken,
    is_custody_tombstone,
    token_fingerprint,
};

/// Begin an interactive login: the authorize URL to open, plus the PKCE
/// verifier and state that must be carried to the code exchange.
///
/// Kept as one call so a consumer cannot accidentally build the URL with one
/// PKCE pair and exchange with another.
pub struct LoginStart {
    /// URL the user should open in a browser.
    pub authorize_url: url::Url,
    /// Verifier to pass to the code exchange.
    pub verifier: PkceVerifier,
    /// Anti-CSRF state to verify against the redirect.
    pub state: String,
}

/// Build the authorize URL plus its matching PKCE material.
pub fn start_login(endpoints: &Endpoints) -> Result<LoginStart> {
    start_login_with_state(endpoints, generate_state()?)
}

/// [`start_login`] with a caller-chosen anti-CSRF `state` (a loopback
/// listener that already committed to one). The state must be 8–512
/// URL-safe characters (`A-Z a-z 0-9 - . _ ~`); anything else is refused
/// with [`Error::Config`].
pub fn start_login_with_state(endpoints: &Endpoints, state: String) -> Result<LoginStart> {
    if !(8..=512).contains(&state.len())
        || !state
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
    {
        return Err(Error::Config(
            "login state must be 8-512 URL-safe characters".into(),
        ));
    }
    let pkce = PkcePair::generate()?;
    let authorize_url = AuthorizeRequest {
        endpoints,
        pkce: &pkce,
        state: &state,
        scopes: &endpoints::AUTHORIZE_SCOPES,
    }
    .to_url()?;
    Ok(LoginStart {
        authorize_url,
        verifier: pkce.verifier,
        state,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_login_binds_url_verifier_and_state_normal() {
        let endpoints = Endpoints::prod();
        let login = start_login(&endpoints).unwrap();

        let pairs: std::collections::HashMap<_, _> =
            login.authorize_url.query_pairs().into_owned().collect();
        assert_eq!(pairs["state"], login.state);
        // The URL carries the challenge derived from the returned verifier.
        let expected = PkcePair::from_verifier(login.verifier.clone()).challenge;
        assert_eq!(pairs["code_challenge"], expected);
        assert_eq!(pairs["code_challenge_method"], pkce::CODE_CHALLENGE_METHOD);
    }

    #[test]
    fn login_round_trip_verifies_state_robust() {
        let login = start_login(&Endpoints::prod()).unwrap();
        let pasted = format!("the-code#{}", login.state);
        assert_eq!(
            parse_redirect_code(&pasted, &login.state).unwrap(),
            "the-code"
        );
        // A tampered state is refused.
        assert!(matches!(
            parse_redirect_code("the-code#tampered", &login.state),
            Err(Error::StateMismatch)
        ));
    }

    #[test]
    fn start_login_with_state_carries_the_callers_state_and_refuses_unsafe_ones() {
        let mut endpoints = Endpoints::prod();
        endpoints.redirect_uri = "http://localhost:54545/callback".into();
        let state = "loopback-state_0123456789abcdefABCDEF~.".to_owned();
        let login = start_login_with_state(&endpoints, state.clone()).unwrap();
        let pairs: std::collections::HashMap<_, _> =
            login.authorize_url.query_pairs().into_owned().collect();
        assert_eq!(pairs["state"], state);
        assert_eq!(login.state, state);
        assert_eq!(pairs["redirect_uri"], "http://localhost:54545/callback");
        for bad in ["short", "has space in it", "a&b=cdefghij", &"x".repeat(513)] {
            assert!(
                matches!(
                    start_login_with_state(&endpoints, bad.to_owned()),
                    Err(Error::Config(_))
                ),
                "{bad:?}"
            );
        }
    }
}
