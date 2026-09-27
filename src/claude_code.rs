//! Claude Code 2.1.280 request fingerprint as merged in anthropic-auth
//! `f74d736` (`claude-code.ts`): beta selection, the header set, the
//! per-account device identity, and the body field order.
//!
//! Merge decisions carried here: upstream's full-agent / structured-output /
//! base beta tuples win; the fork re-applies `effort-2025-11-24` whenever
//! `output_config.effort` is set and `context-1m-2025-08-07` for 1M-capable
//! models; the fork's extra headers (stainless stream helper, env-forwarded
//! headers, agent ids, request class) are kept on top. Each account identity
//! gets its own device id derived from the persistent installation secret.
//!
//! All of this is transport-agnostic — headers are returned as ordered
//! `(name, value)` pairs so an auth-only consumer can apply them to whatever
//! HTTP stack it owns.

use crate::claude_version::UserAgentDetails;
use crate::endpoints::{ANTHROPIC_VERSION, OAUTH_BETA};
use crate::models::{is_fast_mode_supported_model, model_supports_context_1m};

/// Unlocks the 1M-token context window. Without it a request over ~200k
/// input comes back HTTP 200 with `stop_reason: "refusal"`, no content, and
/// the full input billed.
pub const CONTEXT_1M_BETA: &str = "context-1m-2025-08-07";
/// `output_config.effort` opt-in.
pub const EFFORT_BETA: &str = "effort-2025-11-24";
/// `speed: "fast"` opt-in.
pub const FAST_MODE_BETA: &str = "fast-mode-2026-02-01";
/// Interleaved thinking opt-in.
pub const INTERLEAVED_THINKING_BETA: &str = "interleaved-thinking-2025-05-14";

/// Enables server-side fallback at all (`server_side_fallback`).
pub const SERVER_SIDE_FALLBACK_BASE_BETA: &str = "server-side-fallback-2026-06-01";
/// Adds bio/cyber category routing on top of the base capability.
pub const SERVER_SIDE_FALLBACK_CATEGORY_BETA: &str = "server-side-fallback-2026-07-01";
/// Both server-side-fallback betas in Claude Code's `[MP, Ch]` order: base
/// first, then category. Sending only the category beta leaves the base
/// capability off, so the server returns a terminal refusal instead of an
/// inline fallback.
pub const SERVER_SIDE_FALLBACK_BETAS: [&str; 2] = [
    SERVER_SIDE_FALLBACK_BASE_BETA,
    SERVER_SIDE_FALLBACK_CATEGORY_BETA,
];

/// The server-side-fallback betas that ride a route: both on an OAuth route,
/// none on an API-key route (API-key routes strip both).
pub fn server_side_fallback_betas(oauth_route: bool) -> &'static [&'static str] {
    if oauth_route {
        &SERVER_SIDE_FALLBACK_BETAS
    } else {
        &[]
    }
}

/// Full-agent tuple, used when the body has non-empty `tools`, `system`,
/// `thinking`, `context_management`, `output_config` and `diagnostics`
/// (upstream `CLAUDE_CODE_FULL_AGENT_BETAS`). `redact-thinking-2026-02-12`
/// is deliberately omitted.
pub const CLAUDE_CODE_FULL_AGENT_BETAS: [&str; 13] = [
    OAUTH_BETA,
    INTERLEAVED_THINKING_BETA,
    "thinking-token-count-2026-05-13",
    "context-management-2025-06-27",
    "prompt-caching-scope-2026-01-05",
    "claude-code-20250219",
    "advisor-tool-2026-03-01",
    "advanced-tool-use-2025-11-20",
    "mid-conversation-system-2026-04-07",
    EFFORT_BETA,
    "fallback-credit-2026-06-01",
    "extended-cache-ttl-2025-04-11",
    "cache-diagnosis-2026-04-07",
];

/// Structured-output beta.
pub const CLAUDE_CODE_STRUCTURED_OUTPUT_BETA: &str = "structured-outputs-2025-12-15";

/// Tuple for an `output_config.format.type == "json_schema"` body that is not
/// full-agent shaped.
pub const CLAUDE_CODE_STRUCTURED_OUTPUT_BETAS: [&str; 8] = [
    OAUTH_BETA,
    INTERLEAVED_THINKING_BETA,
    "thinking-token-count-2026-05-13",
    "context-management-2025-06-27",
    "prompt-caching-scope-2026-01-05",
    "advisor-tool-2026-03-01",
    CLAUDE_CODE_STRUCTURED_OUTPUT_BETA,
    "cache-diagnosis-2026-04-07",
];

/// Base tuple for every other request (and when there is no body). It has no
/// `claude-code-20250219`.
pub const CLAUDE_CODE_BASE_BETAS: [&str; 9] = [
    OAUTH_BETA,
    INTERLEAVED_THINKING_BETA,
    "thinking-token-count-2026-05-13",
    "context-management-2025-06-27",
    "prompt-caching-scope-2026-01-05",
    "advisor-tool-2026-03-01",
    "advanced-tool-use-2025-11-20",
    "extended-cache-ttl-2025-04-11",
    "cache-diagnosis-2026-04-07",
];

/// Stainless SDK package version Claude Code 2.1.260–2.1.280 reports.
pub const CLAUDE_CODE_STAINLESS_PACKAGE_VERSION: &str = "0.112.1";
/// Stainless runtime version Claude Code 2.1.260–2.1.280 reports.
pub const CLAUDE_CODE_STAINLESS_RUNTIME_VERSION: &str = "v26.3.0";

fn is_record(value: Option<&serde_json::Value>) -> bool {
    value.is_some_and(serde_json::Value::is_object)
}

fn has_structured_output(body: &serde_json::Value) -> bool {
    body.get("output_config")
        .and_then(|c| c.get("format"))
        .and_then(|f| f.get("type"))
        .and_then(|t| t.as_str())
        == Some("json_schema")
}

fn has_full_agent_shape(body: &serde_json::Value) -> bool {
    body.get("tools")
        .and_then(|t| t.as_array())
        .is_some_and(|t| !t.is_empty())
        && body.get("system").is_some_and(serde_json::Value::is_array)
        && is_record(body.get("thinking"))
        && is_record(body.get("context_management"))
        && is_record(body.get("output_config"))
        && is_record(body.get("diagnostics"))
}

/// Merge betas into an existing comma-separated `anthropic-beta` value,
/// preserving order and dropping duplicates.
pub fn merge_anthropic_betas(existing: &str, betas: &[&str]) -> String {
    let mut out: Vec<&str> = Vec::new();
    for beta in existing
        .split(',')
        .map(str::trim)
        .filter(|b| !b.is_empty())
        .chain(betas.iter().map(|b| b.trim()).filter(|b| !b.is_empty()))
    {
        if !out.contains(&beta) {
            out.push(beta);
        }
    }
    out.join(",")
}

/// Select the `anthropic-beta` value for a Claude Code request body (TS
/// `selectClaudeCodeBetas`).
///
/// The tuple is chosen by body shape (full agent, else structured output,
/// else base), then, in order: `fast-mode-2026-02-01` for `speed:"fast"`,
/// `effort-2025-11-24` whenever `output_config.effort` is present (fork),
/// `context-1m-2025-08-07` for a 1M-capable model unless
/// `suppress_context_1m` (fork), and the caller's extras; duplicates are
/// dropped keeping first position.
///
/// `suppress_context_1m` mirrors Claude Code's account-local latch after the
/// server reports that usage credits are required for long context; it does
/// not imply that 1M context is inherently paid.
pub fn select_claude_code_betas(
    body: Option<&serde_json::Value>,
    extra_betas: &[&str],
    suppress_context_1m: bool,
) -> String {
    let mut selected: Vec<&str> = match body {
        Some(body) if has_full_agent_shape(body) => CLAUDE_CODE_FULL_AGENT_BETAS.to_vec(),
        Some(body) if has_structured_output(body) => CLAUDE_CODE_STRUCTURED_OUTPUT_BETAS.to_vec(),
        _ => CLAUDE_CODE_BASE_BETAS.to_vec(),
    };
    if let Some(body) = body {
        if body.get("speed").and_then(|s| s.as_str()) == Some("fast") {
            selected.push(FAST_MODE_BETA);
        }
        if body
            .get("output_config")
            .and_then(serde_json::Value::as_object)
            .is_some_and(|config| config.contains_key("effort"))
        {
            selected.push(EFFORT_BETA);
        }
        let model = body.get("model").and_then(|m| m.as_str()).unwrap_or("");
        if !suppress_context_1m && model_supports_context_1m(model) {
            selected.push(CONTEXT_1M_BETA);
        }
    }
    merge_anthropic_betas("", &[selected.as_slice(), extra_betas].concat())
}

/// Stainless OS label for the current platform.
pub fn stainless_os() -> &'static str {
    match std::env::consts::OS {
        "macos" => "MacOS",
        "windows" => "Windows",
        "linux" => "Linux",
        "freebsd" => "FreeBSD",
        _ => "Unknown",
    }
}

/// Stainless architecture label for the current platform.
pub fn stainless_arch() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x64",
        "x86" => "x32",
        other => other,
    }
}

/// Percent-encode `%` and any non-printable-ASCII byte so a value is a valid
/// HTTP header value (`\x20-\x7e`).
pub fn encode_header_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch == '%' || !(' '..='~').contains(&ch) {
            let mut buf = [0u8; 4];
            for byte in ch.encode_utf8(&mut buf).bytes() {
                out.push_str(&format!("%{byte:02X}"));
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// Inputs for [`claude_code_headers`].
#[derive(Debug, Clone, Default)]
pub struct ClaudeCodeHeaderOptions<'a> {
    /// The request body, for beta selection and the streaming helper header.
    pub body: Option<&'a serde_json::Value>,
    /// Claude Code version to fingerprint as (see [`crate::claude_version`]).
    pub version: &'a str,
    /// User-agent identity details.
    pub user_agent: UserAgentDetails<'a>,
    /// Betas already present on the request (merged, never clobbered).
    pub existing_betas: &'a str,
    /// Additional betas to append.
    pub extra_betas: &'a [&'a str],
    /// Session id (`x-claude-code-session-id`).
    pub session_id: &'a str,
    /// Per-request id (`x-client-request-id`); a fresh UUID is minted when empty.
    pub client_request_id: Option<&'a str>,
    /// Use the standard context path for an account with the credits latch.
    pub suppress_context_1m: bool,
    /// `x-claude-code-agent-id`.
    pub agent_id: Option<&'a str>,
    /// `x-claude-code-parent-agent-id`.
    pub parent_agent_id: Option<&'a str>,
    /// `x-anthropic-additional-protection: true`.
    pub additional_protection: bool,
}

/// Header names an OAuth Claude Code request must not carry.
pub const CLAUDE_CODE_REMOVED_HEADERS: [&str; 1] = ["x-api-key"];

/// The Claude Code 2.1.260–2.1.280 header set for an OAuth Messages request, as
/// ordered `(name, value)` pairs. The `authorization` value contains the
/// bearer token; apply it with the same care as [`crate::HeaderMutation`].
pub fn claude_code_headers(
    access_token: &str,
    options: &ClaudeCodeHeaderOptions<'_>,
) -> Vec<(String, String)> {
    let betas = merge_anthropic_betas(
        &select_claude_code_betas(options.body, &[], options.suppress_context_1m),
        &[
            options
                .existing_betas
                .split(',')
                .map(str::trim)
                .filter(|b| !b.is_empty())
                .collect::<Vec<_>>()
                .as_slice(),
            options.extra_betas,
        ]
        .concat(),
    );
    let request_id = options
        .client_request_id
        .map(str::to_owned)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let mut headers: Vec<(String, String)> = vec![
        ("accept".into(), "application/json".into()),
        ("authorization".into(), format!("Bearer {access_token}")),
        ("content-type".into(), "application/json".into()),
        (
            "user-agent".into(),
            crate::claude_version::claude_code_user_agent(options.version, &options.user_agent),
        ),
        ("anthropic-beta".into(), betas),
        (
            "anthropic-dangerous-direct-browser-access".into(),
            "true".into(),
        ),
        ("anthropic-version".into(), ANTHROPIC_VERSION.into()),
        ("x-app".into(), "cli".into()),
        ("x-client-request-id".into(), request_id),
        (
            "x-claude-code-session-id".into(),
            options.session_id.to_owned(),
        ),
        ("x-stainless-arch".into(), stainless_arch().into()),
        ("x-stainless-lang".into(), "js".into()),
        ("x-stainless-os".into(), stainless_os().into()),
        (
            "x-stainless-package-version".into(),
            CLAUDE_CODE_STAINLESS_PACKAGE_VERSION.into(),
        ),
        ("x-stainless-retry-count".into(), "0".into()),
        ("x-stainless-runtime".into(), "node".into()),
        (
            "x-stainless-runtime-version".into(),
            CLAUDE_CODE_STAINLESS_RUNTIME_VERSION.into(),
        ),
        ("x-stainless-timeout".into(), "600".into()),
    ];
    if options
        .body
        .and_then(|b| b.get("stream"))
        .and_then(|s| s.as_bool())
        == Some(true)
    {
        headers.push(("x-stainless-helper-method".into(), "stream".into()));
    }
    if options.additional_protection {
        headers.push(("x-anthropic-additional-protection".into(), "true".into()));
    }
    if let Some(agent) = options.agent_id.filter(|a| !a.is_empty()) {
        headers.push(("x-claude-code-agent-id".into(), encode_header_value(agent)));
    }
    if let Some(parent) = options.parent_agent_id.filter(|p| !p.is_empty()) {
        headers.push((
            "x-claude-code-parent-agent-id".into(),
            encode_header_value(parent),
        ));
    }
    headers
}

/// Environment variables forwarded as headers (fork `ENV_FORWARDED_HEADERS`),
/// as `(header, env var)` pairs in emission order.
pub const ENV_FORWARDED_HEADERS: [(&str, &str); 3] = [
    ("x-claude-remote-container-id", "CLAUDE_CODE_CONTAINER_ID"),
    (
        "x-claude-remote-session-id",
        "CLAUDE_CODE_REMOTE_SESSION_ID",
    ),
    ("x-client-app", "CLAUDE_AGENT_SDK_CLIENT_APP"),
];

/// Environment variable that turns on `x-anthropic-additional-protection`.
pub const ADDITIONAL_PROTECTION_ENV: &str = "CLAUDE_CODE_ADDITIONAL_PROTECTION";

/// The env-forwarded headers for `lookup` (an environment reader), header
/// value encoded. Unset or empty variables produce nothing. Append them to
/// [`claude_code_headers`].
pub fn claude_code_env_headers(lookup: impl Fn(&str) -> Option<String>) -> Vec<(String, String)> {
    ENV_FORWARDED_HEADERS
        .iter()
        .filter_map(|(header, var)| {
            lookup(var)
                .filter(|value| !value.is_empty())
                .map(|value| ((*header).to_owned(), encode_header_value(&value)))
        })
        .collect()
}

/// [`claude_code_env_headers`] over the process environment.
pub fn claude_code_env_headers_from_env() -> Vec<(String, String)> {
    claude_code_env_headers(|var| std::env::var(var).ok())
}

/// Whether [`ADDITIONAL_PROTECTION_ENV`] is truthy (`1`/`true`/`yes`/`on`) —
/// the value for [`ClaudeCodeHeaderOptions::additional_protection`].
pub fn additional_protection_from_env() -> bool {
    crate::models::env_flag_is_truthy(std::env::var(ADDITIONAL_PROTECTION_ENV).ok().as_deref())
}

/// Identity-cache key for a Claude Code identity (TS
/// `resolveClaudeCodeIdentity`): `identity:<trimmed account identity>`, or
/// `compat:<access token>` (`compat:anonymous` for an empty token) when the
/// credential has no stable account identity.
///
/// The compat key embeds the bearer token: treat it as a secret and never
/// log it.
pub fn claude_code_identity_cache_key(
    account_identity: Option<&str>,
    access_token: &str,
) -> String {
    match account_identity.map(str::trim).filter(|id| !id.is_empty()) {
        Some(identity) => format!("identity:{identity}"),
        None if access_token.is_empty() => "compat:anonymous".to_owned(),
        None => format!("compat:{access_token}"),
    }
}

/// Per-account device id (merge decision 3):
/// `sha256_hex(installation_secret + "\0" + cache_key)`.
///
/// `installation_secret` is the persistent 64-hex installation id
/// (`~/.anthropic-accounts/device.json`, see `device::DeviceIdentityStore`);
/// `cache_key` comes from [`claude_code_identity_cache_key`]. The result is
/// stable across restarts and distinct per account, so two accounts never
/// share a device id. It goes in `metadata.user_id`.
pub fn derive_claude_code_device_id(installation_secret: &str, cache_key: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(installation_secret.as_bytes());
    hasher.update([0u8]);
    hasher.update(cache_key.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The `metadata.user_id` value (TS `buildClaudeCodeMetadataUserId`): a JSON
/// string with `device_id`, `account_uuid`, `session_id` in that order.
/// Claude Code omits the field when the account uuid is unknown.
pub fn build_claude_code_metadata_user_id(
    device_id: &str,
    account_uuid: &str,
    session_id: &str,
) -> String {
    let mut map = serde_json::Map::new();
    map.insert("device_id".into(), device_id.into());
    map.insert("account_uuid".into(), account_uuid.into());
    map.insert("session_id".into(), session_id.into());
    serde_json::Value::Object(map).to_string()
}

/// Optional per-request scheduling hints (fork `applyClaudeCodeHeaders`
/// `requestClass` / `prevToolDurations`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClaudeCodeRequestHints<'a> {
    /// Request classification (compaction, workflow, …) —
    /// `x-claude-code-request-class`.
    pub request_class: Option<&'a str>,
    /// Previous tool execution durations — `x-claude-code-prev-tool-durations`.
    pub prev_tool_durations: Option<&'a str>,
}

/// The optional hint headers for a request, header-value encoded. Empty or
/// absent hints produce nothing. Append them to [`claude_code_headers`].
pub fn claude_code_hint_headers(hints: &ClaudeCodeRequestHints<'_>) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    if let Some(class) = hints.request_class.filter(|c| !c.is_empty()) {
        headers.push((
            "x-claude-code-request-class".into(),
            encode_header_value(class),
        ));
    }
    if let Some(durations) = hints.prev_tool_durations.filter(|d| !d.is_empty()) {
        headers.push((
            "x-claude-code-prev-tool-durations".into(),
            encode_header_value(durations),
        ));
    }
    headers
}

/// Claude Code's body key order; unknown keys follow in their original order.
pub const BODY_FIELD_ORDER: [&str; 14] = [
    "model",
    "messages",
    "system",
    "tools",
    "tool_choice",
    "metadata",
    "max_tokens",
    "temperature",
    "thinking",
    "context_management",
    "output_config",
    "diagnostics",
    "stream",
    "speed",
];

/// Reorder a JSON object body to [`BODY_FIELD_ORDER`]. Non-objects are
/// returned unchanged. Requires `serde_json`'s default (insertion-ordered)
/// map to be meaningful.
pub fn order_claude_code_body(body: serde_json::Value) -> serde_json::Value {
    let serde_json::Value::Object(map) = body else {
        return body;
    };
    let mut ordered = serde_json::Map::with_capacity(map.len());
    for key in BODY_FIELD_ORDER {
        if let Some(value) = map.get(key) {
            ordered.insert(key.to_owned(), value.clone());
        }
    }
    for (key, value) in map {
        if !ordered.contains_key(&key) {
            ordered.insert(key, value);
        }
    }
    serde_json::Value::Object(ordered)
}

/// Whether `speed:"fast"` should be set for `model` when fast mode is
/// requested.
pub fn fast_mode_applies(model: &str, fast_mode_enabled: bool) -> bool {
    fast_mode_enabled && is_fast_mode_supported_model(model)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn betas_of(value: &str) -> Vec<&str> {
        value.split(',').collect()
    }

    #[test]
    fn server_side_fallback_betas_ride_oauth_in_order_and_not_api_key() {
        assert_eq!(
            server_side_fallback_betas(true),
            &[
                SERVER_SIDE_FALLBACK_BASE_BETA,
                SERVER_SIDE_FALLBACK_CATEGORY_BETA
            ]
        );
        assert_eq!(
            SERVER_SIDE_FALLBACK_BETAS[0],
            "server-side-fallback-2026-06-01"
        );
        assert_eq!(
            SERVER_SIDE_FALLBACK_BETAS[1],
            "server-side-fallback-2026-07-01"
        );
        assert!(server_side_fallback_betas(false).is_empty());
        let merged = merge_anthropic_betas(OAUTH_BETA, server_side_fallback_betas(true));
        let list = betas_of(&merged);
        let base = list
            .iter()
            .position(|b| *b == SERVER_SIDE_FALLBACK_BASE_BETA)
            .unwrap();
        let category = list
            .iter()
            .position(|b| *b == SERVER_SIDE_FALLBACK_CATEGORY_BETA)
            .unwrap();
        assert!(base < category);
    }

    #[test]
    fn context_1m_beta_follows_model_support_and_suppression() {
        let body = serde_json::json!({"model":"claude-opus-4-8"});
        assert!(
            betas_of(&select_claude_code_betas(Some(&body), &[], false)).contains(&CONTEXT_1M_BETA)
        );
        assert!(
            !betas_of(&select_claude_code_betas(Some(&body), &[], true)).contains(&CONTEXT_1M_BETA)
        );
        let small = serde_json::json!({"model":"claude-haiku-4-5"});
        assert!(
            !betas_of(&select_claude_code_betas(Some(&small), &[], false))
                .contains(&CONTEXT_1M_BETA)
        );
        assert!(!betas_of(&select_claude_code_betas(None, &[], false)).contains(&CONTEXT_1M_BETA));
        // Suppression leaves the base set intact.
        let suppressed = select_claude_code_betas(Some(&body), &[], true);
        for beta in CLAUDE_CODE_BASE_BETAS {
            assert!(betas_of(&suppressed).contains(&beta), "{beta}");
        }
    }

    /// Fixed vectors from merged-TS `selectClaudeCodeBetas(body,
    /// ["x-extra", " ", "oauth-2025-04-20"])` under Bun.
    #[test]
    fn beta_selection_matches_merged_ts_vectors() {
        const EXTRAS: [&str; 3] = ["x-extra", " ", "oauth-2025-04-20"];
        let cases = [
            (
                serde_json::json!({"model":"claude-opus-5","tools":[{}],"system":[],"thinking":{},
                    "context_management":{},"output_config":{"effort":"high"},"diagnostics":{},"speed":"fast"}),
                "oauth-2025-04-20,interleaved-thinking-2025-05-14,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,claude-code-20250219,advisor-tool-2026-03-01,advanced-tool-use-2025-11-20,mid-conversation-system-2026-04-07,effort-2025-11-24,fallback-credit-2026-06-01,extended-cache-ttl-2025-04-11,cache-diagnosis-2026-04-07,fast-mode-2026-02-01,context-1m-2025-08-07,x-extra",
            ),
            (
                serde_json::json!({"model":"m","output_config":{"format":{"type":"json_schema"}}}),
                "oauth-2025-04-20,interleaved-thinking-2025-05-14,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,advisor-tool-2026-03-01,structured-outputs-2025-12-15,cache-diagnosis-2026-04-07,x-extra",
            ),
            (
                serde_json::json!({"model":"claude-opus-5-5","output_config":{"effort":"max","format":{"type":"json_schema"}}}),
                "oauth-2025-04-20,interleaved-thinking-2025-05-14,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,advisor-tool-2026-03-01,structured-outputs-2025-12-15,cache-diagnosis-2026-04-07,effort-2025-11-24,context-1m-2025-08-07,x-extra",
            ),
            (
                serde_json::json!({"model":"claude-haiku-4-5"}),
                "oauth-2025-04-20,interleaved-thinking-2025-05-14,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,advisor-tool-2026-03-01,advanced-tool-use-2025-11-20,extended-cache-ttl-2025-04-11,cache-diagnosis-2026-04-07,x-extra",
            ),
            (
                serde_json::json!({"model":"claude-haiku-4-5","output_config":{"effort":null}}),
                "oauth-2025-04-20,interleaved-thinking-2025-05-14,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,advisor-tool-2026-03-01,advanced-tool-use-2025-11-20,extended-cache-ttl-2025-04-11,cache-diagnosis-2026-04-07,effort-2025-11-24,x-extra",
            ),
            (
                serde_json::json!({"model":"claude-opus-5-5","speed":"fast"}),
                "oauth-2025-04-20,interleaved-thinking-2025-05-14,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,advisor-tool-2026-03-01,advanced-tool-use-2025-11-20,extended-cache-ttl-2025-04-11,cache-diagnosis-2026-04-07,fast-mode-2026-02-01,context-1m-2025-08-07,x-extra",
            ),
            (
                serde_json::json!({"model":"claude-haiku-4-5[1m]"}),
                "oauth-2025-04-20,interleaved-thinking-2025-05-14,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,advisor-tool-2026-03-01,advanced-tool-use-2025-11-20,extended-cache-ttl-2025-04-11,cache-diagnosis-2026-04-07,context-1m-2025-08-07,x-extra",
            ),
        ];
        for (body, expected) in cases {
            assert_eq!(
                select_claude_code_betas(Some(&body), &EXTRAS, false),
                expected,
                "{body}"
            );
        }
        assert_eq!(
            select_claude_code_betas(None, &[], false),
            CLAUDE_CODE_BASE_BETAS.join(",")
        );
        assert!(!CLAUDE_CODE_BASE_BETAS.contains(&"claude-code-20250219"));
        assert!(!CLAUDE_CODE_FULL_AGENT_BETAS.contains(&"redact-thinking-2026-02-12"));
        assert_eq!(merge_anthropic_betas("a, b,,a", &["b", "c"]), "a,b,c");
    }

    #[test]
    fn env_forwarded_headers_are_encoded_and_optional() {
        let env = |var: &str| match var {
            "CLAUDE_CODE_CONTAINER_ID" => Some("ctr ü".to_owned()),
            "CLAUDE_CODE_REMOTE_SESSION_ID" => Some(String::new()),
            "CLAUDE_AGENT_SDK_CLIENT_APP" => Some("app%1".to_owned()),
            _ => None,
        };
        assert_eq!(
            claude_code_env_headers(env),
            vec![
                (
                    "x-claude-remote-container-id".to_owned(),
                    "ctr %C3%BC".to_owned()
                ),
                ("x-client-app".to_owned(), "app%251".to_owned()),
            ]
        );
        assert!(claude_code_env_headers(|_| None).is_empty());
    }

    /// Bun vectors: `sha256_hex(secret + "\0" + cacheKey)` equals merged-TS
    /// `getClaudeCodeIdentity(cacheKey).deviceId` after
    /// `configureClaudeCodeInstallationDeviceId(secret)`.
    #[test]
    fn per_account_device_id_matches_merged_ts() {
        let secret = "a".repeat(64);
        let identity_key = claude_code_identity_cache_key(Some("  acct-1 "), "sk-ant-oat01-x");
        assert_eq!(identity_key, "identity:acct-1");
        assert_eq!(
            derive_claude_code_device_id(&secret, &identity_key),
            "402cc9d2902492a43d1c3e3e52b43843fc2cd9a57d057dcd8660e80da6293435"
        );
        let compat_key = claude_code_identity_cache_key(Some(" "), "sk-ant-oat01-x");
        assert_eq!(compat_key, "compat:sk-ant-oat01-x");
        assert_eq!(
            derive_claude_code_device_id(&secret, &compat_key),
            "b8044d01beb6608e502d8f211d802d9a6a398c3c2fe4cbd5d323959a7a3ba47e"
        );
        assert_eq!(
            derive_claude_code_device_id(&secret, &claude_code_identity_cache_key(None, "")),
            "9091c68c039af2fb9d4ab6dab86baaf31f016ee4a94345e67702c10b5e2da471"
        );
        // Distinct accounts never share a device id; same inputs are stable.
        let other = derive_claude_code_device_id(&secret, "identity:acct-2");
        assert_ne!(other, derive_claude_code_device_id(&secret, &identity_key));
        assert_eq!(
            other,
            derive_claude_code_device_id(&secret, "identity:acct-2")
        );
        assert_eq!(
            build_claude_code_metadata_user_id("d", "u", "s"),
            r#"{"device_id":"d","account_uuid":"u","session_id":"s"}"#
        );
    }

    #[test]
    fn header_set_matches_2_1_280() {
        let body = serde_json::json!({"model":"claude-opus-5","stream":true});
        let headers = claude_code_headers(
            "sk-ant-oat01-test",
            &ClaudeCodeHeaderOptions {
                body: Some(&body),
                version: crate::claude_version::CLAUDE_CODE_VERSION,
                session_id: "ses_1",
                client_request_id: Some("req-1"),
                existing_betas: "prompt-caching-2024-07-31",
                extra_betas: &SERVER_SIDE_FALLBACK_BETAS,
                agent_id: Some("agent ü"),
                ..Default::default()
            },
        );
        let get = |name: &str| {
            headers
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(get("authorization"), Some("Bearer sk-ant-oat01-test"));
        assert_eq!(
            get("user-agent"),
            Some("claude-cli/2.1.280 (external, cli)")
        );
        assert_eq!(get("x-app"), Some("cli"));
        assert_eq!(get("x-stainless-helper-method"), Some("stream"));
        assert_eq!(get("x-claude-code-agent-id"), Some("agent %C3%BC"));
        assert_eq!(get("x-client-request-id"), Some("req-1"));
        let betas = get("anthropic-beta").unwrap();
        assert!(betas.contains("prompt-caching-2024-07-31"));
        assert!(betas.contains(CONTEXT_1M_BETA));
        assert!(betas.contains(SERVER_SIDE_FALLBACK_BASE_BETA));
        assert!(!headers.iter().any(|(n, _)| n == "x-api-key"));
        // Header order is stable: accept first, authorization second.
        assert_eq!(headers[0].0, "accept");
        assert_eq!(headers[1].0, "authorization");
    }

    /// Fixed vector: the full 2.1.280 OAuth header set, in order, for a
    /// non-streaming Opus 5.5 fast-mode body.
    #[test]
    fn header_vector_2_1_280_opus_5_5() {
        let body = serde_json::json!({"model":"claude-opus-5-5","speed":"fast"});
        let headers = claude_code_headers(
            "tok",
            &ClaudeCodeHeaderOptions {
                body: Some(&body),
                version: "2.1.280",
                session_id: "ses_1",
                client_request_id: Some("req-1"),
                ..Default::default()
            },
        );
        let names: Vec<&str> = headers.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "accept",
                "authorization",
                "content-type",
                "user-agent",
                "anthropic-beta",
                "anthropic-dangerous-direct-browser-access",
                "anthropic-version",
                "x-app",
                "x-client-request-id",
                "x-claude-code-session-id",
                "x-stainless-arch",
                "x-stainless-lang",
                "x-stainless-os",
                "x-stainless-package-version",
                "x-stainless-retry-count",
                "x-stainless-runtime",
                "x-stainless-runtime-version",
                "x-stainless-timeout",
            ]
        );
        let get = |name: &str| {
            headers
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(
            get("user-agent"),
            Some("claude-cli/2.1.280 (external, cli)")
        );
        assert_eq!(get("x-stainless-package-version"), Some("0.112.1"));
        assert_eq!(get("x-stainless-runtime-version"), Some("v26.3.0"));
        assert_eq!(get("anthropic-version"), Some("2023-06-01"));
        // Merged-TS vector (`opus55_fast` minus the extras).
        assert_eq!(
            get("anthropic-beta"),
            Some(
                "oauth-2025-04-20,interleaved-thinking-2025-05-14,\
thinking-token-count-2026-05-13,context-management-2025-06-27,\
prompt-caching-scope-2026-01-05,advisor-tool-2026-03-01,advanced-tool-use-2025-11-20,\
extended-cache-ttl-2025-04-11,cache-diagnosis-2026-04-07,fast-mode-2026-02-01,\
context-1m-2025-08-07"
            )
        );
    }

    #[test]
    fn hint_headers_are_optional_and_encoded() {
        assert!(claude_code_hint_headers(&ClaudeCodeRequestHints::default()).is_empty());
        assert!(
            claude_code_hint_headers(&ClaudeCodeRequestHints {
                request_class: Some(""),
                prev_tool_durations: Some(""),
            })
            .is_empty()
        );
        assert_eq!(
            claude_code_hint_headers(&ClaudeCodeRequestHints {
                request_class: Some("compaction"),
                prev_tool_durations: Some("Bash:1200,Read:5 ü"),
            }),
            vec![
                (
                    "x-claude-code-request-class".to_owned(),
                    "compaction".to_owned()
                ),
                (
                    "x-claude-code-prev-tool-durations".to_owned(),
                    "Bash:1200,Read:5 %C3%BC".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn body_order_matches_claude_code() {
        let body =
            serde_json::json!({"stream":true,"max_tokens":1,"zzz":1,"model":"m","messages":[]});
        let ordered = order_claude_code_body(body);
        let keys: Vec<&str> = ordered
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            vec!["model", "messages", "max_tokens", "stream", "zzz"]
        );
        assert_eq!(encode_header_value("a%b\u{7f}"), "a%25b%7F");
    }
}
