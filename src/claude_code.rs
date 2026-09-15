//! Claude Code 2.1.260 request fingerprint: beta selection, the header set,
//! and the body field order.
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

/// Betas every Claude Code request carries.
pub const CLAUDE_CODE_BASE_BETAS: [&str; 9] = [
    "claude-code-20250219",
    OAUTH_BETA,
    INTERLEAVED_THINKING_BETA,
    "thinking-token-count-2026-05-13",
    "context-management-2025-06-27",
    "prompt-caching-scope-2026-01-05",
    EFFORT_BETA,
    "extended-cache-ttl-2025-04-11",
    "cache-diagnosis-2026-04-07",
];

/// Extra betas for a full-agent-shaped body (tools + system + thinking +
/// context_management + output_config + diagnostics).
pub const CLAUDE_CODE_FULL_AGENT_EXTRA_BETAS: [&str; 2] =
    ["advisor-tool-2026-03-01", "advanced-tool-use-2025-11-20"];
/// Extra beta for a structured-output body.
pub const CLAUDE_CODE_STRUCTURED_OUTPUT_BETA: &str = "structured-outputs-2025-12-15";

/// Stainless SDK package version Claude Code 2.1.260 reports.
pub const CLAUDE_CODE_STAINLESS_PACKAGE_VERSION: &str = "0.112.1";
/// Stainless runtime version Claude Code 2.1.260 reports.
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

/// Select the `anthropic-beta` value for a Claude Code request body.
///
/// `suppress_context_1m` mirrors Claude Code's account-local latch after the
/// server reports that usage credits are required for long context; it does
/// not imply that 1M context is inherently paid.
pub fn select_claude_code_betas(
    body: Option<&serde_json::Value>,
    extra_betas: &[&str],
    suppress_context_1m: bool,
) -> String {
    let mut selected: Vec<&str> = CLAUDE_CODE_BASE_BETAS.to_vec();
    if let Some(body) = body {
        if has_full_agent_shape(body) {
            selected.extend(CLAUDE_CODE_FULL_AGENT_EXTRA_BETAS);
        } else if has_structured_output(body) {
            selected.push(CLAUDE_CODE_STRUCTURED_OUTPUT_BETA);
        }
        if body.get("speed").and_then(|s| s.as_str()) == Some("fast") {
            selected.push(FAST_MODE_BETA);
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

/// The Claude Code 2.1.260 header set for an OAuth Messages request, as
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

    #[test]
    fn beta_selection_by_body_shape() {
        let full = serde_json::json!({
            "model":"claude-opus-5","tools":[{}],"system":[],"thinking":{},
            "context_management":{},"output_config":{},"diagnostics":{},"speed":"fast"
        });
        let selected = select_claude_code_betas(Some(&full), &["x-extra", " ", "x-extra"], false);
        let list = betas_of(&selected);
        for beta in CLAUDE_CODE_FULL_AGENT_EXTRA_BETAS {
            assert!(list.contains(&beta));
        }
        assert!(list.contains(&FAST_MODE_BETA));
        assert_eq!(list.iter().filter(|b| **b == "x-extra").count(), 1);
        let structured =
            serde_json::json!({"model":"m","output_config":{"format":{"type":"json_schema"}}});
        assert!(
            betas_of(&select_claude_code_betas(Some(&structured), &[], false))
                .contains(&CLAUDE_CODE_STRUCTURED_OUTPUT_BETA)
        );
        assert_eq!(merge_anthropic_betas("a, b,,a", &["b", "c"]), "a,b,c");
    }

    #[test]
    fn header_set_matches_2_1_260() {
        let body = serde_json::json!({"model":"claude-opus-5","stream":true});
        let headers = claude_code_headers(
            "sk-ant-oat01-test",
            &ClaudeCodeHeaderOptions {
                body: Some(&body),
                version: "2.1.260",
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
            Some("claude-cli/2.1.260 (external, cli)")
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
