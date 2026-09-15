//! Claude Code 2.1.260 billing header (`x-anthropic-billing-header`).
//!
//! The header is the first `system` text block of a Messages request:
//!
//! ```text
//! x-anthropic-billing-header: cc_version=<ver>.<sfx>; cc_entrypoint=<ep>; cch=00000;[ cc_workload=<w>;][ cc_is_subagent=true;][ cc_prev_req=req_…;][ cc_prompt_id=<uuid>;]
//! ```
//!
//! `<sfx>` is the message-derived three-character suffix
//! `sha256("59cf53e54c78" + text[4] + text[7] + text[20] + version)[..3]`
//! where `text` is the first non-meta user message's text and a missing
//! position samples `'0'`.
//!
//! **The `cch` slot is the literal `00000` on the wire.** Claude Code 2.1.260
//! does not hash-sign it. The 2.1.233 xxHash64 signing kept in [`crate::cch`]
//! is legacy/diagnostic and must not be applied to a normal request against
//! the 2.1.260 fingerprint; [`normalize_billing_header_cch`] resets any
//! previously signed slot back to the native placeholder.

use sha2::{Digest, Sha256};

/// Salt prefixed to the sampled characters and the version.
pub const CCH_SALT: &str = "59cf53e54c78";
/// UTF-16 code-unit positions sampled from the first user text.
pub const CCH_POSITIONS: [usize; 3] = [4, 7, 20];
/// Default entrypoint segment.
pub const CLAUDE_CODE_ENTRYPOINT: &str = "cli";
/// The literal cch slot Claude Code 2.1.260 emits.
pub const CCH_LITERAL: &str = "cch=00000;";

/// Compute Claude Code's message-derived three-character `cc_version` suffix.
///
/// Positions index UTF-16 code units, as the JavaScript original does; a lone
/// surrogate hashes as U+FFFD exactly as Node's UTF-8 encoder emits it.
pub fn compute_version_suffix(version: &str, first_user_text: &str) -> String {
    let units: Vec<u16> = first_user_text.encode_utf16().collect();
    let mut sampled = String::new();
    for position in CCH_POSITIONS {
        match units.get(position) {
            Some(unit) => sampled.push_str(&String::from_utf16_lossy(&[*unit])),
            None => sampled.push('0'),
        }
    }
    let digest = Sha256::digest(format!("{CCH_SALT}{sampled}{version}").as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    hex[..3].to_owned()
}

/// Text of the first non-meta user message: a string body verbatim, else the
/// first `text` block of an array body, else empty. `messages` is the
/// serialized Messages `messages` array; an `isMeta: true` message is skipped.
pub fn extract_first_user_message_text(messages: &[serde_json::Value]) -> String {
    let Some(user) = messages.iter().find(|m| {
        m.get("role").and_then(|r| r.as_str()) == Some("user")
            && m.get("isMeta").and_then(|v| v.as_bool()) != Some(true)
    }) else {
        return String::new();
    };
    match user.get("content") {
        Some(serde_json::Value::String(text)) => text.clone(),
        Some(serde_json::Value::Array(blocks)) => blocks
            .iter()
            .find(|b| b.get("type").and_then(|t| t.as_str()) == Some("text"))
            .and_then(|b| b.get("text").and_then(|t| t.as_str()))
            .filter(|t| !t.is_empty())
            .map(str::to_owned)
            .unwrap_or_default(),
        _ => String::new(),
    }
}

/// Optional billing-attribution segments.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BillingAttribution<'a> {
    /// `cc_workload=<w>;`
    pub workload: Option<&'a str>,
    /// `cc_is_subagent=true;`
    pub is_subagent: bool,
    /// `cc_prev_req=<req_…>;` — emitted only when it matches `req_[A-Za-z0-9_-]{1,36}`.
    pub previous_request_id: Option<&'a str>,
    /// `cc_prompt_id=<uuid>;` — emitted only when it is an RFC 4122 UUID string.
    pub prompt_id: Option<&'a str>,
}

fn is_request_id(value: &str) -> bool {
    value.strip_prefix("req_").is_some_and(|rest| {
        (1..=36).contains(&rest.len())
            && rest
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    })
}

fn is_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    bytes.iter().enumerate().all(|(i, b)| match i {
        8 | 13 | 18 | 23 => *b == b'-',
        _ => b.is_ascii_hexdigit(),
    })
}

/// Build the billing header value with Claude Code 2.1.260's segment order and
/// spacing. `first_user_text` feeds the version suffix; see
/// [`extract_first_user_message_text`].
pub fn build_billing_header_value(
    version: &str,
    entrypoint: &str,
    first_user_text: &str,
    attribution: &BillingAttribution<'_>,
) -> String {
    let suffix = compute_version_suffix(version, first_user_text);
    let mut header = format!(
        "x-anthropic-billing-header: cc_version={version}.{suffix}; cc_entrypoint={entrypoint}; {CCH_LITERAL}"
    );
    if let Some(workload) = attribution
        .workload
        .map(str::trim)
        .filter(|w| !w.is_empty())
    {
        header.push_str(&format!(" cc_workload={workload};"));
    }
    if attribution.is_subagent {
        header.push_str(" cc_is_subagent=true;");
    }
    if let Some(prev) = attribution
        .previous_request_id
        .map(str::trim)
        .filter(|p| is_request_id(p))
    {
        header.push_str(&format!(" cc_prev_req={prev};"));
    }
    if let Some(prompt) = attribution.prompt_id.map(str::trim).filter(|p| is_uuid(p)) {
        header.push_str(&format!(" cc_prompt_id={prompt};"));
    }
    header
}

/// Reset a previously hash-signed billing-header slot (`cch=<5 hex>;`) in a
/// serialized request body back to the native literal `cch=00000;`. Only the
/// first-system-block billing header is touched; message history is left
/// alone. Bodies without a billing header are returned unchanged.
pub fn normalize_billing_header_cch(serialized_body: &str) -> String {
    const PREFIX: &str =
        "\"system\":[{\"type\":\"text\",\"text\":\"x-anthropic-billing-header: cc_version=";
    let Some(start) = serialized_body.find(PREFIX) else {
        return serialized_body.to_owned();
    };
    let from = start + PREFIX.len();
    // End of the header string: the first quote after the prefix.
    let Some(end) = serialized_body[from..].find('"').map(|o| from + o) else {
        return serialized_body.to_owned();
    };
    let header = &serialized_body[start..end];
    let Some(cch_rel) = header.find("cch=") else {
        return serialized_body.to_owned();
    };
    let digits_start = start + cch_rel + 4;
    let digits = &serialized_body[digits_start..];
    let hex_len = digits
        .bytes()
        .take(5)
        .take_while(|b| b.is_ascii_hexdigit())
        .count();
    if hex_len != 5 || digits.as_bytes().get(5) != Some(&b';') {
        return serialized_body.to_owned();
    }
    let mut out = serialized_body.to_owned();
    out.replace_range(digits_start..digits_start + 5, "00000");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(text: &str) -> Vec<serde_json::Value> {
        vec![serde_json::json!({"role":"user","content":text})]
    }

    #[test]
    fn matches_live_claude_code_2_1_233_suffix_captures() {
        assert_eq!(
            compute_version_suffix("2.1.233", "audit header capture"),
            "141"
        );
        assert_eq!(
            compute_version_suffix("2.1.233", "audit oauth header capture"),
            "8a4"
        );
        assert_eq!(compute_version_suffix("2.1.233", ""), "015");
        assert_eq!(
            compute_version_suffix("2.1.87", "hello world test message"),
            "6ff"
        );
    }

    #[test]
    fn skips_meta_user_messages() {
        let messages = vec![
            serde_json::json!({"role":"user","isMeta":true,"content":"meta message"}),
            serde_json::json!({"role":"user","content":"audit header capture"}),
        ];
        assert_eq!(
            extract_first_user_message_text(&messages),
            "audit header capture"
        );
        let header = build_billing_header_value(
            "2.1.233",
            "sdk-cli",
            &extract_first_user_message_text(&messages),
            &BillingAttribution::default(),
        );
        assert!(header.contains("cc_version=2.1.233.141;"));
        let blocks = vec![
            serde_json::json!({"role":"user","content":[{"type":"image"},{"type":"text","text":"audit header capture"}]}),
        ];
        assert_eq!(
            extract_first_user_message_text(&blocks),
            "audit header capture"
        );
        assert_eq!(extract_first_user_message_text(&[]), "");
    }

    #[test]
    fn emits_only_cch_without_attribution() {
        let text = extract_first_user_message_text(&user("audit header capture"));
        assert_eq!(
            build_billing_header_value("2.1.233", "cli", &text, &BillingAttribution::default()),
            "x-anthropic-billing-header: cc_version=2.1.233.141; cc_entrypoint=cli; cch=00000;"
        );
    }

    #[test]
    fn matches_2_1_260_segment_order_and_spacing() {
        let text = extract_first_user_message_text(&user("audit header capture"));
        let header = build_billing_header_value(
            "2.1.233",
            "cli",
            &text,
            &BillingAttribution {
                workload: Some("cron"),
                is_subagent: true,
                previous_request_id: Some("req_abc123"),
                prompt_id: Some("6ba7b810-9dad-11d1-80b4-00c04fd430c8"),
            },
        );
        assert_eq!(
            header,
            "x-anthropic-billing-header: cc_version=2.1.233.141; cc_entrypoint=cli; cch=00000; cc_workload=cron; cc_is_subagent=true; cc_prev_req=req_abc123; cc_prompt_id=6ba7b810-9dad-11d1-80b4-00c04fd430c8;"
        );
        let bare =
            build_billing_header_value("2.1.233", "cli", &text, &BillingAttribution::default());
        assert_eq!(header.find(CCH_LITERAL), bare.find(CCH_LITERAL));
    }

    #[test]
    fn rejects_malformed_ids_and_omits_false_subagent() {
        let header = build_billing_header_value(
            "2.1.233",
            "cli",
            "",
            &BillingAttribution {
                previous_request_id: Some("not-a-req-id"),
                prompt_id: Some("not-a-uuid"),
                ..Default::default()
            },
        );
        assert!(!header.contains("cc_prev_req"));
        assert!(!header.contains("cc_prompt_id"));
        assert!(!header.contains("cc_is_subagent"));
    }

    #[test]
    fn normalizes_only_the_billing_header_slot() {
        let history = "historical debug content: cch=abcde; cch=00000;";
        let body = serde_json::json!({
            "messages":[{"role":"user","content":[{"type":"text","text":history}]}],
            "system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.233.141; cc_entrypoint=cli; cch=59353;"}]
        })
        .to_string();
        let normalized = normalize_billing_header_cch(&body);
        assert!(normalized.contains(history));
        assert!(normalized.contains("cc_entrypoint=cli; cch=00000;"));
        assert!(!normalized.contains("cch=59353;"));
        // Already native, or no header at all: unchanged.
        assert_eq!(normalize_billing_header_cch(&normalized), normalized);
        assert_eq!(normalize_billing_header_cch("{}"), "{}");
    }

    #[test]
    fn full_header_value_for_2_1_87() {
        let text = extract_first_user_message_text(&user("hello world test message"));
        assert_eq!(
            build_billing_header_value("2.1.87", "sdk-cli", &text, &BillingAttribution::default()),
            "x-anthropic-billing-header: cc_version=2.1.87.6ff; cc_entrypoint=sdk-cli; cch=00000;"
        );
    }
}
