//! Recovery for credential-bound encrypted server-tool content.
//!
//! Anthropic's server tools (web search, code execution) return blocks whose
//! payload is encrypted against the credential that issued them:
//! `search_result.encrypted_content`, `text.encrypted_index`, and
//! `encrypted_code_execution_result.encrypted_stdout`. Replaying a
//! conversation that carries them against a DIFFERENT OAuth account or API key
//! fails with HTTP 400 and one of the messages below — exactly what a
//! fallback-account router does when it migrates a live session.
//!
//! Claude Code 2.1.280 added labels for these (`web_search_content_rejected`,
//! `code_execution_output_rejected`; `cNn`/`dNn` in `chunk-1xqpf2j8.js`) but no
//! strip-and-retry rung. Ported from the anthropic-auth fork's
//! `encrypted-content.ts`: once the turn has already been rejected, replacing
//! the unusable blocks with a plain-text placeholder and retrying once can
//! only improve the outcome.

use serde_json::{Map, Value};

/// 400 messages Anthropic returns for a web-search payload it cannot decrypt.
const WEB_SEARCH_CONTENT_REJECTED_MESSAGES: [&str; 3] = [
    "invalid encrypted_content in search_result block",
    "invalid encrypted_index in text block",
    "failed to decrypt web search result content",
];

/// 400 message Anthropic returns for a code-execution payload it cannot decrypt.
const CODE_EXECUTION_OUTPUT_REJECTED_MESSAGE: &str =
    "invalid encrypted_stdout in encrypted_code_execution_result block";

/// Placeholder text for a dropped `search_result` block.
pub const ENCRYPTED_SEARCH_RESULT_PLACEHOLDER: &str =
    "[web search result omitted: its encrypted payload was issued to a different account]";
/// Placeholder text for a dropped `encrypted_code_execution_result` block.
pub const ENCRYPTED_CODE_EXECUTION_PLACEHOLDER: &str =
    "[code execution output omitted: its encrypted payload was issued to a different account]";

/// Claude Code's `Sat`: compare case- and backtick-insensitively.
fn normalize_error_text(body: &str) -> String {
    body.to_lowercase().replace('`', "")
}

/// Whether a response is the 2.1.280 `web_search_content_rejected` 400.
pub fn is_web_search_content_rejected_error(status: u16, body: &str) -> bool {
    if status != 400 {
        return false;
    }
    let normalized = normalize_error_text(body);
    WEB_SEARCH_CONTENT_REJECTED_MESSAGES
        .iter()
        .any(|message| normalized.contains(message))
}

/// Whether a response is the 2.1.280 `code_execution_output_rejected` 400.
pub fn is_code_execution_output_rejected_error(status: u16, body: &str) -> bool {
    status == 400 && normalize_error_text(body).contains(CODE_EXECUTION_OUTPUT_REJECTED_MESSAGE)
}

/// True when a 400 names encrypted server-tool content this credential cannot
/// decrypt — the signature of a session replayed on a different account.
pub fn is_encrypted_server_tool_content_error(status: u16, body: &str) -> bool {
    is_web_search_content_rejected_error(status, body)
        || is_code_execution_output_rejected_error(status, body)
}

fn text_block(text: &str) -> Value {
    let mut block = Map::new();
    block.insert("type".into(), Value::String("text".into()));
    block.insert("text".into(), Value::String(text.into()));
    Value::Object(block)
}

/// Rewrite one content array in place; true when anything changed. Server-tool
/// results nest their blocks one level down, so nested `content` arrays are
/// walked recursively.
fn strip_blocks(blocks: &mut [Value]) -> bool {
    let mut stripped = false;
    for entry in blocks.iter_mut() {
        let Some(block) = entry.as_object_mut() else {
            continue;
        };
        match block.get("type").and_then(Value::as_str) {
            Some("search_result") => {
                *entry = text_block(ENCRYPTED_SEARCH_RESULT_PLACEHOLDER);
                stripped = true;
            }
            Some("encrypted_code_execution_result") => {
                *entry = text_block(ENCRYPTED_CODE_EXECUTION_PLACEHOLDER);
                stripped = true;
            }
            Some("text") if block.contains_key("encrypted_index") => {
                block.shift_remove("encrypted_index");
                stripped = true;
            }
            _ => {
                if let Some(Value::Array(nested)) = block.get_mut("content") {
                    stripped |= strip_blocks(nested);
                }
            }
        }
    }
    stripped
}

/// Replace credential-bound encrypted server-tool blocks in a parsed Messages
/// body: `search_result` and `encrypted_code_execution_result` blocks become a
/// text placeholder (dropping them outright can leave an empty `content`
/// array, itself a 400), and `encrypted_index` is removed from text blocks
/// while the visible text is kept. Returns whether anything changed.
pub fn strip_encrypted_server_tool_content_value(body: &mut Value) -> bool {
    let Some(messages) = body.get_mut("messages").and_then(Value::as_array_mut) else {
        return false;
    };
    let mut stripped = false;
    for message in messages.iter_mut() {
        if let Some(Value::Array(content)) = message.get_mut("content") {
            stripped |= strip_blocks(content);
        }
    }
    stripped
}

/// [`strip_encrypted_server_tool_content_value`] over serialized JSON. Returns
/// the original text unchanged — with `false` — when there is nothing to do or
/// the body is not JSON, so a caller can skip a pointless retry.
pub fn strip_encrypted_server_tool_content(body_text: &str) -> (String, bool) {
    let Ok(mut parsed) = serde_json::from_str::<Value>(body_text) else {
        return (body_text.to_owned(), false);
    };
    if !parsed.is_object() || !strip_encrypted_server_tool_content_value(&mut parsed) {
        return (body_text.to_owned(), false);
    }
    match serde_json::to_string(&parsed) {
        Ok(text) => (text, true),
        Err(_) => (body_text.to_owned(), false),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn classifies_web_search_rejections_case_and_backtick_insensitively() {
        for body in [
            r#"{"error":{"message":"invalid encrypted_content in search_result block"}}"#,
            "Invalid `encrypted_index` in `text` block",
            "FAILED TO DECRYPT WEB SEARCH RESULT CONTENT",
        ] {
            assert!(is_web_search_content_rejected_error(400, body), "{body}");
            assert!(is_encrypted_server_tool_content_error(400, body), "{body}");
            assert!(
                !is_code_execution_output_rejected_error(400, body),
                "{body}"
            );
        }
        assert!(!is_web_search_content_rejected_error(
            500,
            "invalid encrypted_content in search_result block"
        ));
        assert!(!is_web_search_content_rejected_error(400, ""));
    }

    #[test]
    fn classifies_code_execution_rejections() {
        let body = "Invalid `encrypted_stdout` in `encrypted_code_execution_result` block";
        assert!(is_code_execution_output_rejected_error(400, body));
        assert!(is_encrypted_server_tool_content_error(400, body));
        assert!(!is_web_search_content_rejected_error(400, body));
        assert!(!is_code_execution_output_rejected_error(429, body));
        assert!(!is_encrypted_server_tool_content_error(400, "unrelated"));
    }

    /// Byte-for-byte vector produced by the fork's
    /// `stripEncryptedServerToolContent` under Bun.
    #[test]
    fn strips_nested_blocks_matching_fork_vector() {
        let input = json!({"messages":[{"role":"assistant","content":[
            {"type":"text","text":"a","encrypted_index":"x","citations":[]},
            {"type":"web_search_tool_result","tool_use_id":"t","content":[{"type":"search_result","encrypted_content":"z"}]},
            {"type":"encrypted_code_execution_result","encrypted_stdout":"q"}
        ]}]})
        .to_string();
        let (out, stripped) = strip_encrypted_server_tool_content(&input);
        assert!(stripped);
        assert_eq!(
            out,
            r#"{"messages":[{"role":"assistant","content":[{"type":"text","text":"a","citations":[]},{"type":"web_search_tool_result","tool_use_id":"t","content":[{"type":"text","text":"[web search result omitted: its encrypted payload was issued to a different account]"}]},{"type":"text","text":"[code execution output omitted: its encrypted payload was issued to a different account]"}]}]}"#
        );
    }

    #[test]
    fn leaves_clean_or_invalid_bodies_untouched() {
        let clean = r#"{"messages":[{"role":"user","content":"hi"},{"role":"assistant","content":[{"type":"text","text":"ok"}]}]}"#;
        assert_eq!(
            strip_encrypted_server_tool_content(clean),
            (clean.to_owned(), false)
        );
        assert_eq!(
            strip_encrypted_server_tool_content("not json"),
            ("not json".to_owned(), false)
        );
        assert_eq!(
            strip_encrypted_server_tool_content("[]"),
            ("[]".to_owned(), false)
        );
        assert_eq!(
            strip_encrypted_server_tool_content(r#"{"model":"m"}"#),
            (r#"{"model":"m"}"#.to_owned(), false)
        );
    }
}
