//! Claude Code 2.1.138–2.1.233 billing-header CCH signing (legacy).
//!
//! Those versions patch `cch=00000` inside the first billing system block
//! immediately before transport. Versions 2.1.172–2.1.233 hash a canonical
//! preimage: every `model` value is emptied and every integer `max_tokens`
//! field (plus one adjacent comma) is removed. Nested-field native oracles
//! confirm that this transform is global. Only the five-character wire
//! slot is changed; the actual request keeps its model and token limit.
//!
//! **Claude Code 2.1.260 does not sign this slot.** It emits the literal
//! `cch=00000;` and derives the `cc_version` suffix from the first user
//! message instead — see [`crate::billing`]. Requests fingerprinted as
//! 2.1.260 or newer must use [`crate::billing::build_billing_header_value`]
//! and must not call [`sign_request_body`]; this module is retained for
//! diagnostics and for callers pinned to the 2.1.233 fingerprint.

use crate::error::{Error, Result};

/// Placeholder emitted while constructing the billing header.
pub const CCH_PLACEHOLDER: &str = "cch=00000";
/// Claude Code 2.1.138–2.1.233 xxHash64 seed.
pub const CCH_SEED_2_1_233: u64 = 0x4d65_9218_e32a_3268;
const CCH_MASK: u64 = 0x0f_ffff;

/// Compute the five-character CCH from canonical preimage bytes.
pub fn compute_cch(preimage: &[u8]) -> String {
    let hash = xxhash_rust::xxh64::xxh64(preimage, CCH_SEED_2_1_233);
    format!("{:05x}", hash & CCH_MASK)
}

/// Apply the Claude Code 2.1.172+ CCH preimage transform.
pub fn build_cch_preimage(serialized_body: &str) -> String {
    let mut output = serialized_body.to_owned();
    let model_prefix = "\"model\":\"";
    let mut search_from = 0;
    while let Some(relative_start) = output[search_from..].find(model_prefix) {
        let value_start = search_from + relative_start + model_prefix.len();
        let Some(value_end) = find_json_string_end(&output, value_start) else {
            break;
        };
        output.replace_range(value_start..value_end, "");
        search_from = value_start + 1;
    }

    let max_tokens_prefix = "\"max_tokens\":";
    search_from = 0;
    while let Some(relative_start) = output[search_from..].find(max_tokens_prefix) {
        let field_start = search_from + relative_start;
        let value_start = field_start + max_tokens_prefix.len();
        let value_end = output[value_start..]
            .bytes()
            .take_while(u8::is_ascii_digit)
            .count()
            + value_start;
        if value_end == value_start {
            search_from = value_start;
            continue;
        }
        if output.as_bytes().get(value_end) == Some(&b',') {
            output.replace_range(field_start..=value_end, "");
            search_from = field_start;
        } else if field_start > 0 && output.as_bytes()[field_start - 1] == b',' {
            output.replace_range(field_start - 1..value_end, "");
            search_from = field_start.saturating_sub(1);
        } else if output.as_bytes().get(value_end) == Some(&b'}') {
            output.replace_range(field_start..value_end, "");
            search_from = field_start;
        } else {
            search_from = value_end;
        }
    }
    output
}

/// Sign the billing-header placeholder in a serialized Messages request.
///
/// The billing header must be the first system text block. Other literal
/// `cch=00000` strings in message history are never modified.
pub fn sign_request_body(serialized_body: &str) -> Result<String> {
    let first_system_prefix =
        "\"system\":[{\"type\":\"text\",\"text\":\"x-anthropic-billing-header:";
    let header_start = serialized_body
        .find(first_system_prefix)
        .ok_or_else(|| Error::Protocol("billing header is not the first system block".into()))?;
    let header_content_start = header_start + first_system_prefix.len();
    let header_end = serialized_body[header_content_start..]
        .find('"')
        .map(|offset| header_content_start + offset)
        .ok_or_else(|| Error::Protocol("billing header is unterminated".into()))?;
    let placeholder_start = serialized_body[header_start..header_end]
        .find(CCH_PLACEHOLDER)
        .map(|offset| header_start + offset)
        .ok_or_else(|| Error::Protocol("billing header has no CCH placeholder".into()))?;

    let preimage = build_cch_preimage(serialized_body);
    let token = compute_cch(preimage.as_bytes());
    let digits_start = placeholder_start + "cch=".len();
    let mut signed = serialized_body.to_owned();
    signed.replace_range(digits_start..digits_start + 5, &token);
    Ok(signed)
}

fn find_json_string_end(value: &str, start: usize) -> Option<usize> {
    let bytes = value.as_bytes();
    let mut index = start;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            return Some(index);
        }
        index += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_six_pair_native_oracle_vector() {
        let body = r#"{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"probe-0"}],"system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.233.000; cc_entrypoint=sdk-cli; cch=00000;"}],"max_tokens":1,"stream":true}"#;
        let preimage = build_cch_preimage(body);
        assert!(preimage.contains("\"model\":\"\""));
        assert!(!preimage.contains("max_tokens"));
        let signed = sign_request_body(body).unwrap();
        assert!(signed.contains("cch=833f0;"));
        assert!(signed.contains("\"model\":\"claude-sonnet-4-6\""));
        assert!(signed.contains("\"max_tokens\":1"));
    }

    #[test]
    fn globally_canonicalizes_nested_model_and_max_token_fields() {
        assert_eq!(
            build_cch_preimage(r#"{"input":{"max_tokens":7}}"#),
            r#"{"input":{}}"#
        );
        let nested_max = r#"{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"nested-probe","max_tokens":7}],"system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.233.000; cc_entrypoint=sdk-cli; cch=00000;"}],"max_tokens":1,"stream":true}"#;
        assert!(
            sign_request_body(nested_max)
                .unwrap()
                .contains("cch=3632a;")
        );

        let nested_model = r#"{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"nested-model-probe","model":"nested"}],"system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.233.000; cc_entrypoint=sdk-cli; cch=00000;"}],"max_tokens":1,"stream":true}"#;
        assert!(
            sign_request_body(nested_model)
                .unwrap()
                .contains("cch=4db54;")
        );
    }

    #[test]
    fn only_first_billing_block_placeholder_is_patched() {
        let history = "message history cch=00000";
        let body = format!(
            r#"{{"model":"m","messages":[{{"role":"user","content":"{history}"}}],"system":[{{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.233.000; cc_entrypoint=sdk-cli; cch=00000;"}}],"max_tokens":1}}"#
        );
        let signed = sign_request_body(&body).unwrap();
        assert!(signed.contains(history));
        assert_eq!(signed.matches(CCH_PLACEHOLDER).count(), 1);
    }
}
