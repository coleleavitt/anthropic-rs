//! Billing-header `cch` signing, aligned with the merged anthropic-auth
//! TypeScript (`cch.ts` at merge `f74d736`: upstream canonical signing wins,
//! the fork's mode switch is kept).
//!
//! The billing header is built with a `cch=00000;` placeholder
//! ([`crate::billing::build_billing_header_value`]). After the final request
//! body is serialized, [`sign_request_body_with_mode`] fills that slot.
//!
//! **Default ([`CchMode::Native`]) = upstream canonical signing**
//! ([`sign_request_body`], TS `signRequestBody`):
//!
//! 1. The body must match the TS pattern, with the billing header as
//!    `system[0]`:
//!    `"system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=[^;"]+; cc_entrypoint=[^;"]+; cch=[0-9a-f]{5};`.
//!    Otherwise the body is returned unchanged.
//! 2. Any previously signed slot is reset to `cch=00000;`.
//! 3. The body is parsed; the top-level `model` (when present) becomes `""`
//!    and the top-level `max_tokens` is deleted; it is re-serialized exactly
//!    as `JSON.stringify` would ([`js_json_stringify`]).
//! 4. xxHash64 (seed `0x4d659218e32a3268`) of those bytes, low 20 bits, as
//!    five zero-padded lower-case hex digits, replaces the placeholder in the
//!    *original* (unsigned) serialization. Only those five bytes change.
//!
//! The fork's `ANTHROPIC_AUTH_CCH_MODE` switch is kept: `literal` (the
//! 2.1.260-era `cch=00000;`), `hmac` and `xxhash` (experimental).
//!
//! [`sign_request_body_2_1_233`] keeps this crate's earlier port of Claude
//! Code 2.1.233's *global* preimage transform (every nested `model` emptied,
//! every integer `max_tokens` removed), which native-binary oracles
//! confirmed. It differs from the merged TS only for bodies that carry nested
//! `model` / `max_tokens` fields and is retained for diagnostics.

use crate::error::{Error, Result};

/// Placeholder emitted while constructing the billing header.
pub const CCH_PLACEHOLDER: &str = "cch=00000";
/// Claude Code xxHash64 seed (2.1.138+, unchanged at 2.1.280).
pub const CCH_SEED_2_1_233: u64 = 0x4d65_9218_e32a_3268;
const CCH_MASK: u64 = 0x0f_ffff;

/// Compute the five-character CCH from canonical preimage bytes.
pub fn compute_cch(preimage: &[u8]) -> String {
    let hash = xxhash_rust::xxh64::xxh64(preimage, CCH_SEED_2_1_233);
    format!("{:05x}", hash & CCH_MASK)
}

/// TS `buildCCHPreimage`-style diagnostic transform: every `model` value is
/// emptied and every integer `max_tokens` field (plus one adjacent comma) is
/// removed, at any depth. Used by [`sign_request_body_2_1_233`];
/// [`sign_request_body`] canonicalizes the parsed body instead.
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

/// Byte offset of the five `cch` digits in the first match of the TS
/// `BILLING_HEADER_CCH_PATTERN`:
///
/// ```text
/// "system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=[^;"]+; cc_entrypoint=[^;"]+; cch=([0-9a-f]{5});
/// ```
///
/// With `placeholder_only`, the digits must be `00000` (TS
/// `BILLING_HEADER_CCH_PLACEHOLDER_PATTERN`). The leftmost match wins, as
/// with a non-global JavaScript regex.
pub fn billing_header_cch_offset(serialized_body: &str, placeholder_only: bool) -> Option<usize> {
    const PREFIX: &str =
        "\"system\":[{\"type\":\"text\",\"text\":\"x-anthropic-billing-header: cc_version=";
    let bytes = serialized_body.as_bytes();
    // `[^;"]+` followed by `literal`: greedy with no useful backtracking,
    // because the class excludes the literal's first byte (`;`).
    let segment = |from: usize, literal: &str| -> Option<usize> {
        let run = bytes[from..]
            .iter()
            .take_while(|b| **b != b';' && **b != b'"')
            .count();
        if run == 0 {
            return None;
        }
        let at = from + run;
        serialized_body[at..]
            .starts_with(literal)
            .then_some(at + literal.len())
    };
    let mut search_from = 0;
    while let Some(relative) = serialized_body[search_from..].find(PREFIX) {
        let start = search_from + relative;
        search_from = start + 1;
        let Some(after_version) = segment(start + PREFIX.len(), "; cc_entrypoint=") else {
            continue;
        };
        let Some(digits) = segment(after_version, "; cch=") else {
            continue;
        };
        let Some(slot) = bytes.get(digits..digits + 6) else {
            continue;
        };
        let hex_ok = slot[..5]
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b));
        if !hex_ok || slot[5] != b';' {
            continue;
        }
        if placeholder_only && &slot[..5] != b"00000" {
            continue;
        }
        return Some(digits);
    }
    None
}

/// TS `extractBillingHeaderCCH`: the five digits currently in the billing
/// header slot.
pub fn extract_billing_header_cch(serialized_body: &str) -> Option<&str> {
    let at = billing_header_cch_offset(serialized_body, false)?;
    Some(&serialized_body[at..at + 5])
}

/// TS `resetBillingHeaderCCH`: put the billing-header slot back to
/// `cch=00000;`. Message history is never touched; a body without a
/// matching billing header is returned unchanged.
pub fn reset_billing_header_cch(serialized_body: &str) -> String {
    let mut out = serialized_body.to_owned();
    if let Some(at) = billing_header_cch_offset(serialized_body, false) {
        out.replace_range(at..at + 5, "00000");
    }
    out
}

/// Serialize a JSON value exactly as JavaScript's `JSON.stringify` does:
/// compact, insertion-ordered keys, the same string escapes, and ECMAScript
/// `Number::toString` numerals (`1.0` → `1`, `1e21` → `1e+21`, `-0` → `0`,
/// integers beyond 2^53 rounded through `f64`).
pub fn js_json_stringify(value: &serde_json::Value) -> String {
    let mut out = String::new();
    write_js_json(value, &mut out);
    out
}

fn write_js_json(value: &serde_json::Value, out: &mut String) {
    use serde_json::Value;
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&js_number(n)),
        // serde_json's escaping is JSON.stringify's: `"`, `\\`, \b \t \n \f
        // \r, other C0 controls as lower-case `\u00xx`, everything else raw.
        Value::String(s) => out.push_str(&serde_json::Value::String(s.clone()).to_string()),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_js_json(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (index, (key, item)) in map.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::Value::String(key.clone()).to_string());
                out.push(':');
                write_js_json(item, out);
            }
            out.push('}');
        }
    }
}

const JS_MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

fn js_number(number: &serde_json::Number) -> String {
    if let Some(u) = number.as_u64()
        && u <= JS_MAX_SAFE_INTEGER
    {
        return u.to_string();
    }
    if let Some(i) = number.as_i64()
        && i.unsigned_abs() <= JS_MAX_SAFE_INTEGER
    {
        return i.to_string();
    }
    js_f64_to_string(number.as_f64().unwrap_or(0.0))
}

/// ECMAScript `Number::toString(10)` for a finite `f64`.
fn js_f64_to_string(value: f64) -> String {
    if value == 0.0 {
        return "0".into();
    }
    if !value.is_finite() {
        // JSON.stringify renders non-finite numbers as null; serde_json
        // values never hold them.
        return "null".into();
    }
    let sign = if value < 0.0 { "-" } else { "" };
    // Rust's `{:e}` prints the shortest round-trip digits, as JS does.
    let scientific = format!("{:e}", value.abs());
    let (mantissa, exponent) = scientific.split_once('e').unwrap_or((&scientific, "0"));
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let k = digits.len() as i64;
    let n = exponent.parse::<i64>().unwrap_or(0) + 1;
    let body = if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat((-n) as usize))
    } else {
        let exp_sign = if n - 1 < 0 { "-" } else { "+" };
        let exp = (n - 1).abs();
        if k == 1 {
            format!("{digits}e{exp_sign}{exp}")
        } else {
            format!("{}.{}e{exp_sign}{exp}", &digits[..1], &digits[1..])
        }
    };
    format!("{sign}{body}")
}

/// Upstream canonical signing (TS `signRequestBody`, the merged default).
///
/// Returns the body unchanged when it has no matching billing header (the
/// header must be `system[0]`) or when the body is not a JSON object. Only
/// the five slot digits of the original serialization change; the request
/// keeps its model, token limit and byte layout.
pub fn sign_request_body(serialized_body: &str) -> String {
    if billing_header_cch_offset(serialized_body, false).is_none() {
        return serialized_body.to_owned();
    }
    let unsigned = reset_billing_header_cch(serialized_body);
    let Ok(serde_json::Value::Object(mut canonical)) =
        serde_json::from_str::<serde_json::Value>(&unsigned)
    else {
        return serialized_body.to_owned();
    };
    if let Some(model) = canonical.get_mut("model") {
        *model = serde_json::Value::String(String::new());
    }
    canonical.shift_remove("max_tokens");
    let token = compute_cch(js_json_stringify(&serde_json::Value::Object(canonical)).as_bytes());
    let Some(at) = billing_header_cch_offset(&unsigned, true) else {
        return unsigned;
    };
    let mut signed = unsigned;
    signed.replace_range(at..at + 5, &token);
    signed
}

/// Claude Code 2.1.172–2.1.233 signing with the *global* string preimage
/// ([`build_cch_preimage`]), kept for diagnostics against native oracles.
/// The slot must hold the placeholder.
pub fn sign_request_body_2_1_233(serialized_body: &str) -> Result<String> {
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

/// Environment variable selecting the [`CchMode`].
pub const CCH_MODE_ENV: &str = "ANTHROPIC_AUTH_CCH_MODE";

/// How [`sign_request_body_with_mode`] fills the billing-header `cch` slot
/// (TS `CCHMode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CchMode {
    /// Upstream canonical xxHash64 signing ([`sign_request_body`]). Default.
    #[default]
    Native,
    /// Keep the literal `cch=00000;` (the fork's 2.1.260-era claim); any
    /// signed slot is reset.
    Literal,
    /// First five hex digits of HMAC-SHA256(key = `59cf53e54c78`, body).
    Hmac,
    /// xxHash64 (same seed, 20-bit mask) over the raw serialized body,
    /// placeholder included and without canonicalization.
    Xxhash,
}

impl CchMode {
    /// Parse an `ANTHROPIC_AUTH_CCH_MODE` value (trimmed, case-insensitive);
    /// anything unrecognized, or absent, is [`CchMode::Native`].
    pub fn from_env_value(value: Option<&str>) -> Self {
        match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
            Some("hmac") => Self::Hmac,
            Some("xxhash") => Self::Xxhash,
            Some("literal") => Self::Literal,
            _ => Self::Native,
        }
    }

    /// [`CchMode::from_env_value`] reading [`CCH_MODE_ENV`].
    pub fn from_env() -> Self {
        Self::from_env_value(std::env::var(CCH_MODE_ENV).ok().as_deref())
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    const BLOCK: usize = 64;
    let mut block_key = [0u8; BLOCK];
    if key.len() > BLOCK {
        block_key[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block_key[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(block_key.map(|b| b ^ 0x36));
    inner.update(data);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(block_key.map(|b| b ^ 0x5c));
    outer.update(inner);
    outer.finalize().into()
}

/// The fork's HMAC body attestation token: the first five hex digits of
/// HMAC-SHA256 keyed with [`crate::billing::CCH_SALT`].
pub fn compute_hmac_cch(serialized_body: &str) -> String {
    let digest = hmac_sha256(
        crate::billing::CCH_SALT.as_bytes(),
        serialized_body.as_bytes(),
    );
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    hex[..5].to_owned()
}

/// Fill the billing-header `cch` slot according to `mode` (TS
/// `signRequestBodyWithMode`).
///
/// - [`CchMode::Native`] uses [`sign_request_body`].
/// - [`CchMode::Literal`] uses [`reset_billing_header_cch`].
/// - [`CchMode::Hmac`] / [`CchMode::Xxhash`] hash the body exactly as given
///   and write the token into the billing-header placeholder. Unlike the
///   TypeScript `String.replace`, a literal `cch=00000;` in message history
///   is never touched; a body without a placeholder slot is returned
///   unchanged.
pub fn sign_request_body_with_mode(serialized_body: &str, mode: CchMode) -> String {
    let token = match mode {
        CchMode::Native => return sign_request_body(serialized_body),
        CchMode::Literal => return reset_billing_header_cch(serialized_body),
        CchMode::Hmac => compute_hmac_cch(serialized_body),
        CchMode::Xxhash => compute_cch(serialized_body.as_bytes()),
    };
    let Some(digits) = billing_header_cch_offset(serialized_body, true) else {
        return serialized_body.to_owned();
    };
    let mut signed = serialized_body.to_owned();
    signed.replace_range(digits..digits + 5, &token);
    signed
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

    const HDR: &str =
        "x-anthropic-billing-header: cc_version=2.1.280.015; cc_entrypoint=cli; cch=00000;";

    fn with_cch(body: &str, token: &str) -> String {
        body.replacen("cch=00000;", &format!("cch={token};"), 1)
    }

    /// 2.1.233 native-oracle body: top-level-only fields, so the merged TS
    /// canonical signer and the global 2.1.233 transform agree (`833f0`).
    #[test]
    fn matches_six_pair_native_oracle_vector() {
        let body = r#"{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"probe-0"}],"system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.233.000; cc_entrypoint=sdk-cli; cch=00000;"}],"max_tokens":1,"stream":true}"#;
        let preimage = build_cch_preimage(body);
        assert!(preimage.contains("\"model\":\"\""));
        assert!(!preimage.contains("max_tokens"));
        let signed = sign_request_body(body);
        assert_eq!(signed, with_cch(body, "833f0"));
        assert_eq!(sign_request_body_2_1_233(body).unwrap(), signed);
    }

    /// Nested `model` / `max_tokens`: the merged TS only canonicalizes the
    /// top level (Bun vectors `bd41c` / `87d8c`); the 2.1.233 global
    /// transform (native oracles `3632a` / `4db54`) is kept separately.
    #[test]
    fn canonical_signing_is_top_level_only_unlike_2_1_233() {
        assert_eq!(
            build_cch_preimage(r#"{"input":{"max_tokens":7}}"#),
            r#"{"input":{}}"#
        );
        let nested_max = r#"{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"nested-probe","max_tokens":7}],"system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.233.000; cc_entrypoint=sdk-cli; cch=00000;"}],"max_tokens":1,"stream":true}"#;
        assert_eq!(sign_request_body(nested_max), with_cch(nested_max, "bd41c"));
        assert_eq!(
            sign_request_body_2_1_233(nested_max).unwrap(),
            with_cch(nested_max, "3632a")
        );

        let nested_model = r#"{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"nested-model-probe","model":"nested"}],"system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.233.000; cc_entrypoint=sdk-cli; cch=00000;"}],"max_tokens":1,"stream":true}"#;
        assert_eq!(
            sign_request_body(nested_model),
            with_cch(nested_model, "87d8c")
        );
        assert_eq!(
            sign_request_body_2_1_233(nested_model).unwrap(),
            with_cch(nested_model, "4db54")
        );
    }

    fn mode_body() -> String {
        format!(
            r#"{{"model":"claude-opus-5-5","messages":[{{"role":"user","content":"hi"}}],"system":[{{"type":"text","text":"{HDR}"}}],"max_tokens":1}}"#
        )
    }

    /// Vectors produced by merged-TS `signRequestBodyWithMode` under Bun.
    #[test]
    fn cch_modes_match_merged_ts_vectors() {
        assert_eq!(CchMode::default(), CchMode::Native);
        assert_eq!(CchMode::from_env_value(None), CchMode::Native);
        assert_eq!(CchMode::from_env_value(Some(" HMAC ")), CchMode::Hmac);
        assert_eq!(CchMode::from_env_value(Some("xxhash")), CchMode::Xxhash);
        assert_eq!(CchMode::from_env_value(Some("Literal")), CchMode::Literal);
        assert_eq!(CchMode::from_env_value(Some("native")), CchMode::Native);
        assert_eq!(CchMode::from_env_value(Some("sha")), CchMode::Native);
        let body = mode_body();
        assert_eq!(
            sign_request_body_with_mode(&body, CchMode::Native),
            with_cch(&body, "f1816")
        );
        assert_eq!(sign_request_body_with_mode(&body, CchMode::Literal), body);
        assert_eq!(
            sign_request_body_with_mode(&body, CchMode::Hmac),
            with_cch(&body, "38a56")
        );
        let xx = sign_request_body_with_mode(&body, CchMode::Xxhash);
        assert_eq!(xx, with_cch(&body, "26053"));
        // Literal resets a signed slot back to the placeholder.
        assert_eq!(sign_request_body_with_mode(&xx, CchMode::Literal), body);
        // An already-signed slot has no placeholder for hmac/xxhash to fill.
        assert_eq!(sign_request_body_with_mode(&xx, CchMode::Hmac), xx);
        // Native re-signs: a stale token is reset before hashing.
        let presigned = with_cch(&body, "abc12");
        assert_eq!(sign_request_body(&presigned), with_cch(&body, "f1816"));
        assert_eq!(extract_billing_header_cch(&presigned), Some("abc12"));
    }

    /// Bun vector: numbers, escapes and whitespace are canonicalized through
    /// `JSON.parse`/`JSON.stringify`, while the wire keeps its bytes.
    #[test]
    fn canonical_preimage_matches_json_stringify() {
        let body = format!(
            r#"{{"model":"claude-opus-5","messages":[{{"role":"user","content":"n\u0001\"é\/"}}],"system":[{{"type":"text","text":"{HDR} cc_workload=cron;"}}],"max_tokens":64000,"temperature":1.0,"top_p":0.7,"x":1e21,"y":1.5e-7,"z":12345678901234567890,"w":-0.0,"v":100e0,"u":[1,2.50,{{"a":null,"b":true}}]}}"#
        );
        let mut parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        let object = parsed.as_object_mut().unwrap();
        object.insert("model".into(), "".into());
        object.shift_remove("max_tokens");
        assert_eq!(
            js_json_stringify(&parsed),
            format!(
                r#"{{"model":"","messages":[{{"role":"user","content":"n\u0001\"é/"}}],"system":[{{"type":"text","text":"{HDR} cc_workload=cron;"}}],"temperature":1,"top_p":0.7,"x":1e+21,"y":1.5e-7,"z":12345678901234567000,"w":0,"v":100,"u":[1,2.5,{{"a":null,"b":true}}]}}"#
            )
        );
        assert_eq!(sign_request_body(&body), with_cch(&body, "e75e7"));

        let spaced = format!(
            "{{ \"model\" : \"claude-opus-5\",\n \"system\":[{{\"type\":\"text\",\"text\":\"{HDR}\"}}], \"max_tokens\": 5 }}"
        );
        // Whitespace breaks the `"system":[{"type":…` pattern only inside it;
        // here the pattern still matches, and the output keeps the spacing.
        assert_eq!(sign_request_body(&spaced), with_cch(&spaced, "995dc"));
        let no_model = format!(
            r#"{{"messages":[],"system":[{{"type":"text","text":"{HDR}"}}],"max_tokens":3}}"#
        );
        assert_eq!(sign_request_body(&no_model), with_cch(&no_model, "3d394"));
    }

    #[test]
    fn js_number_formatting_follows_ecmascript() {
        for (value, expected) in [
            (0.1, "0.1"),
            (1e-7, "1e-7"),
            (0.000001, "0.000001"),
            (123e20, "1.23e+22"),
            (1e21, "1e+21"),
            (999999999999999900000.0, "999999999999999900000"),
            (-2.5, "-2.5"),
            (5e-324, "5e-324"),
        ] {
            assert_eq!(js_f64_to_string(value), expected, "{value}");
        }
    }

    #[test]
    fn signing_requires_the_header_as_the_first_system_block() {
        let no_header = r#"{"model":"m","system":[{"type":"text","text":"hello"}],"max_tokens":1}"#;
        assert_eq!(sign_request_body(no_header), no_header);
        let not_first = format!(
            r#"{{"model":"m","system":[{{"type":"text","text":"hello"}},{{"type":"text","text":"{HDR}"}}],"max_tokens":1}}"#
        );
        assert_eq!(sign_request_body(&not_first), not_first);
        assert_eq!(
            sign_request_body_with_mode(&not_first, CchMode::Hmac),
            not_first
        );
        // Header segments out of order do not match the TS pattern.
        let reordered = r#"{"system":[{"type":"text","text":"x-anthropic-billing-header: cc_entrypoint=cli; cc_version=1; cch=00000;"}]}"#;
        assert_eq!(sign_request_body(reordered), reordered);
    }

    #[test]
    fn signing_never_touches_history_placeholders() {
        let body = format!(
            r#"{{"model":"m","messages":[{{"role":"user","content":"x cch=00000; y"}}],"system":[{{"type":"text","text":"{HDR}"}}]}}"#
        );
        // Bun vector `04ea8`.
        let native = sign_request_body(&body);
        assert_eq!(
            native,
            body.replace(HDR, &HDR.replace("cch=00000;", "cch=04ea8;"))
        );
        assert!(native.contains("\"x cch=00000; y\""));
        let hmac = sign_request_body_with_mode(&body, CchMode::Hmac);
        assert!(hmac.contains("\"x cch=00000; y\""));
        assert_eq!(hmac.matches("cch=00000;").count(), 1);
        assert_eq!(sign_request_body_with_mode("{}", CchMode::Xxhash), "{}");
        assert_eq!(sign_request_body("{}"), "{}");
    }

    #[test]
    fn seed_mask_and_placeholder_match_2_1_280() {
        assert_eq!(CCH_SEED_2_1_233, 0x4d65_9218_e32a_3268);
        assert_eq!(CCH_MASK, 0xf_ffff);
        assert_eq!(CCH_PLACEHOLDER, "cch=00000");
        assert_eq!(format!("{CCH_PLACEHOLDER};"), crate::billing::CCH_LITERAL);
        let token = compute_cch(b"");
        assert_eq!(token.len(), 5);
        assert!(
            token
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
    }

    #[test]
    fn hmac_matches_rfc_4231_style_vector() {
        let digest = hmac_sha256(b"key", b"The quick brown fox jumps over the lazy dog");
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
        let long = hmac_sha256(
            &[0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        let hex: String = long.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn legacy_2_1_233_signer_patches_only_the_first_billing_block() {
        let history = "message history cch=00000";
        let body = format!(
            r#"{{"model":"m","messages":[{{"role":"user","content":"{history}"}}],"system":[{{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.233.000; cc_entrypoint=sdk-cli; cch=00000;"}}],"max_tokens":1}}"#
        );
        let signed = sign_request_body_2_1_233(&body).unwrap();
        assert!(signed.contains(history));
        assert_eq!(signed.matches(CCH_PLACEHOLDER).count(), 1);
    }
}
