//! Claude Code 2.1.280 billing header (`x-anthropic-billing-header`), as
//! merged in anthropic-auth `f74d736` (`cch.ts`).
//!
//! The header is the first `system` text block of a Messages request:
//!
//! ```text
//! x-anthropic-billing-header: cc_version=<ver>.<sfx>; cc_entrypoint=<ep>; cch=00000;[ cc_workload=<w>;][ cc_is_subagent=true;][ cc_prev_req=req_…;][ cc_prompt_id=<uuid>;]
//! ```
//!
//! `cc_workload` / `cc_is_subagent` are the fork's segments and come before
//! upstream's lineage segments `cc_prev_req` / `cc_prompt_id`.
//!
//! `<sfx>` is the message-derived three-character suffix
//! `sha256("59cf53e54c78" + text[4] + text[7] + text[20] + version)[..3]`
//! where `text` is the first user text ([`extract_first_user_message_text`],
//! or a per-session pinned value from [`FirstUserTextTracker`]) and a missing
//! position samples `'0'`.
//!
//! **`cch=00000;` is a placeholder.** After the final body is serialized,
//! [`crate::cch::sign_request_body_with_mode`] fills it; the merged default
//! ([`crate::cch::CchMode::Native`]) signs it with upstream's canonical
//! xxHash64. [`normalize_billing_header_cch`] resets a signed slot.

use sha2::{Digest, Sha256};

/// Salt prefixed to the sampled characters and the version.
pub const CCH_SALT: &str = "59cf53e54c78";
/// UTF-16 code-unit positions sampled from the first user text.
pub const CCH_POSITIONS: [usize; 3] = [4, 7, 20];
/// Default entrypoint segment.
pub const CLAUDE_CODE_ENTRYPOINT: &str = "cli";
/// The unsigned `cch` placeholder slot (literal on the wire only in
/// [`crate::cch::CchMode::Literal`]).
pub const CCH_LITERAL: &str = "cch=00000;";
/// Default capacity of [`FirstUserTextTracker`] (TS `limit = 1_000`).
pub const FIRST_USER_TEXT_TRACKER_LIMIT: usize = 1_000;

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

/// Text of the first non-meta user message (TS `extractFirstUserMessageText`):
///
/// 1. the first `role:"user"` message whose `isMeta` is not `true`;
/// 2. a string body verbatim;
/// 3. else the first `text` block containing `<command-name>`, sliced from
///    that tag;
/// 4. else the **last** non-empty `text` block (Claude Code prepends
///    reminder blocks before the visible prompt);
/// 5. else empty.
pub fn extract_first_user_message_text(messages: &[serde_json::Value]) -> String {
    let Some(user) = messages.iter().find(|m| {
        m.get("role").and_then(|r| r.as_str()) == Some("user")
            && m.get("isMeta").and_then(|v| v.as_bool()) != Some(true)
    }) else {
        return String::new();
    };
    match user.get("content") {
        Some(serde_json::Value::String(text)) => text.clone(),
        Some(serde_json::Value::Array(blocks)) => {
            let texts: Vec<Option<&str>> = blocks
                .iter()
                .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("text"))
                .map(|b| b.get("text").and_then(|t| t.as_str()))
                .collect();
            if let Some(command) = texts
                .iter()
                .flatten()
                .find(|text| text.contains("<command-name>"))
                && let Some(at) = command.find("<command-name>")
            {
                return command[at..].to_owned();
            }
            texts
                .iter()
                .rev()
                .flatten()
                .find(|text| !text.is_empty())
                .map(|text| (*text).to_owned())
                .unwrap_or_default()
        }
        _ => String::new(),
    }
}

/// Per-session pinned first-user text (TS `ClaudeCodeFirstUserTextTracker`):
/// the first resolution for a session is kept, so later turns (after
/// compaction or history edits) keep the same `cc_version` suffix. LRU with
/// a fixed capacity.
#[derive(Debug, Clone)]
pub struct FirstUserTextTracker {
    limit: usize,
    // Front = least recently used.
    values: std::collections::VecDeque<(String, String)>,
}

impl Default for FirstUserTextTracker {
    fn default() -> Self {
        Self::new(FIRST_USER_TEXT_TRACKER_LIMIT)
    }
}

impl FirstUserTextTracker {
    /// A tracker holding at most `limit` sessions.
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            values: std::collections::VecDeque::new(),
        }
    }

    /// The pinned text for `session_id`, or extract it from `messages`
    /// (pinning it when `pin`).
    pub fn resolve(
        &mut self,
        session_id: &str,
        messages: &[serde_json::Value],
        pin: bool,
    ) -> String {
        if let Some(index) = self.values.iter().position(|(id, _)| id == session_id)
            && let Some(entry) = self.values.remove(index)
        {
            let value = entry.1.clone();
            self.values.push_back(entry);
            return value;
        }
        let value = extract_first_user_message_text(messages);
        if pin && self.limit > 0 {
            if self.values.len() >= self.limit {
                self.values.pop_front();
            }
            self.values
                .push_back((session_id.to_owned(), value.clone()));
        }
        value
    }

    /// Whether `session_id` has a pinned value.
    pub fn has(&self, session_id: &str) -> bool {
        self.values.iter().any(|(id, _)| id == session_id)
    }

    /// Forget every session.
    pub fn clear(&mut self) {
        self.values.clear();
    }
}

/// Optional billing-attribution segments.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BillingAttribution<'a> {
    /// `cc_workload=<w>;`
    pub workload: Option<&'a str>,
    /// `cc_is_subagent=true;`
    pub is_subagent: bool,
    /// `cc_prev_req=<req_…>;` — emitted only when it matches
    /// `^req_[A-Za-z0-9_-]{8,128}$` ([`is_valid_anthropic_request_id`]).
    pub previous_request_id: Option<&'a str>,
    /// `cc_prompt_id=<uuid>;` — emitted only when
    /// [`is_valid_billing_prompt_id`] accepts it.
    pub prompt_id: Option<&'a str>,
}

/// Upstream `isValidAnthropicRequestId`: `^req_[A-Za-z0-9_-]{8,128}$`.
pub fn is_valid_anthropic_request_id(value: &str) -> bool {
    value.strip_prefix("req_").is_some_and(|rest| {
        (8..=128).contains(&rest.len())
            && rest
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    })
}

/// Upstream `isValidBillingPromptId`: an RFC 9562 UUID string, version
/// 1–8, variant `8`–`b`, case-insensitive.
pub fn is_valid_billing_prompt_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    let shape = bytes.iter().enumerate().all(|(i, b)| match i {
        8 | 13 | 18 | 23 => *b == b'-',
        _ => b.is_ascii_hexdigit(),
    });
    shape
        && (b'1'..=b'8').contains(&bytes[14])
        && matches!(bytes[19].to_ascii_lowercase(), b'8' | b'9' | b'a' | b'b')
}

/// Build the billing header value with the merged segment order and spacing
/// (TS `buildBillingHeaderValue`). `first_user_text` feeds the version suffix; see
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
        .filter(|p| is_valid_anthropic_request_id(p))
    {
        header.push_str(&format!(" cc_prev_req={prev};"));
    }
    if let Some(prompt) = attribution
        .prompt_id
        .filter(|p| is_valid_billing_prompt_id(p))
    {
        header.push_str(&format!(" cc_prompt_id={prompt};"));
    }
    header
}

/// Reset a previously signed billing-header slot (`cch=<5 hex>;`) in a
/// serialized request body back to `cch=00000;` (TS `resetBillingHeaderCCH`,
/// see [`crate::cch::reset_billing_header_cch`]). Only the first-system-block
/// billing header is touched; message history is left alone. Bodies without a
/// billing header are returned unchanged.
pub fn normalize_billing_header_cch(serialized_body: &str) -> String {
    crate::cch::reset_billing_header_cch(serialized_body)
}

/// Remove the request-scoped lineage segments (` cc_prev_req=…;`,
/// ` cc_prompt_id=…;`) from a billing header string (TS
/// `stripBillingLineageFields`), before a body is reused (cache warm-up,
/// relay replay).
pub fn strip_billing_lineage_fields(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    loop {
        let next = [" cc_prev_req=", " cc_prompt_id="]
            .iter()
            .filter_map(|needle| rest.find(needle).map(|at| (at, needle.len())))
            .min();
        let Some((at, needle_len)) = next else {
            out.push_str(rest);
            return out;
        };
        let value_start = at + needle_len;
        // `[^;\r\n]*;` — the segment must end in `;` before any line break.
        let run = rest[value_start..]
            .find([';', '\r', '\n'])
            .filter(|end| rest[value_start + end..].starts_with(';'));
        match run {
            Some(end) => {
                out.push_str(&rest[..at]);
                rest = &rest[value_start + end + 1..];
            }
            None => {
                out.push_str(&rest[..value_start]);
                rest = &rest[value_start..];
            }
        }
    }
}

/// Strip lineage from every billing-header text block of `body.system` (TS
/// `stripBillingLineageFromBody`). Returns how many blocks changed.
pub fn strip_billing_lineage_from_body(body: &mut serde_json::Value) -> usize {
    let Some(system) = body.get_mut("system").and_then(|s| s.as_array_mut()) else {
        return 0;
    };
    let mut stripped = 0;
    for block in system {
        let Some(text) = block.get("text").and_then(|t| t.as_str()) else {
            continue;
        };
        if !text.starts_with("x-anthropic-billing-header:") {
            continue;
        }
        let clean = strip_billing_lineage_fields(text);
        if clean == text {
            continue;
        }
        if let Some(object) = block.as_object_mut() {
            object.insert("text".into(), serde_json::Value::String(clean));
            stripped += 1;
        }
    }
    stripped
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

    /// Bun vector from merged-TS `buildBillingHeaderValue`: fork segments
    /// (`cc_workload`, `cc_is_subagent`) precede upstream lineage.
    #[test]
    fn matches_merged_segment_order_and_spacing() {
        let text = extract_first_user_message_text(&user("audit header capture"));
        let header = build_billing_header_value(
            "2.1.280",
            "cli",
            &text,
            &BillingAttribution {
                workload: Some("cron"),
                is_subagent: true,
                previous_request_id: Some("req_011CabcdEFGH"),
                prompt_id: Some("6ba7b810-9dad-11d1-80b4-00c04fd430c8"),
            },
        );
        assert_eq!(
            header,
            "x-anthropic-billing-header: cc_version=2.1.280.472; cc_entrypoint=cli; cch=00000; cc_workload=cron; cc_is_subagent=true; cc_prev_req=req_011CabcdEFGH; cc_prompt_id=6ba7b810-9dad-11d1-80b4-00c04fd430c8;"
        );
        let bare =
            build_billing_header_value("2.1.280", "cli", &text, &BillingAttribution::default());
        assert_eq!(header.find(CCH_LITERAL), bare.find(CCH_LITERAL));
        // Stripping lineage leaves the fork segments (Bun vector).
        assert_eq!(
            strip_billing_lineage_fields(&header),
            "x-anthropic-billing-header: cc_version=2.1.280.472; cc_entrypoint=cli; cch=00000; cc_workload=cron; cc_is_subagent=true;"
        );
    }

    /// Upstream validation: request ids need 8–128 chars after `req_`; the
    /// prompt id needs UUID version 1–8 and variant 8–b; neither is trimmed.
    #[test]
    fn lineage_ids_follow_upstream_patterns() {
        assert!(is_valid_anthropic_request_id("req_011CabcdEFGH"));
        assert!(is_valid_anthropic_request_id(&format!(
            "req_{}",
            "a".repeat(128)
        )));
        assert!(!is_valid_anthropic_request_id(&format!(
            "req_{}",
            "a".repeat(129)
        )));
        assert!(!is_valid_anthropic_request_id("req_abc123"));
        assert!(!is_valid_anthropic_request_id(" req_011CabcdEFGH"));
        assert!(is_valid_billing_prompt_id(
            "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
        ));
        assert!(is_valid_billing_prompt_id(
            "6BA7B810-9DAD-41D1-B0B4-00C04FD430C8"
        ));
        assert!(!is_valid_billing_prompt_id(
            "6ba7b810-9dad-01d1-80b4-00c04fd430c8"
        ));
        assert!(!is_valid_billing_prompt_id(
            "6ba7b810-9dad-91d1-80b4-00c04fd430c8"
        ));
        assert!(!is_valid_billing_prompt_id(
            "6BA7B810-9DAD-41D1-C0B4-00C04FD430C8"
        ));
        // Bun vectors: invalid lineage is dropped entirely.
        for (prev, prompt) in [
            ("req_abc123", "6ba7b810-9dad-01d1-80b4-00c04fd430c8"),
            (" req_011CabcdEFGH", "6BA7B810-9DAD-41D1-C0B4-00C04FD430C8"),
        ] {
            assert_eq!(
                build_billing_header_value(
                    "2.1.280",
                    "cli",
                    "",
                    &BillingAttribution {
                        previous_request_id: Some(prev),
                        prompt_id: Some(prompt),
                        ..Default::default()
                    },
                ),
                "x-anthropic-billing-header: cc_version=2.1.280.d7b; cc_entrypoint=cli; cch=00000;"
            );
        }
    }

    /// Bun vectors from merged-TS `extractFirstUserMessageText`.
    #[test]
    fn first_user_text_prefers_command_block_then_last_text_block() {
        let command = vec![serde_json::json!({"role":"user","content":[
            {"type":"text","text":"<system-reminder>x</system-reminder>"},
            {"type":"text","text":"pre <command-name>/foo</command-name> args"},
            {"type":"text","text":"last"}
        ]})];
        assert_eq!(
            extract_first_user_message_text(&command),
            "<command-name>/foo</command-name> args"
        );
        let reminders = vec![serde_json::json!({"role":"user","content":[
            {"type":"text","text":"first reminder"},
            {"type":"image"},
            {"type":"text","text":"visible prompt"},
            {"type":"text","text":""}
        ]})];
        assert_eq!(
            extract_first_user_message_text(&reminders),
            "visible prompt"
        );
    }

    #[test]
    fn tracker_pins_first_text_per_session_with_lru_bound() {
        let mut tracker = FirstUserTextTracker::new(2);
        assert_eq!(tracker.resolve("a", &user("first a"), true), "first a");
        assert_eq!(tracker.resolve("a", &user("later a"), true), "first a");
        assert_eq!(tracker.resolve("b", &user("unpinned"), false), "unpinned");
        assert!(!tracker.has("b"));
        tracker.resolve("b", &user("b"), true);
        // "a" is now the least recently used entry and is evicted.
        tracker.resolve("c", &user("c"), true);
        assert!(!tracker.has("a"));
        assert!(tracker.has("b") && tracker.has("c"));
        tracker.clear();
        assert!(!tracker.has("c"));
    }

    #[test]
    fn strips_lineage_only_from_billing_header_blocks() {
        let header = "x-anthropic-billing-header: cc_version=2.1.280.472; cc_entrypoint=cli; cch=00000; cc_prev_req=req_011CabcdEFGH; cc_prompt_id=6ba7b810-9dad-11d1-80b4-00c04fd430c8;";
        let mut body = serde_json::json!({"system":[
            {"type":"text","text":header},
            {"type":"text","text":"x cc_prev_req=req_011CabcdEFGH;"}
        ]});
        assert_eq!(strip_billing_lineage_from_body(&mut body), 1);
        assert_eq!(
            body["system"][0]["text"],
            "x-anthropic-billing-header: cc_version=2.1.280.472; cc_entrypoint=cli; cch=00000;"
        );
        assert_eq!(body["system"][1]["text"], "x cc_prev_req=req_011CabcdEFGH;");
        assert_eq!(strip_billing_lineage_from_body(&mut body), 0);
        // An unterminated segment is not a match.
        assert_eq!(
            strip_billing_lineage_fields("a cc_prev_req=x\n; b"),
            "a cc_prev_req=x\n; b"
        );
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

    /// Fixed vectors for the 2.1.280 fingerprint, cross-checked against the
    /// fork's `computeVersionSuffix`.
    #[test]
    fn full_header_value_for_2_1_280() {
        assert_eq!(compute_version_suffix("2.1.280", ""), "d7b");
        assert_eq!(compute_version_suffix("2.1.280", "ping"), "d7b");
        assert_eq!(
            compute_version_suffix("2.1.280", "audit header capture"),
            "472"
        );
        let text = extract_first_user_message_text(&user("reply with the single word pong"));
        assert_eq!(
            build_billing_header_value("2.1.280", "cli", &text, &BillingAttribution::default()),
            "x-anthropic-billing-header: cc_version=2.1.280.3a6; cc_entrypoint=cli; cch=00000;"
        );
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
