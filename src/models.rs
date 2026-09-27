//! First-party Claude model knowledge that shapes a request: canonical model
//! ids, the adaptive-thinking / effort capability split, the
//! `CLAUDE_CODE_DISABLE_ADAPTIVE_THINKING` escape hatch, the refusal fallback
//! route map, 1M-context and fast-mode support, and local pricing.
//!
//! Everything here is a pure function of the model id. It mirrors Claude Code
//! 2.1.260's baked capability catalog (`firstPartyNameToCanonical`, `FH8`,
//! `N5$`, `E5$`), the 2.1.280 additions (Opus 5.5 and the
//! `rejects_disabled_thinking` capability), and 2.1.268's refusal route maps
//! (`Swo`/`ywo`/`_wo`), as ported by the anthropic-auth fork.

/// Claude Fable 5 model id.
pub const CLAUDE_FABLE_5_MODEL_ID: &str = "claude-fable-5";
/// Claude Mythos 5 model id (restricted access).
pub const CLAUDE_MYTHOS_5_MODEL_ID: &str = "claude-mythos-5";
/// Claude Sonnet 5 model id.
pub const CLAUDE_SONNET_5_MODEL_ID: &str = "claude-sonnet-5";
/// Claude Opus 5 model id.
pub const CLAUDE_OPUS_5_MODEL_ID: &str = "claude-opus-5";
/// Claude Opus 5.5 model id — a separate catalog entry in Claude Code
/// 2.1.280, not a snapshot of Opus 5.
pub const CLAUDE_OPUS_5_5_MODEL_ID: &str = "claude-opus-5-5";
/// Opus 5.5 release date.
pub const CLAUDE_OPUS_5_5_RELEASE_DATE: &str = "2026-09-18";
/// Opus 5.5 context window (native 1M).
pub const CLAUDE_OPUS_5_5_CONTEXT_WINDOW: u64 = 1_000_000;
/// Opus 5.5 maximum output tokens.
pub const CLAUDE_OPUS_5_5_MAX_OUTPUT_TOKENS: u64 = 128_000;
/// Claude Opus 4.8 model id — the refusal catch-all floor.
pub const CLAUDE_OPUS_4_8_MODEL_ID: &str = "claude-opus-4-8";
/// Haiku 4.5 model id.
pub const CLAUDE_HAIKU_4_5_MODEL_ID: &str = "claude-haiku-4-5";

/// The safe floor a terminal refusal downgrades to when no category route
/// applies.
pub const CLAUDE_REFUSAL_CATCH_ALL_MODEL: &str = CLAUDE_OPUS_4_8_MODEL_ID;

/// Families that only accept the legacy `{type:"enabled",budget_tokens}`
/// thinking shape, keyed on canonical id.
const NON_ADAPTIVE_THINKING_MODEL_IDS: [&str; 6] = [
    "claude-opus-4-0",
    "claude-opus-4-1",
    "claude-opus-4-5",
    "claude-sonnet-4-0",
    "claude-sonnet-4-5",
    "claude-haiku-4-5",
];

/// Adaptive models that accept `max` effort but not `xhigh` (Claude Code's
/// `E5$` is strictly narrower than `FH8`/`N5$`).
const NON_XHIGH_ADAPTIVE_MODEL_IDS: [&str; 2] = ["claude-opus-4-6", "claude-sonnet-4-6"];

/// The only models on which the adaptive shape may be forced back to a manual
/// budget: they still accept the deprecated shape, whereas Opus 4.7+ hard-400s.
const FORCIBLE_MANUAL_THINKING_MODEL_IDS: [&str; 2] = ["claude-opus-4-6", "claude-sonnet-4-6"];

/// Family matchers, in Claude Code's `firstPartyNameToCanonical` order. A
/// needle is a substring test against the normalized id; the bare `-4`
/// families additionally require that no single-digit point release follows.
const CANONICAL_FAMILY_MATCHERS: [(&str, bool, &str); 16] = [
    ("claude-opus-4-8", false, "claude-opus-4-8"),
    ("claude-opus-4-7", false, "claude-opus-4-7"),
    ("claude-opus-4-6", false, "claude-opus-4-6"),
    ("claude-opus-4-5", false, "claude-opus-4-5"),
    ("claude-opus-4-1", false, "claude-opus-4-1"),
    ("claude-opus-4", true, "claude-opus-4-0"),
    ("claude-sonnet-4-6", false, "claude-sonnet-4-6"),
    ("claude-sonnet-4-5", false, "claude-sonnet-4-5"),
    ("claude-sonnet-4", true, "claude-sonnet-4-0"),
    ("claude-haiku-4-5", false, "claude-haiku-4-5"),
    ("claude-3-7-sonnet", false, "claude-3-7-sonnet"),
    ("claude-3-5-sonnet", false, "claude-3-5-sonnet"),
    ("claude-3-5-haiku", false, "claude-3-5-haiku"),
    ("claude-3-opus", false, "claude-3-opus"),
    ("claude-3-sonnet", false, "claude-3-sonnet"),
    ("claude-3-haiku", false, "claude-3-haiku"),
];

/// Model families that accept the `context-1m-2025-08-07` beta. Prefixes, so a
/// dated release id matches its family.
const CONTEXT_1M_MODEL_PREFIXES: [&str; 9] = [
    "claude-opus-5",
    "claude-opus-4-8",
    "claude-opus-4-7",
    "claude-opus-4-6",
    "claude-sonnet-5",
    "claude-sonnet-4-6",
    "claude-sonnet-4-5",
    "claude-fable-5",
    "claude-mythos-5",
];

/// Strip every `[1m]` marker (case-insensitive) from an id.
fn strip_context_1m_marker(id: &str) -> String {
    let lower = id.to_ascii_lowercase();
    let mut out = String::with_capacity(id.len());
    let mut rest = lower.as_str();
    while let Some(pos) = rest.find("[1m]") {
        out.push_str(&rest[..pos]);
        rest = &rest[pos + 4..];
    }
    out.push_str(rest);
    out
}

/// Mirrors `/claude-opus-4(?!-\d(?!\d))/`: the needle matches unless it is
/// immediately followed by `-<digit>` where that digit is *not* followed by
/// another digit (i.e. a single-digit point release such as `-4-1`).
fn needle_matches(haystack: &str, needle: &str, exclude_point_release: bool) -> bool {
    let bytes = haystack.as_bytes();
    let mut from = 0;
    while let Some(rel) = haystack[from..].find(needle) {
        let end = from + rel + needle.len();
        if !exclude_point_release {
            return true;
        }
        let after = bytes.get(end).copied();
        let after1 = bytes.get(end + 1).copied();
        let after2 = bytes.get(end + 2).copied();
        let single_digit_point = after == Some(b'-')
            && after1.is_some_and(|b| b.is_ascii_digit())
            && !after2.is_some_and(|b| b.is_ascii_digit());
        if !single_digit_point {
            return true;
        }
        from = end;
    }
    false
}

/// Strip a trailing `-YYYYMMDD` or `@YYYYMMDD` snapshot suffix.
fn strip_snapshot_suffix(id: &str) -> &str {
    let bytes = id.as_bytes();
    if bytes.len() > 9 {
        let tail = &bytes[bytes.len() - 8..];
        let sep = bytes[bytes.len() - 9];
        if (sep == b'-' || sep == b'@') && tail.iter().all(u8::is_ascii_digit) {
            return &id[..id.len() - 9];
        }
    }
    id
}

/// Canonical model id: lower-cased, `[1m]` marker removed, family matchers
/// applied in Claude Code's order, and otherwise a trailing dated snapshot
/// suffix stripped. Capability lookups key on this.
pub fn canonical_claude_model_id(model: &str) -> String {
    let normalized = strip_context_1m_marker(model.trim());
    for (needle, exclude_point, canonical) in CANONICAL_FAMILY_MATCHERS {
        if needle_matches(&normalized, needle, exclude_point) {
            return canonical.to_owned();
        }
    }
    strip_snapshot_suffix(&normalized).to_owned()
}

fn is_first_party_claude_id(canonical: &str) -> bool {
    canonical.starts_with("claude-") || canonical.starts_with("anthropic")
}

/// Whether the model takes `thinking:{type:"adaptive"}` + `output_config.effort`
/// rather than a manual token budget. Adaptive is the default for first-party
/// models; the deny list is the older families plus every Claude 3.x.
///
/// `claude-mythos-5` is adaptive even though its baked catalog entry ships
/// `capabilities: []`: Claude Code hardcodes it into its adaptive predicates.
pub fn model_supports_adaptive_thinking(model: &str) -> bool {
    let canonical = canonical_claude_model_id(model);
    if canonical.starts_with("claude-3-") {
        return false;
    }
    if NON_ADAPTIVE_THINKING_MODEL_IDS.contains(&canonical.as_str()) {
        return false;
    }
    is_first_party_claude_id(&canonical)
}

/// `output_config.effort: "max"` support: identical to the adaptive split.
pub fn model_supports_max_effort(model: &str) -> bool {
    model_supports_adaptive_thinking(model)
}

/// `output_config.effort: "xhigh"` support: adaptive minus Opus 4.6 and
/// Sonnet 4.6.
pub fn model_supports_xhigh_effort(model: &str) -> bool {
    let canonical = canonical_claude_model_id(model);
    if !model_supports_adaptive_thinking(&canonical) {
        return false;
    }
    !NON_XHIGH_ADAPTIVE_MODEL_IDS.contains(&canonical.as_str())
}

/// Downgrade an effort level the model cannot serve (`max`/`xhigh` → `high`),
/// exactly as Claude Code does before sending.
pub fn clamp_effort_for_model<'a>(effort: &'a str, model: &str) -> &'a str {
    if effort == "max" && !model_supports_max_effort(model) {
        return "high";
    }
    if effort == "xhigh" && !model_supports_xhigh_effort(model) {
        return "high";
    }
    effort
}

/// Whether `CLAUDE_CODE_DISABLE_ADAPTIVE_THINKING` may force this model back
/// to a manual budget (Opus 4.6 and Sonnet 4.6 only).
pub fn model_allows_forced_manual_thinking(model: &str) -> bool {
    FORCIBLE_MANUAL_THINKING_MODEL_IDS.contains(&canonical_claude_model_id(model).as_str())
}

/// Environment variable that opts adaptive-capable 4.6 models back into a
/// manual thinking budget.
pub const DISABLE_ADAPTIVE_THINKING_ENV: &str = "CLAUDE_CODE_DISABLE_ADAPTIVE_THINKING";

/// Whether an environment flag value spells "on" (`1`, `true`, `yes`, `on`;
/// case-insensitive, trimmed).
pub fn env_flag_is_truthy(value: Option<&str>) -> bool {
    matches!(
        value.map(|v| v.trim().to_ascii_lowercase()).as_deref(),
        Some("1" | "true" | "yes" | "on")
    )
}

/// The wire shape a model's `thinking` field takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThinkingShape {
    /// `{type:"adaptive"}` plus `output_config.effort`.
    Adaptive,
    /// `{type:"enabled",budget_tokens:N}`.
    Budget,
}

/// Resolve the thinking shape for `model`, honoring the escape hatch value
/// (`disable_adaptive_flag` is the raw `CLAUDE_CODE_DISABLE_ADAPTIVE_THINKING`
/// value). The hatch downgrades only the models that still accept a manual
/// budget; elsewhere it is ignored so it cannot produce a 400.
pub fn resolve_thinking_shape(model: &str, disable_adaptive_flag: Option<&str>) -> ThinkingShape {
    if !model_supports_adaptive_thinking(model) {
        return ThinkingShape::Budget;
    }
    if env_flag_is_truthy(disable_adaptive_flag) && model_allows_forced_manual_thinking(model) {
        return ThinkingShape::Budget;
    }
    ThinkingShape::Adaptive
}

/// [`resolve_thinking_shape`] reading the escape hatch from the process
/// environment.
pub fn resolve_thinking_shape_from_env(model: &str) -> ThinkingShape {
    let flag = std::env::var(DISABLE_ADAPTIVE_THINKING_ENV).ok();
    resolve_thinking_shape(model, flag.as_deref())
}

/// Upstream `normalizeAnthropicModelId`: strip one trailing `[1m]` context
/// qualifier (exact, case-sensitive) before any family predicate.
pub fn normalize_anthropic_model_id(model: &str) -> &str {
    model.strip_suffix("[1m]").unwrap_or(model)
}

fn family_matches(model: &str, family: &str) -> bool {
    let model = normalize_anthropic_model_id(model);
    model == family
        || model
            .strip_prefix(family)
            .is_some_and(|rest| rest.starts_with('-'))
}

/// Whether the id is Claude Fable 5 or Mythos 5 (any point release/snapshot).
pub fn is_claude_fable_or_mythos_5_model(model: &str) -> bool {
    family_matches(model, CLAUDE_FABLE_5_MODEL_ID)
        || family_matches(model, CLAUDE_MYTHOS_5_MODEL_ID)
}

/// Whether the id is the 5.1 point release of Fable or Mythos (`-5-1` or a
/// `-5-1-<snapshot>`, trimmed and case-insensitive), which sits on a cheaper
/// cache-read tier.
pub fn is_claude_fable_or_mythos_5_point_one_model(model: &str) -> bool {
    let canonical = model.trim().to_ascii_lowercase();
    ["claude-fable-5-1", "claude-mythos-5-1"]
        .iter()
        .any(|id| family_matches(&canonical, id))
}

/// Whether the id is Claude Sonnet 5.
pub fn is_claude_sonnet_5_model(model: &str) -> bool {
    family_matches(model, CLAUDE_SONNET_5_MODEL_ID)
}

/// Whether the id is Claude Opus 5 (or an Opus 5 snapshot) but **not** the
/// 5.5 point release — upstream `isClaudeOpus5Model` semantics, adopted by
/// the merge. Use [`is_claude_opus_5_family_model`] for behavior shared by
/// 5.0 and 5.5 (adaptive-thinking injection, effort variants).
pub fn is_claude_opus_5_model(model: &str) -> bool {
    !is_claude_opus_5_5_model(model) && family_matches(model, CLAUDE_OPUS_5_MODEL_ID)
}

/// Whether the id is Claude Opus 5.5: the exact id, the `[1m]`-suffixed form,
/// or a dated snapshot — never Opus 5 or an Opus 5 snapshot. Like upstream,
/// matching is exact (no trimming or case folding).
pub fn is_claude_opus_5_5_model(model: &str) -> bool {
    family_matches(model, CLAUDE_OPUS_5_5_MODEL_ID)
}

/// Whether the id is Opus 5 or Opus 5.5 (upstream `isClaudeOpus5FamilyModel`).
pub fn is_claude_opus_5_family_model(model: &str) -> bool {
    is_claude_opus_5_model(model) || is_claude_opus_5_5_model(model)
}

/// Models that reject `thinking: {type:"disabled"}` with HTTP 400 (use
/// `thinking.type.adaptive` and `output_config.effort` instead). Mirrors the
/// `rejects_disabled_thinking` capability in Claude Code 2.1.280's baked
/// catalog — Fable 5, Fable 5.1, Mythos 5.1, Opus 5.5 — plus Mythos 5, which
/// ships an empty capability array but is hardcoded adaptive and rejects a
/// disable exactly like Fable.
///
/// Opus 5 and Sonnet 5 are deliberately absent: both accept an explicit
/// disable (Opus 5 only caps `effort` at `high` while disabled).
pub fn model_rejects_disabled_thinking(model: &str) -> bool {
    is_claude_fable_or_mythos_5_model(model) || is_claude_opus_5_5_model(model)
}

/// Whether the 5-series family injects `{type:"adaptive",display:"summarized"}`
/// by default (thinking is on by default there and only `display` is opted
/// back in). Adaptive non-5 models must NOT be force-injected: omitting
/// `thinking` means thinking is off, so injecting would silently bill for
/// reasoning nobody requested.
pub fn model_injects_summarized_adaptive_thinking(model: &str) -> bool {
    is_claude_fable_or_mythos_5_model(model)
        || is_claude_sonnet_5_model(model)
        || is_claude_opus_5_family_model(model)
}

/// Models that reject a forced `tool_choice` (`{type:"any"}` or
/// `{type:"tool",name}`), including a host's "required" structured-output
/// tool: Opus 5.5 (upstream anthropic-auth `eae6591`) and the Fable/Mythos 5.1
/// point releases. `auto`/`none` stay valid.
pub fn model_rejects_forced_tool_choice(model: &str) -> bool {
    is_claude_opus_5_5_model(model) || is_claude_fable_or_mythos_5_point_one_model(model)
}

/// Whether `speed:"fast"` (and the fast-mode beta) is accepted: Opus 4.8,
/// Opus 5 and Opus 5.5 (prefix match, so snapshots and `[1m]` forms count).
///
/// Opus 4.7 rejects `speed:"fast"` and Opus 4.6 silently runs at standard
/// speed, so neither is eligible (upstream anthropic-auth `eae6591`).
pub fn is_fast_mode_supported_model(model: &str) -> bool {
    ["claude-opus-4-8", "claude-opus-5"]
        .iter()
        .any(|prefix| model.starts_with(prefix))
}

/// Whether `model` should carry the `context-1m-2025-08-07` beta: an explicit
/// `[1m]` marker, or membership in a 1M-capable family.
pub fn model_supports_context_1m(model: &str) -> bool {
    let trimmed = model.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("[1m]") {
        return true;
    }
    CONTEXT_1M_MODEL_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
}

/// Per-million-token USD pricing for the Fable/Mythos families.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FableMythosPricing {
    /// Input tokens.
    pub input: f64,
    /// Output tokens.
    pub output: f64,
    /// Cache-read tokens.
    pub cache_read: f64,
    /// Five-minute cache-write tokens.
    pub cache_write_5m: f64,
    /// One-hour cache-write tokens.
    pub cache_write_1h: f64,
}

/// Fable/Mythos 5.0 (`tier_10_50`, cache read $1.00).
pub const CLAUDE_FABLE_MYTHOS_5_PRICING: FableMythosPricing = FableMythosPricing {
    input: 10.0,
    output: 50.0,
    cache_read: 1.0,
    cache_write_5m: 12.5,
    cache_write_1h: 20.0,
};

/// Fable/Mythos 5.1 (`tier_10_50_cache_read_0_25`): identical except cache
/// read is $0.25. Pricing 5.1 with the 5.0 table over-reports cache reads 4x.
pub const CLAUDE_FABLE_MYTHOS_5_1_PRICING: FableMythosPricing = FableMythosPricing {
    cache_read: 0.25,
    ..CLAUDE_FABLE_MYTHOS_5_PRICING
};

/// Opus 5.5 (`tier_4_20_cache_read_0_20`): cheaper than Opus 5 (`tier_5_25`)
/// on every axis. Reusing the Opus 5 prefix price overstates tokens by 25% and
/// cache reads by 2.5x.
pub const CLAUDE_OPUS_5_5_PRICING: FableMythosPricing = FableMythosPricing {
    input: 4.0,
    output: 20.0,
    cache_read: 0.2,
    cache_write_5m: 5.0,
    cache_write_1h: 8.0,
};

/// Cache-read-accurate pricing for any Fable/Mythos id.
pub fn resolve_claude_fable_mythos_5_pricing(model: &str) -> FableMythosPricing {
    if is_claude_fable_or_mythos_5_point_one_model(model) {
        CLAUDE_FABLE_MYTHOS_5_1_PRICING
    } else {
        CLAUDE_FABLE_MYTHOS_5_PRICING
    }
}

/// Per-million-token USD cost used for local reporting (`/v1/models` does not
/// expose pricing).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ModelCost {
    /// Input tokens.
    pub input: f64,
    /// Output tokens.
    pub output: f64,
    /// Cache-read tokens.
    pub cache_read: f64,
    /// Cache-write tokens (five-minute TTL).
    pub cache_write: f64,
}

const fn cost(input: f64, output: f64, cache_read: f64, cache_write: f64) -> ModelCost {
    ModelCost {
        input,
        output,
        cache_read,
        cache_write,
    }
}

/// Exact-prefix pricing, matched longest-prefix-first.
const MODEL_PRICING: [(&str, ModelCost); 6] = [
    // Opus 5.5 must win the longest-prefix match or it inherits Opus 5's rates.
    (
        CLAUDE_OPUS_5_5_MODEL_ID,
        cost(
            CLAUDE_OPUS_5_5_PRICING.input,
            CLAUDE_OPUS_5_5_PRICING.output,
            CLAUDE_OPUS_5_5_PRICING.cache_read,
            CLAUDE_OPUS_5_5_PRICING.cache_write_5m,
        ),
    ),
    ("claude-opus-5", cost(5.0, 25.0, 0.5, 6.25)),
    ("claude-sonnet-5", cost(2.0, 10.0, 0.2, 2.5)),
    ("claude-opus-4", cost(5.0, 25.0, 0.5, 6.25)),
    ("claude-sonnet-4", cost(3.0, 15.0, 0.3, 3.75)),
    ("claude-haiku-4", cost(1.0, 5.0, 0.1, 1.25)),
];

/// Family pricing for ids released after the table above was written.
const FAMILY_PRICING: [(&str, ModelCost); 3] = [
    ("opus", cost(5.0, 25.0, 0.5, 6.25)),
    ("sonnet", cost(3.0, 15.0, 0.3, 3.75)),
    ("haiku", cost(1.0, 5.0, 0.1, 1.25)),
];

const FALLBACK_COST: ModelCost = cost(3.0, 15.0, 0.3, 3.75);

/// Resolve the local cost table entry for `model`: Fable/Mythos tiers first,
/// then the longest exact prefix, then the family word, then a Sonnet-class
/// fallback.
pub fn resolve_model_cost(model: &str) -> ModelCost {
    if is_claude_fable_or_mythos_5_model(model) {
        let pricing = resolve_claude_fable_mythos_5_pricing(model);
        return cost(
            pricing.input,
            pricing.output,
            pricing.cache_read,
            pricing.cache_write_5m,
        );
    }
    let mut exact: Vec<&(&str, ModelCost)> = MODEL_PRICING.iter().collect();
    exact.sort_by_key(|entry| std::cmp::Reverse(entry.0.len()));
    if let Some((_, c)) = exact
        .into_iter()
        .find(|(prefix, _)| model.starts_with(prefix))
    {
        return *c;
    }
    FAMILY_PRICING
        .iter()
        .find(|(word, _)| model.contains(word))
        .map(|(_, c)| *c)
        .unwrap_or(FALLBACK_COST)
}

/// Fallback model for a refusal `category` on `model` per Claude Code 2.1.268:
/// default `{bio→opus-5, cyber→opus-4-8}`; Opus 5 `{cyber→opus-4-8}` (no bio
/// route). Returns `None` for an unmapped or absent category.
pub fn refusal_fallback_route(model: &str, category: &str) -> Option<&'static str> {
    let on_opus_5 = canonical_claude_model_id(model) == CLAUDE_OPUS_5_MODEL_ID;
    match category {
        "cyber" => Some(CLAUDE_OPUS_4_8_MODEL_ID),
        "bio" if !on_opus_5 => Some(CLAUDE_OPUS_5_MODEL_ID),
        _ => None,
    }
}

/// The model a terminal `stop_reason: refusal` should re-route to.
///
/// Faithful to Claude Code's category map, plus one deliberate addition: with
/// `catch_all` set, a missing or unmapped category downgrades to Opus 4.8 —
/// the floor a user reaches by hand today. Never routes to the refusing model
/// or to an already-tried model (compared on canonical ids), so a bounded hop
/// count cannot loop.
pub fn resolve_refusal_fallback_model(
    model: &str,
    category: Option<&str>,
    tried_models: &[&str],
    catch_all: bool,
) -> Option<&'static str> {
    let mapped = category.and_then(|c| refusal_fallback_route(model, c));
    let candidate = mapped.or(if catch_all {
        Some(CLAUDE_REFUSAL_CATCH_ALL_MODEL)
    } else {
        None
    })?;
    let candidate_canonical = canonical_claude_model_id(candidate);
    if candidate_canonical == canonical_claude_model_id(model) {
        return None;
    }
    if tried_models
        .iter()
        .any(|tried| canonical_claude_model_id(tried) == candidate_canonical)
    {
        return None;
    }
    Some(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adaptive_models_match_claude_code_catalog() {
        for id in [
            "claude-opus-4-6",
            "claude-opus-4-7",
            "claude-opus-4-8",
            "claude-opus-4-8-20260101",
            "claude-opus-5",
            "claude-sonnet-4-6",
            "claude-sonnet-5",
            "claude-fable-5",
            "claude-mythos-5",
            "claude-haiku-5",
        ] {
            assert!(
                model_supports_adaptive_thinking(id),
                "{id} should be adaptive"
            );
        }
        for id in [
            "claude-opus-4-0",
            "claude-opus-4-1",
            "claude-opus-4-5",
            "claude-opus-4-5-20251101",
            "claude-sonnet-4-0",
            "claude-sonnet-4-5",
            "claude-haiku-4-5",
            "claude-3-5-sonnet",
            "claude-3-opus",
            "gpt-5",
            "",
        ] {
            assert!(
                !model_supports_adaptive_thinking(id),
                "{id} should be budget"
            );
        }
    }

    #[test]
    fn canonical_id_strips_snapshots_and_1m_marker() {
        assert_eq!(
            canonical_claude_model_id("claude-opus-4-8-20260101"),
            "claude-opus-4-8"
        );
        assert_eq!(
            canonical_claude_model_id("claude-opus-4-8@20260101"),
            "claude-opus-4-8"
        );
        assert_eq!(
            canonical_claude_model_id("claude-opus-4-8[1m]"),
            "claude-opus-4-8"
        );
        assert_eq!(
            canonical_claude_model_id("Claude-Opus-4-8[1M]"),
            "claude-opus-4-8"
        );
        assert_eq!(
            canonical_claude_model_id("claude-opus-5-20260901"),
            "claude-opus-5"
        );
        assert_eq!(
            canonical_claude_model_id("claude-fable-5-1-20260601"),
            "claude-fable-5-1"
        );
    }

    #[test]
    fn bare_4_family_excludes_single_digit_point_releases() {
        assert_eq!(
            canonical_claude_model_id("claude-opus-4-20250514"),
            "claude-opus-4-0"
        );
        assert_eq!(
            canonical_claude_model_id("claude-opus-4"),
            "claude-opus-4-0"
        );
        assert_eq!(
            canonical_claude_model_id("claude-opus-4-1"),
            "claude-opus-4-1"
        );
        assert_eq!(
            canonical_claude_model_id("claude-sonnet-4-20250514"),
            "claude-sonnet-4-0"
        );
        assert_eq!(
            canonical_claude_model_id("claude-sonnet-4-5"),
            "claude-sonnet-4-5"
        );
        assert_eq!(
            canonical_claude_model_id("claude-3-5-sonnet-20241022"),
            "claude-3-5-sonnet"
        );
    }

    #[test]
    fn xhigh_is_strictly_narrower_than_adaptive() {
        for id in ["claude-opus-4-6", "claude-sonnet-4-6"] {
            assert!(model_supports_adaptive_thinking(id));
            assert!(model_supports_max_effort(id));
            assert!(!model_supports_xhigh_effort(id));
        }
        for id in [
            "claude-opus-4-7",
            "claude-opus-4-8",
            "claude-opus-5",
            "claude-sonnet-5",
            "claude-fable-5",
            "claude-mythos-5",
            "claude-mythos-5-1",
        ] {
            assert!(model_supports_xhigh_effort(id), "{id}");
        }
        for id in ["claude-opus-4-5", "claude-haiku-4-5", "claude-3-opus"] {
            assert!(!model_supports_xhigh_effort(id), "{id}");
        }
    }

    #[test]
    fn clamp_effort_matches_claude_code_downgrades() {
        assert_eq!(clamp_effort_for_model("xhigh", "claude-opus-4-6"), "high");
        assert_eq!(clamp_effort_for_model("xhigh", "claude-sonnet-4-6"), "high");
        assert_eq!(clamp_effort_for_model("max", "claude-opus-4-6"), "max");
        assert_eq!(clamp_effort_for_model("xhigh", "claude-opus-4-7"), "xhigh");
        assert_eq!(clamp_effort_for_model("max", "claude-opus-5"), "max");
        assert_eq!(clamp_effort_for_model("xhigh", "claude-opus-4-5"), "high");
        assert_eq!(clamp_effort_for_model("max", "claude-opus-4-5"), "high");
        assert_eq!(clamp_effort_for_model("low", "claude-opus-4-6"), "low");
        assert_eq!(clamp_effort_for_model("high", "claude-opus-4-5"), "high");
    }

    #[test]
    fn thinking_shape_escape_hatch_is_limited_to_4_6() {
        assert_eq!(
            resolve_thinking_shape("claude-opus-4-6", None),
            ThinkingShape::Adaptive
        );
        assert_eq!(
            resolve_thinking_shape("claude-opus-4-8", None),
            ThinkingShape::Adaptive
        );
        assert_eq!(
            resolve_thinking_shape("claude-opus-4-5", None),
            ThinkingShape::Budget
        );
        assert_eq!(
            resolve_thinking_shape("claude-opus-4-5", Some("1")),
            ThinkingShape::Budget
        );
        assert_eq!(
            resolve_thinking_shape("claude-opus-4-6", Some("1")),
            ThinkingShape::Budget
        );
        assert_eq!(
            resolve_thinking_shape("claude-sonnet-4-6", Some("1")),
            ThinkingShape::Budget
        );
        assert_eq!(
            resolve_thinking_shape("claude-opus-4-7", Some("1")),
            ThinkingShape::Adaptive
        );
        assert_eq!(
            resolve_thinking_shape("claude-opus-4-8", Some("1")),
            ThinkingShape::Adaptive
        );
        assert_eq!(
            resolve_thinking_shape("claude-opus-5", Some("1")),
            ThinkingShape::Adaptive
        );
        for value in ["1", "true", "yes", "on", "TRUE", " on "] {
            assert_eq!(
                resolve_thinking_shape("claude-opus-4-6", Some(value)),
                ThinkingShape::Budget,
                "{value}"
            );
        }
        for value in ["0", "false", "", "off"] {
            assert_eq!(
                resolve_thinking_shape("claude-opus-4-6", Some(value)),
                ThinkingShape::Adaptive,
                "{value}"
            );
        }
        assert!(model_allows_forced_manual_thinking("claude-opus-4-6"));
        assert!(model_allows_forced_manual_thinking("claude-sonnet-4-6"));
        assert!(!model_allows_forced_manual_thinking("claude-opus-4-7"));
        assert!(!model_allows_forced_manual_thinking("claude-opus-5"));
    }

    #[test]
    fn mythos_5_is_adaptive_despite_empty_catalog_capabilities() {
        assert!(model_supports_adaptive_thinking("claude-mythos-5"));
        assert!(model_supports_max_effort("claude-mythos-5"));
        assert!(model_supports_xhigh_effort("claude-mythos-5"));
        assert_eq!(
            resolve_thinking_shape("claude-mythos-5", None),
            ThinkingShape::Adaptive
        );
        assert!(!model_allows_forced_manual_thinking("claude-mythos-5"));
        assert_eq!(
            resolve_thinking_shape("claude-mythos-5", Some("1")),
            ThinkingShape::Adaptive
        );
        assert!(model_supports_adaptive_thinking("claude-mythos-5-1"));
    }

    #[test]
    fn fable_mythos_5_1_cache_read_tier() {
        for id in [
            "claude-fable-5",
            "claude-mythos-5",
            "claude-fable-5-20260609",
        ] {
            assert_eq!(
                resolve_claude_fable_mythos_5_pricing(id).cache_read,
                1.0,
                "{id}"
            );
        }
        for id in [
            "claude-fable-5-1",
            "claude-mythos-5-1",
            "claude-fable-5-1-20260601",
        ] {
            assert_eq!(
                resolve_claude_fable_mythos_5_pricing(id).cache_read,
                0.25,
                "{id}"
            );
        }
        let five = CLAUDE_FABLE_MYTHOS_5_PRICING;
        let five_one = CLAUDE_FABLE_MYTHOS_5_1_PRICING;
        assert_eq!(five.input, five_one.input);
        assert_eq!(five.output, five_one.output);
        assert_eq!(five.cache_write_5m, five_one.cache_write_5m);
        assert_eq!(five.cache_write_1h, five_one.cache_write_1h);
        assert_eq!(resolve_model_cost("claude-fable-5-1").cache_read, 0.25);
        assert_eq!(resolve_model_cost("claude-fable-5").cache_write, 12.5);
    }

    #[test]
    fn model_cost_prefers_longest_prefix_then_family() {
        assert_eq!(resolve_model_cost("claude-opus-5-20260901").input, 5.0);
        assert_eq!(resolve_model_cost("claude-sonnet-5").input, 2.0);
        assert_eq!(resolve_model_cost("claude-sonnet-4-6").input, 3.0);
        assert_eq!(resolve_model_cost("claude-haiku-9").input, 1.0);
        assert_eq!(resolve_model_cost("claude-unknown"), FALLBACK_COST);
    }

    #[test]
    fn refusal_route_map_matches_claude_code_2_1_268() {
        let none: &[&str] = &[];
        assert_eq!(
            resolve_refusal_fallback_model("claude-fable-5", Some("cyber"), none, true),
            Some("claude-opus-4-8")
        );
        assert_eq!(
            resolve_refusal_fallback_model("claude-fable-5-1", Some("bio"), none, true),
            Some("claude-opus-5")
        );
        assert_eq!(
            resolve_refusal_fallback_model("claude-opus-5", Some("bio"), none, true),
            Some("claude-opus-4-8")
        );
        assert_eq!(
            resolve_refusal_fallback_model("claude-opus-5", Some("cyber"), none, true),
            Some("claude-opus-4-8")
        );
        assert_eq!(
            resolve_refusal_fallback_model("claude-fable-5", None, none, true),
            Some("claude-opus-4-8")
        );
        assert_eq!(
            resolve_refusal_fallback_model("claude-fable-5", None, none, false),
            None
        );
        assert_eq!(
            resolve_refusal_fallback_model("claude-opus-4-8", Some("cyber"), none, true),
            None
        );
        assert_eq!(
            resolve_refusal_fallback_model(
                "claude-fable-5",
                Some("cyber"),
                &["claude-opus-4-8-20260101"],
                true
            ),
            None
        );
        assert_eq!(
            resolve_refusal_fallback_model(
                "claude-opus-5-20260901",
                Some("cyber"),
                &["claude-opus-4-8"],
                true
            ),
            None
        );
        // Unmapped categories (v2.1.272 aup/agentic/control) reach the catch-all.
        assert_eq!(
            resolve_refusal_fallback_model("claude-opus-5", Some("aup"), none, true),
            Some("claude-opus-4-8")
        );
        assert_eq!(refusal_fallback_route("claude-opus-5", "bio"), None);
    }

    #[test]
    fn context_1m_families_and_marker() {
        for id in [
            "claude-opus-5",
            "claude-opus-4-8-20260101",
            "claude-opus-4-6",
            "claude-sonnet-5",
            "claude-sonnet-4-5",
            "claude-fable-5",
            "claude-mythos-5",
            "claude-haiku-4-5[1m]",
        ] {
            assert!(model_supports_context_1m(id), "{id}");
        }
        for id in [
            "claude-haiku-4-5",
            "claude-opus-4-1",
            "claude-3-5-sonnet",
            "",
            "  ",
        ] {
            assert!(!model_supports_context_1m(id), "{id:?}");
        }
    }

    #[test]
    fn family_predicates_and_fast_mode() {
        assert!(is_claude_fable_or_mythos_5_model("claude-mythos-5-1"));
        assert!(!is_claude_fable_or_mythos_5_model("claude-fable-50"));
        assert!(is_claude_sonnet_5_model("claude-sonnet-5-20260101"));
        assert!(is_claude_opus_5_model("claude-opus-5"));
        assert!(model_injects_summarized_adaptive_thinking("claude-opus-5"));
        assert!(!model_injects_summarized_adaptive_thinking(
            "claude-opus-4-8"
        ));
        assert!(is_fast_mode_supported_model("claude-opus-4-8"));
        assert!(!is_fast_mode_supported_model("claude-sonnet-5"));
    }

    /// Upstream `fast.test.ts` (eae6591): Opus 4.6/4.7 are not fast-mode
    /// models; Opus 4.8, 5 and 5.5 (any snapshot or `[1m]` form) are.
    #[test]
    fn fast_mode_eligibility_matches_upstream_table() {
        for (model, expected) in [
            ("claude-opus-4-6", false),
            ("claude-opus-4-7", false),
            ("claude-opus-4-7[1m]", false),
            ("claude-opus-4-8", true),
            ("claude-opus-4-8-20260901", true),
            ("claude-opus-5", true),
            ("claude-opus-5-5", true),
            ("claude-opus-5-5[1m]", true),
            ("claude-sonnet-5", false),
        ] {
            assert_eq!(is_fast_mode_supported_model(model), expected, "{model}");
        }
    }

    #[test]
    fn opus_5_5_specifications_and_pricing() {
        assert_eq!(CLAUDE_OPUS_5_5_MODEL_ID, "claude-opus-5-5");
        assert_eq!(CLAUDE_OPUS_5_5_CONTEXT_WINDOW, 1_000_000);
        assert_eq!(CLAUDE_OPUS_5_5_MAX_OUTPUT_TOKENS, 128_000);
        assert_eq!(
            CLAUDE_OPUS_5_5_PRICING,
            FableMythosPricing {
                input: 4.0,
                output: 20.0,
                cache_read: 0.2,
                cache_write_5m: 5.0,
                cache_write_1h: 8.0,
            }
        );
        // Claude Code 2.1.280 tier_4_20_cache_read_0_20; the Opus 5 prefix
        // must not swallow it.
        assert_eq!(
            resolve_model_cost("claude-opus-5-5"),
            cost(4.0, 20.0, 0.2, 5.0)
        );
        assert_eq!(
            resolve_model_cost("claude-opus-5-5-20260918"),
            cost(4.0, 20.0, 0.2, 5.0)
        );
        assert_eq!(
            resolve_model_cost("claude-opus-5"),
            cost(5.0, 25.0, 0.5, 6.25)
        );
    }

    #[test]
    fn opus_5_5_predicate_matches_id_marker_and_snapshots_only() {
        assert!(is_claude_opus_5_5_model("claude-opus-5-5"));
        assert!(is_claude_opus_5_5_model("claude-opus-5-5[1m]"));
        assert!(is_claude_opus_5_5_model("claude-opus-5-5-20260918"));
        assert!(is_claude_opus_5_5_model("claude-opus-5-5-20260601"));
        assert!(!is_claude_opus_5_5_model("claude-opus-5"));
        assert!(!is_claude_opus_5_5_model("claude-opus-5-20260901"));
        assert!(!is_claude_opus_5_5_model("claude-opus-4-8"));
        assert!(!is_claude_opus_5_5_model("claude-sonnet-5"));
        assert!(!is_claude_opus_5_5_model(""));
        // Merged (upstream) semantics: the Opus 5 predicate excludes 5.5.
        assert!(!is_claude_opus_5_model("claude-opus-5-5"));
        assert!(!is_claude_opus_5_model("claude-opus-5-5-20260918"));
        assert!(is_claude_opus_5_model("claude-opus-5-20260901"));
        assert!(is_claude_opus_5_family_model("claude-opus-5"));
        assert!(is_claude_opus_5_family_model("claude-opus-5-5"));
        assert!(is_claude_opus_5_family_model("claude-opus-5-5-20260918"));
        assert!(!is_claude_opus_5_family_model("claude-opus-4-8"));
    }

    #[test]
    fn opus_5_5_canonicalizes_to_its_own_id() {
        assert_eq!(
            canonical_claude_model_id("claude-opus-5-5"),
            "claude-opus-5-5"
        );
        assert_eq!(
            canonical_claude_model_id("claude-opus-5-5-20260601"),
            "claude-opus-5-5"
        );
        assert_eq!(
            canonical_claude_model_id("claude-opus-5-5[1m]"),
            "claude-opus-5-5"
        );
    }

    #[test]
    fn opus_5_5_is_adaptive_with_every_effort_and_no_forced_budget() {
        assert!(model_supports_adaptive_thinking("claude-opus-5-5"));
        assert!(model_supports_max_effort("claude-opus-5-5"));
        assert!(model_supports_xhigh_effort("claude-opus-5-5"));
        assert_eq!(clamp_effort_for_model("max", "claude-opus-5-5"), "max");
        assert_eq!(clamp_effort_for_model("xhigh", "claude-opus-5-5"), "xhigh");
        assert!(!model_allows_forced_manual_thinking("claude-opus-5-5"));
        assert_eq!(
            resolve_thinking_shape("claude-opus-5-5", None),
            ThinkingShape::Adaptive
        );
        assert_eq!(
            resolve_thinking_shape("claude-opus-5-5", Some("1")),
            ThinkingShape::Adaptive
        );
        assert!(model_injects_summarized_adaptive_thinking(
            "claude-opus-5-5"
        ));
        assert!(model_supports_context_1m("claude-opus-5-5"));
    }

    #[test]
    fn forced_tool_choice_rejection_covers_opus_5_5_and_5_1_point_releases() {
        for model in [
            "claude-opus-5-5",
            "claude-opus-5-5[1m]",
            "claude-opus-5-5-20260918",
            "claude-fable-5-1",
            "claude-mythos-5-1",
        ] {
            assert!(model_rejects_forced_tool_choice(model), "{model}");
        }
        for model in [
            "claude-opus-5",
            "claude-fable-5",
            "claude-opus-4-8",
            "claude-sonnet-5",
        ] {
            assert!(!model_rejects_forced_tool_choice(model), "{model}");
        }
    }

    /// Verified live 2026-09-22 (fork): Opus 5.5 answers a disabled request
    /// with 400 "thinking.type.disabled is not supported for this model".
    #[test]
    fn rejects_disabled_thinking_matches_2_1_280_capability() {
        assert!(model_rejects_disabled_thinking("claude-opus-5-5"));
        assert!(model_rejects_disabled_thinking("claude-opus-5-5[1m]"));
        assert!(!model_rejects_disabled_thinking("claude-opus-5"));
        assert!(!model_rejects_disabled_thinking("claude-sonnet-5"));
        assert!(model_rejects_disabled_thinking("claude-fable-5"));
        assert!(model_rejects_disabled_thinking("claude-mythos-5-1"));
        assert!(!model_rejects_disabled_thinking("claude-opus-4-8"));
    }

    /// Bun vectors from merged-TS `isClaudeOpus5Model`, `isClaudeOpus55Model`,
    /// `isClaudeOpus5FamilyModel`, `isClaudeFableOrMythos5Model`,
    /// `isClaudeFableOrMythos5PointOneModel`.
    #[test]
    fn family_predicates_match_merged_ts_vectors() {
        for (id, expected) in [
            ("claude-opus-5", [true, false, true, false, false]),
            ("claude-opus-5-5", [false, true, true, false, false]),
            ("claude-opus-5-5[1m]", [false, true, true, false, false]),
            ("claude-opus-5[1m]", [true, false, true, false, false]),
            ("claude-opus-5-20260901", [true, false, true, false, false]),
            (
                "claude-opus-5-5-20260918",
                [false, true, true, false, false],
            ),
            ("Claude-Opus-5-5", [false, false, false, false, false]),
            ("claude-opus-5-50", [true, false, true, false, false]),
            (" claude-opus-5-5", [false, false, false, false, false]),
            ("claude-opus-5-5[1M]", [true, false, true, false, false]),
            ("claude-fable-5-1[1m]", [false, false, false, true, true]),
        ] {
            let actual = [
                is_claude_opus_5_model(id),
                is_claude_opus_5_5_model(id),
                is_claude_opus_5_family_model(id),
                is_claude_fable_or_mythos_5_model(id),
                is_claude_fable_or_mythos_5_point_one_model(id),
            ];
            assert_eq!(actual, expected, "{id:?}");
        }
        assert_eq!(
            normalize_anthropic_model_id("claude-opus-5[1m]"),
            "claude-opus-5"
        );
        assert_eq!(
            normalize_anthropic_model_id("claude-opus-5[1M]"),
            "claude-opus-5[1M]"
        );
        // Shared 5-series behavior still covers 5.5 through the family.
        assert!(model_injects_summarized_adaptive_thinking(
            "claude-opus-5-5"
        ));
        assert!(model_injects_summarized_adaptive_thinking(
            "claude-opus-5[1m]"
        ));
    }
}
