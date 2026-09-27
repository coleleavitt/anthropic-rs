//! Request shaping rules that decide bytes on the wire: the thinking field
//! shape (adaptive vs. manual budget), the effort enum, the prompt-cache
//! breakpoint on the final user turn, and the reserved-tool-name alias.

use serde_json::{Value, json};

use crate::models::{
    ThinkingShape,
    clamp_effort_for_model,
    is_claude_opus_5_model,
    model_injects_summarized_adaptive_thinking,
    model_rejects_disabled_thinking,
    model_rejects_forced_tool_choice,
    resolve_thinking_shape,
};

/// A caller's reasoning level (Pi/host vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReasoningLevel {
    /// Minimal — not in Anthropic's effort enum; maps to `low`.
    Minimal,
    /// Low.
    Low,
    /// Medium.
    Medium,
    /// High.
    High,
    /// Extra high.
    Xhigh,
    /// Max.
    Max,
}

impl ReasoningLevel {
    /// Parse a host reasoning level string.
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value.trim().to_ascii_lowercase().as_str() {
            "minimal" => Self::Minimal,
            "low" => Self::Low,
            "medium" => Self::Medium,
            "high" => Self::High,
            "xhigh" => Self::Xhigh,
            "max" => Self::Max,
            _ => return None,
        })
    }

    /// The Anthropic `output_config.effort` value before model clamping.
    /// `minimal` is not in the enum (`low`/`medium`/`high`/`xhigh`/`max`) and
    /// would 400 if passed through, so it maps to `low`.
    pub fn effort(self) -> &'static str {
        match self {
            Self::Minimal | Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Xhigh => "xhigh",
            Self::Max => "max",
        }
    }

    /// Default manual thinking budget for legacy (non-adaptive) models.
    pub fn default_budget_tokens(self) -> u32 {
        match self {
            Self::Minimal => 1_024,
            Self::Low => 4_096,
            Self::Medium => 10_240,
            Self::High => 20_480,
            Self::Xhigh => 32_000,
            Self::Max => 10_240,
        }
    }
}

/// The resolved `thinking` / `output_config` fields for a request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ThinkingPlan {
    /// The `thinking` field to set, if any.
    pub thinking: Option<Value>,
    /// The `output_config.effort` value to set, if any.
    pub effort: Option<&'static str>,
}

/// Inputs for [`resolve_thinking_plan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThinkingRequest<'a> {
    /// Target model id.
    pub model: &'a str,
    /// The caller's explicit reasoning level, if any.
    pub reasoning: Option<ReasoningLevel>,
    /// The request's `max_tokens`; manual budgets are clamped below it.
    pub max_tokens: u32,
    /// A caller-supplied manual budget override for `reasoning`.
    pub requested_budget_tokens: Option<u32>,
    /// Raw `CLAUDE_CODE_DISABLE_ADAPTIVE_THINKING` value.
    pub disable_adaptive_flag: Option<&'a str>,
}

/// Resolve the thinking shape exactly as Claude Code 2.1.260 / the fork's
/// `buildAnthropicRequest` does:
///
/// - the 5-series (Fable/Mythos/Sonnet/Opus 5) always gets
///   `{type:"adaptive",display:"summarized"}` — thinking is on by default
///   there and this only opts `display` back in;
/// - adaptive non-5 models (Opus 4.6/4.7/4.8, Sonnet 4.6) get an adaptive
///   field only when `reasoning` is set — omitting `thinking` means OFF, so
///   injecting would silently bill for reasoning nobody asked for;
/// - adaptive models pair reasoning with `output_config.effort` (clamped to
///   what the model accepts) and never `budget_tokens`;
/// - legacy families get `{type:"enabled",budget_tokens:N}` with `N` clamped
///   to `max_tokens - 1` (Anthropic requires `budget_tokens < max_tokens`).
pub fn resolve_thinking_plan(request: ThinkingRequest<'_>) -> ThinkingPlan {
    let mut plan = ThinkingPlan::default();
    let injects = model_injects_summarized_adaptive_thinking(request.model);
    if injects {
        plan.thinking = Some(json!({"type": "adaptive", "display": "summarized"}));
    }
    let Some(reasoning) = request.reasoning else {
        return plan;
    };
    match resolve_thinking_shape(request.model, request.disable_adaptive_flag) {
        ThinkingShape::Adaptive => {
            if !injects {
                plan.thinking = Some(json!({"type": "adaptive", "display": "summarized"}));
            }
            plan.effort = Some(clamp_effort_for_model(reasoning.effort(), request.model));
        }
        ThinkingShape::Budget => {
            let requested = request
                .requested_budget_tokens
                .unwrap_or_else(|| reasoning.default_budget_tokens());
            let budget = requested.min(request.max_tokens.saturating_sub(1));
            plan.thinking = Some(json!({"type": "enabled", "budget_tokens": budget}));
        }
    }
    plan
}

/// Apply a [`ThinkingPlan`] to a JSON request body (`thinking` and
/// `output_config.effort`).
pub fn apply_thinking_plan(body: &mut Value, plan: &ThinkingPlan) {
    let Some(object) = body.as_object_mut() else {
        return;
    };
    if let Some(thinking) = &plan.thinking {
        object.insert("thinking".into(), thinking.clone());
    }
    if let Some(effort) = plan.effort {
        let config = object.entry("output_config").or_insert_with(|| json!({}));
        if let Some(config) = config.as_object_mut() {
            config.insert("effort".into(), Value::String(effort.to_owned()));
        }
    }
}

/// What [`enforce_model_request_constraints`] changed in a body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ModelConstraintFixups {
    /// A forced `tool_choice` (`any`/`tool`) was removed; `tools` are kept.
    pub removed_forced_tool_choice: bool,
    /// A `thinking` shape the model rejects was rewritten to
    /// `{type:"adaptive",display:"summarized"}`.
    pub rewrote_thinking: bool,
    /// `output_config.effort` was lowered to `high` to pair with a disabled
    /// thinking field on Opus 5.
    pub capped_effort: bool,
}

/// Rewrite the request fields a model is known to reject with HTTP 400,
/// leaving everything else untouched:
///
/// - Opus 5.5 and Fable/Mythos 5.1 reject a forced `tool_choice`
///   (`{type:"any"}`, `{type:"tool"}`) — it is removed, the tools stay
///   declared, and the model may still call them (upstream `eae6591`);
/// - models with `rejects_disabled_thinking` (Opus 5.5, Fable/Mythos) reject
///   `thinking:{type:"disabled"}` and a manual `budget_tokens` shape — both
///   become adaptive summarized (Claude Code 2.1.280 never sends a disable to
///   Opus 5.5);
/// - Opus 5 accepts a disable only at effort `high` or below, so a disabled
///   thinking field caps `output_config.effort` `xhigh`/`max` to `high` and is
///   canonicalized to a bare `{type:"disabled"}`.
///
/// Non-object bodies and bodies without a string `model` are left alone.
pub fn enforce_model_request_constraints(body: &mut Value) -> ModelConstraintFixups {
    let mut fixups = ModelConstraintFixups::default();
    let Some(object) = body.as_object_mut() else {
        return fixups;
    };
    let Some(model) = object
        .get("model")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        return fixups;
    };
    if model_rejects_forced_tool_choice(&model) {
        let forced = object
            .get("tool_choice")
            .and_then(|c| c.get("type"))
            .and_then(Value::as_str)
            .is_some_and(|t| t == "any" || t == "tool");
        if forced {
            object.remove("tool_choice");
            fixups.removed_forced_tool_choice = true;
        }
    }
    let thinking_type = object
        .get("thinking")
        .and_then(|t| t.get("type"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    if model_rejects_disabled_thinking(&model) {
        if matches!(thinking_type.as_deref(), Some("disabled" | "enabled")) {
            object.insert(
                "thinking".into(),
                json!({"type": "adaptive", "display": "summarized"}),
            );
            fixups.rewrote_thinking = true;
        }
    } else if is_claude_opus_5_model(&model) && thinking_type.as_deref() == Some("disabled") {
        object.insert("thinking".into(), json!({"type": "disabled"}));
        let config = object
            .get_mut("output_config")
            .and_then(Value::as_object_mut)
            .filter(|c| {
                matches!(
                    c.get("effort").and_then(Value::as_str),
                    Some("xhigh" | "max")
                )
            });
        if let Some(config) = config {
            config.insert("effort".into(), Value::String("high".into()));
            fixups.capped_effort = true;
        }
    }
    fixups
}

/// Place the ephemeral prompt-cache breakpoints: on the last tool, the last
/// system block, and the final user turn.
///
/// A plain-string user turn (a typed prompt, a task notification) is wrapped
/// in `[{type:"text",text,cache_control}]` so it still closes the cached
/// prefix; leaving it as a string skipped the breakpoint and re-sent the
/// whole conversation uncached (~300k tokens per one-line reply in a long
/// session) while array-content tool-result turns were cached normally.
pub fn apply_ephemeral_cache_control(body: &mut Value) {
    let ephemeral = json!({"type": "ephemeral"});
    if let Some(tool) = body
        .get_mut("tools")
        .and_then(Value::as_array_mut)
        .and_then(|t| t.last_mut())
        .and_then(Value::as_object_mut)
    {
        tool.insert("cache_control".into(), ephemeral.clone());
    }
    if let Some(system) = body
        .get_mut("system")
        .and_then(Value::as_array_mut)
        .and_then(|s| s.last_mut())
        .and_then(Value::as_object_mut)
    {
        system.insert("cache_control".into(), ephemeral.clone());
    }
    let Some(messages) = body.get_mut("messages").and_then(Value::as_array_mut) else {
        return;
    };
    for message in messages.iter_mut().rev() {
        if message.get("role").and_then(Value::as_str) != Some("user") {
            continue;
        }
        let Some(object) = message.as_object_mut() else {
            continue;
        };
        match object.get_mut("content") {
            Some(Value::Array(blocks)) => {
                if let Some(last) = blocks.last_mut().and_then(Value::as_object_mut) {
                    last.insert("cache_control".into(), ephemeral.clone());
                }
            }
            Some(Value::String(text)) => {
                let text = std::mem::take(text);
                object.insert(
                    "content".into(),
                    json!([{"type": "text", "text": text, "cache_control": ephemeral}]),
                );
            }
            _ => {}
        }
        break;
    }
}

/// Claude Code's canonical tool names; a caller's lower-cased name is mapped
/// to the canonical casing on the wire.
pub const CLAUDE_CODE_TOOL_NAMES: [&str; 10] = [
    "Read",
    "Write",
    "Edit",
    "Bash",
    "Grep",
    "Glob",
    "AskUserQuestion",
    "TodoWrite",
    "WebFetch",
    "WebSearch",
];

/// Anthropic reserves this exact tool name for Claude Code's paid research
/// surface; a third-party tool with this wire name is rejected as extra-usage
/// traffic even with healthy quota.
pub const RESERVED_DEEP_RESEARCH_TOOL: &str = "deep_research";
/// The wire alias used in place of [`RESERVED_DEEP_RESEARCH_TOOL`].
pub const DEEP_RESEARCH_WIRE_TOOL: &str = "prime_deep_research";

/// The tool name to send on the wire: the reserved research name is aliased,
/// and Claude Code's own tools take their canonical casing.
pub fn to_wire_tool_name(name: &str) -> &str {
    if name == RESERVED_DEEP_RESEARCH_TOOL {
        return DEEP_RESEARCH_WIRE_TOOL;
    }
    CLAUDE_CODE_TOOL_NAMES
        .iter()
        .find(|canonical| canonical.eq_ignore_ascii_case(name))
        .copied()
        .unwrap_or(name)
}

/// Map a streamed `tool_use` name back to the caller's declared tool name.
/// The research alias is restored only when the caller actually declared
/// `deep_research`; otherwise names match case-insensitively against
/// `declared_tools`.
pub fn from_wire_tool_name<'a>(name: &'a str, declared_tools: &[&'a str]) -> &'a str {
    if name == DEEP_RESEARCH_WIRE_TOOL && declared_tools.contains(&RESERVED_DEEP_RESEARCH_TOOL) {
        return RESERVED_DEEP_RESEARCH_TOOL;
    }
    declared_tools
        .iter()
        .find(|tool| tool.eq_ignore_ascii_case(name))
        .copied()
        .unwrap_or(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Upstream `transform.test.ts` (eae6591): Opus 5.5 drops forced tool
    /// choice without dropping tools; `auto`/`none` and Opus 5 are untouched.
    #[test]
    fn opus_5_5_removes_forced_tool_choice_but_keeps_tools() {
        for (model, choice) in [
            ("claude-opus-5-5", json!({"type": "any"})),
            ("claude-opus-5-5[1m]", json!({"type": "any"})),
            (
                "claude-opus-5-5-20260918",
                json!({"type": "tool", "name": "StructuredOutput"}),
            ),
            ("claude-fable-5-1", json!({"type": "tool", "name": "x"})),
        ] {
            let mut body = json!({"model": model, "tools": [{"name": "StructuredOutput"}], "tool_choice": choice});
            let fixups = enforce_model_request_constraints(&mut body);
            assert!(fixups.removed_forced_tool_choice, "{model}");
            assert!(body.get("tool_choice").is_none(), "{model}");
            assert_eq!(body["tools"].as_array().map(Vec::len), Some(1));
        }
        for kind in ["auto", "none"] {
            let mut body = json!({"model": "claude-opus-5-5", "tool_choice": {"type": kind}});
            assert!(!enforce_model_request_constraints(&mut body).removed_forced_tool_choice);
            assert_eq!(body["tool_choice"], json!({"type": kind}));
        }
        let mut opus5 = json!({"model": "claude-opus-5", "tool_choice": {"type": "any"}});
        enforce_model_request_constraints(&mut opus5);
        assert_eq!(opus5["tool_choice"], json!({"type": "any"}));
    }

    #[test]
    fn opus_5_5_rewrites_disabled_and_budget_thinking_to_adaptive() {
        for thinking in [
            json!({"type": "disabled"}),
            json!({"type": "enabled", "budget_tokens": 4096}),
        ] {
            let mut body = json!({"model": "claude-opus-5-5", "thinking": thinking});
            let fixups = enforce_model_request_constraints(&mut body);
            assert!(fixups.rewrote_thinking);
            assert_eq!(
                body["thinking"],
                json!({"type": "adaptive", "display": "summarized"})
            );
        }
        let mut fable = json!({"model": "claude-fable-5", "thinking": {"type": "disabled"}});
        assert!(enforce_model_request_constraints(&mut fable).rewrote_thinking);
        // Already adaptive, or absent: untouched.
        let mut adaptive = json!({"model": "claude-opus-5-5", "thinking": {"type": "adaptive"}});
        assert_eq!(
            enforce_model_request_constraints(&mut adaptive),
            ModelConstraintFixups::default()
        );
        let mut absent = json!({"model": "claude-opus-5-5"});
        enforce_model_request_constraints(&mut absent);
        assert!(absent.get("thinking").is_none());
    }

    #[test]
    fn opus_5_disabled_thinking_caps_effort_at_high() {
        let mut body = json!({
            "model": "claude-opus-5",
            "thinking": {"type": "disabled", "display": "summarized"},
            "output_config": {"effort": "max"}
        });
        let fixups = enforce_model_request_constraints(&mut body);
        assert!(fixups.capped_effort && !fixups.rewrote_thinking);
        assert_eq!(body["thinking"], json!({"type": "disabled"}));
        assert_eq!(body["output_config"]["effort"], "high");
        let mut medium = json!({
            "model": "claude-opus-5",
            "thinking": {"type": "disabled"},
            "output_config": {"effort": "medium"}
        });
        assert!(!enforce_model_request_constraints(&mut medium).capped_effort);
        assert_eq!(medium["output_config"]["effort"], "medium");
        // Sonnet 5 accepts a disable; nothing changes.
        let mut sonnet = json!({"model": "claude-sonnet-5", "thinking": {"type": "disabled"}, "output_config": {"effort": "max"}});
        assert_eq!(
            enforce_model_request_constraints(&mut sonnet),
            ModelConstraintFixups::default()
        );
        assert_eq!(
            enforce_model_request_constraints(&mut json!([])),
            ModelConstraintFixups::default()
        );
    }

    fn request(model: &str, reasoning: Option<ReasoningLevel>) -> ThinkingRequest<'_> {
        ThinkingRequest {
            model,
            reasoning,
            max_tokens: 16_384,
            requested_budget_tokens: None,
            disable_adaptive_flag: None,
        }
    }

    #[test]
    fn adaptive_non_5_models_get_adaptive_plus_effort_only_with_reasoning() {
        let none = resolve_thinking_plan(request("claude-opus-4-8", None));
        assert_eq!(
            none,
            ThinkingPlan::default(),
            "must not force-inject thinking (would bill reasoning nobody asked for)"
        );
        let high = resolve_thinking_plan(request("claude-opus-4-8", Some(ReasoningLevel::High)));
        assert_eq!(
            high.thinking,
            Some(json!({"type":"adaptive","display":"summarized"}))
        );
        assert_eq!(high.effort, Some("high"));
        assert!(
            high.thinking
                .as_ref()
                .unwrap()
                .get("budget_tokens")
                .is_none()
        );
    }

    #[test]
    fn effort_is_clamped_per_model() {
        assert_eq!(
            resolve_thinking_plan(request("claude-opus-4-6", Some(ReasoningLevel::Xhigh))).effort,
            Some("high")
        );
        assert_eq!(
            resolve_thinking_plan(request("claude-opus-4-6", Some(ReasoningLevel::Max))).effort,
            Some("max")
        );
        assert_eq!(
            resolve_thinking_plan(request("claude-opus-4-7", Some(ReasoningLevel::Xhigh))).effort,
            Some("xhigh")
        );
        assert_eq!(
            resolve_thinking_plan(request("claude-opus-5", Some(ReasoningLevel::Minimal))).effort,
            Some("low")
        );
        assert_eq!(ReasoningLevel::parse("XHIGH"), Some(ReasoningLevel::Xhigh));
        assert_eq!(ReasoningLevel::parse("ultra"), None);
    }

    #[test]
    fn five_series_injects_summarized_adaptive_without_reasoning() {
        for model in [
            "claude-fable-5",
            "claude-mythos-5",
            "claude-sonnet-5",
            "claude-opus-5",
        ] {
            let plan = resolve_thinking_plan(request(model, None));
            assert_eq!(
                plan.thinking,
                Some(json!({"type":"adaptive","display":"summarized"})),
                "{model}"
            );
            assert_eq!(plan.effort, None);
            let with = resolve_thinking_plan(request(model, Some(ReasoningLevel::High)));
            assert_eq!(
                with.thinking,
                Some(json!({"type":"adaptive","display":"summarized"}))
            );
            assert_eq!(with.effort, Some("high"));
        }
    }

    #[test]
    fn legacy_models_get_manual_budget_clamped_below_max_tokens() {
        let plan = resolve_thinking_plan(request("claude-opus-4-5", Some(ReasoningLevel::High)));
        assert_eq!(
            plan.thinking,
            Some(json!({"type":"enabled","budget_tokens":16_383}))
        );
        assert_eq!(plan.effort, None);
        let small = resolve_thinking_plan(request("claude-sonnet-4-5", Some(ReasoningLevel::Low)));
        assert_eq!(
            small.thinking,
            Some(json!({"type":"enabled","budget_tokens":4_096}))
        );
        let custom = resolve_thinking_plan(ThinkingRequest {
            requested_budget_tokens: Some(2_000),
            ..request("claude-haiku-4-5", Some(ReasoningLevel::High))
        });
        assert_eq!(
            custom.thinking,
            Some(json!({"type":"enabled","budget_tokens":2_000}))
        );
        // The 4.6 escape hatch forces a budget; 4.7+ ignores it.
        let hatch = resolve_thinking_plan(ThinkingRequest {
            disable_adaptive_flag: Some("1"),
            ..request("claude-opus-4-6", Some(ReasoningLevel::High))
        });
        assert_eq!(
            hatch.thinking,
            Some(json!({"type":"enabled","budget_tokens":16_383}))
        );
        let ignored = resolve_thinking_plan(ThinkingRequest {
            disable_adaptive_flag: Some("1"),
            ..request("claude-opus-4-7", Some(ReasoningLevel::High))
        });
        assert_eq!(ignored.effort, Some("high"));
    }

    #[test]
    fn apply_plan_writes_thinking_and_output_config() {
        let mut body = json!({"model":"claude-opus-4-8","max_tokens":100});
        apply_thinking_plan(
            &mut body,
            &resolve_thinking_plan(request("claude-opus-4-8", Some(ReasoningLevel::Medium))),
        );
        assert_eq!(body["thinking"]["type"], "adaptive");
        assert_eq!(body["output_config"]["effort"], "medium");
        let mut existing = json!({"output_config":{"format":{"type":"json_schema"}}});
        apply_thinking_plan(
            &mut existing,
            &ThinkingPlan {
                thinking: None,
                effort: Some("low"),
            },
        );
        assert_eq!(existing["output_config"]["format"]["type"], "json_schema");
        assert_eq!(existing["output_config"]["effort"], "low");
    }

    #[test]
    fn cache_breakpoint_lands_on_plain_text_final_user_turn() {
        let mut body = json!({
            "tools":[{"name":"a"},{"name":"b"}],
            "system":[{"type":"text","text":"s1"},{"type":"text","text":"s2"}],
            "messages":[
                {"role":"user","content":[{"type":"text","text":"first"}]},
                {"role":"assistant","content":"reply"},
                {"role":"user","content":"typed prompt"}
            ]
        });
        apply_ephemeral_cache_control(&mut body);
        assert_eq!(body["tools"][1]["cache_control"]["type"], "ephemeral");
        assert!(body["tools"][0].get("cache_control").is_none());
        assert_eq!(body["system"][1]["cache_control"]["type"], "ephemeral");
        assert_eq!(
            body["messages"][2]["content"],
            json!([{"type":"text","text":"typed prompt","cache_control":{"type":"ephemeral"}}])
        );
        assert!(
            body["messages"][0]["content"][0]
                .get("cache_control")
                .is_none()
        );
        // Array content: breakpoint on the last block only.
        let mut array = json!({"messages":[{"role":"user","content":[{"type":"text","text":"a"},{"type":"tool_result","tool_use_id":"x"}]}]});
        apply_ephemeral_cache_control(&mut array);
        assert_eq!(
            array["messages"][0]["content"][1]["cache_control"]["type"],
            "ephemeral"
        );
        assert!(
            array["messages"][0]["content"][0]
                .get("cache_control")
                .is_none()
        );
    }

    #[test]
    fn reserved_research_tool_is_aliased_and_restored() {
        assert_eq!(to_wire_tool_name("deep_research"), "prime_deep_research");
        assert_eq!(to_wire_tool_name("bash"), "Bash");
        assert_eq!(to_wire_tool_name("custom_tool"), "custom_tool");
        assert_eq!(
            from_wire_tool_name("prime_deep_research", &["deep_research", "bash"]),
            "deep_research"
        );
        // Not declared: the wire name is returned untouched.
        assert_eq!(
            from_wire_tool_name("prime_deep_research", &["bash"]),
            "prime_deep_research"
        );
        assert_eq!(from_wire_tool_name("Bash", &["bash"]), "bash");
    }
}
