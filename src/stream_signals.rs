//! Pure classification of what an Anthropic SSE stream is telling the
//! router: an error frame on an HTTP-200 stream (a rate limit with no status
//! and no `retry-after`), a terminal `message_delta` stop reason (refusal,
//! context overflow) with the token counts that explain it, and the bounded
//! client-side refusal → fallback decision.
//!
//! Everything here consumes already-parsed SSE `data:` JSON so it is
//! testable without a network; pair it with [`crate::SseDecoder`].

use serde::Deserialize;

use crate::models::resolve_refusal_fallback_model;

/// Streamed error types worth rotating to another account. Anything else is
/// the caller's business and is surfaced as-is rather than burning the pool.
pub const ROTATABLE_STREAM_ERRORS: [&str; 2] = ["rate_limit_error", "overloaded_error"];

/// Maximum client-side refusal re-routes per turn (mirrors Claude Code 2.1.268).
pub const MAX_REFUSAL_FALLBACK_HOPS: u32 = 2;

#[derive(Debug, Default, Deserialize)]
struct RawError {
    #[serde(rename = "type")]
    error_type: Option<String>,
    message: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RawStopDetails {
    category: Option<String>,
    explanation: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RawDelta {
    #[serde(rename = "type")]
    delta_type: Option<String>,
    stop_reason: Option<String>,
    stop_details: Option<RawStopDetails>,
}

#[derive(Debug, Default, Deserialize)]
struct RawUsage {
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
struct RawEvent {
    #[serde(rename = "type")]
    event_type: Option<String>,
    error: Option<RawError>,
    delta: Option<RawDelta>,
    usage: Option<RawUsage>,
}

/// Why a stream stopped, from `message_delta.delta`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StopDetails {
    /// `stop_details.category` (e.g. `bio`, `cyber`), when present.
    pub category: Option<String>,
    /// `stop_details.explanation`, when present.
    pub explanation: Option<String>,
}

/// A terminal `message_delta` frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageDeltaSignal {
    /// `delta.stop_reason`, when the delta carried one.
    pub stop_reason: Option<String>,
    /// Refusal category/explanation, when present.
    pub stop_details: StopDetails,
    /// `usage.input_tokens` from the same delta — what separates a
    /// context-size refusal from a content decline.
    pub input_tokens: Option<u64>,
    /// `usage.output_tokens` from the same delta.
    pub output_tokens: Option<u64>,
}

/// What a single parsed SSE event means to the router.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamSignal {
    /// `{"type":"error","error":{"type":"rate_limit_error"|"overloaded_error"}}`
    /// — an out-of-credits account answers HTTP 200 with this as its first
    /// frame. Rotate to another account.
    RotatableError {
        /// `error.type`.
        error_type: String,
        /// `error.message`, when present.
        message: Option<String>,
    },
    /// Any other error frame: surface as-is.
    StreamError {
        /// `error.type`, when present.
        error_type: Option<String>,
        /// `error.message`, when present.
        message: Option<String>,
    },
    /// A `message_delta` frame.
    MessageDelta(MessageDeltaSignal),
    /// Anything else (content deltas, `message_start`, pings…).
    Other,
}

impl StreamSignal {
    /// Classify the JSON payload of one SSE `data:` line. Unparseable data is
    /// [`StreamSignal::Other`].
    pub fn classify(data: &str) -> StreamSignal {
        let Ok(event) = serde_json::from_str::<RawEvent>(data) else {
            return StreamSignal::Other;
        };
        match event.event_type.as_deref() {
            Some("error") => {
                // Read `error.type`, keeping the old `delta.type` read as a
                // fallback for peers that emitted it there.
                let error_type = event
                    .error
                    .as_ref()
                    .and_then(|e| e.error_type.clone())
                    .or_else(|| event.delta.as_ref().and_then(|d| d.delta_type.clone()));
                let message = event.error.as_ref().and_then(|e| e.message.clone());
                match error_type {
                    Some(kind) if ROTATABLE_STREAM_ERRORS.contains(&kind.as_str()) => {
                        StreamSignal::RotatableError {
                            error_type: kind,
                            message,
                        }
                    }
                    other => StreamSignal::StreamError {
                        error_type: other,
                        message,
                    },
                }
            }
            Some("message_delta") => {
                let delta = event.delta.unwrap_or_default();
                let details = delta.stop_details.unwrap_or_default();
                let usage = event.usage.unwrap_or_default();
                StreamSignal::MessageDelta(MessageDeltaSignal {
                    stop_reason: delta.stop_reason,
                    stop_details: StopDetails {
                        category: details
                            .category
                            .map(|c| c.trim().to_owned())
                            .filter(|c| !c.is_empty()),
                        explanation: details
                            .explanation
                            .map(|e| e.trim().to_owned())
                            .filter(|e| !e.is_empty()),
                    },
                    input_tokens: usage.input_tokens,
                    output_tokens: usage.output_tokens,
                })
            }
            _ => StreamSignal::Other,
        }
    }

    /// Whether this is the first-frame rotatable error.
    pub fn is_rotatable_error(&self) -> bool {
        matches!(self, StreamSignal::RotatableError { .. })
    }
}

/// The caller-facing outcome class of an Anthropic `stop_reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopKind {
    /// `end_turn`, `pause_turn`, `stop_sequence`.
    Stop,
    /// `max_tokens`.
    Length,
    /// `tool_use`.
    ToolUse,
    /// `refusal`, `model_context_window_exceeded`, or anything unknown.
    Error,
}

/// Map an Anthropic `stop_reason` to its outcome class.
///
/// `model_context_window_exceeded` stays an error instead of the `length`
/// truncation Claude Code reuses for it: a caller that compacts a
/// conversation would otherwise accept the truncated response as a complete
/// summary and persist it over the original messages.
pub fn map_stop_reason(reason: Option<&str>) -> StopKind {
    match reason {
        Some("end_turn" | "pause_turn" | "stop_sequence") => StopKind::Stop,
        Some("max_tokens") => StopKind::Length,
        Some("tool_use") => StopKind::ToolUse,
        _ => StopKind::Error,
    }
}

/// Human-readable failure text for an error stop reason.
pub fn describe_stop_reason_failure(reason: &str, details: &StopDetails) -> String {
    match reason {
        "refusal" => {
            let mut text = "Anthropic refused this request (stop_reason: refusal). The input and any thinking or output tokens produced before the refusal are billed.".to_owned();
            if let Some(category) = &details.category {
                text.push_str(&format!(" Category: {category}."));
            }
            if let Some(explanation) = &details.explanation {
                text.push(' ');
                text.push_str(explanation);
            }
            text
        }
        "model_context_window_exceeded" => "Anthropic stopped early: the request exceeded the model context window (stop_reason: model_context_window_exceeded). Compact or split the conversation.".to_owned(),
        other => format!("Anthropic stream ended with an unhandled stop reason: {other}"),
    }
}

/// What a turn had produced by the time a terminal refusal arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RefusalContext {
    /// Any user-visible text/thinking was already streamed to the caller.
    pub visible_content_streamed: bool,
    /// A tool call was completed on this turn.
    pub completed_tool_call: bool,
    /// Re-routes already taken this turn.
    pub hops_taken: u32,
}

/// The client-side decision for a terminal `stop_reason: refusal`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefusalDecision {
    /// Re-issue the prompt on this model.
    Reroute {
        /// The mapped fallback model.
        model: &'static str,
    },
    /// Preserve the refusal as the turn's outcome; do not retry on any
    /// account (a refusal is terminal, not transient).
    Surface,
}

/// Decide whether a terminal refusal on `model` should be re-issued on a
/// mapped fallback model. Mirrors Claude Code 2.1.268's client-side recovery:
/// only when nothing user-visible was streamed and no tool call completed,
/// bounded to [`MAX_REFUSAL_FALLBACK_HOPS`], and only to a model that is not
/// the refusing one and has not been tried this turn.
pub fn decide_refusal_fallback(
    model: &str,
    details: &StopDetails,
    tried_models: &[&str],
    context: RefusalContext,
) -> RefusalDecision {
    if context.visible_content_streamed
        || context.completed_tool_call
        || context.hops_taken >= MAX_REFUSAL_FALLBACK_HOPS
    {
        return RefusalDecision::Surface;
    }
    match resolve_refusal_fallback_model(model, details.category.as_deref(), tried_models, true) {
        Some(target) => RefusalDecision::Reroute { model: target },
        None => RefusalDecision::Surface,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact production payload: HTTP 200, first frame.
    const RATE_LIMITED_FRAME: &str = r#"{"type":"error","error":{"details":null,"type":"rate_limit_error","message":"Rate limited"}}"#;

    #[test]
    fn detects_a_rate_limit_on_a_200_stream() {
        let signal = StreamSignal::classify(RATE_LIMITED_FRAME);
        assert_eq!(
            signal,
            StreamSignal::RotatableError {
                error_type: "rate_limit_error".into(),
                message: Some("Rate limited".into())
            }
        );
        assert!(signal.is_rotatable_error());
        assert!(
            StreamSignal::classify(r#"{"type":"error","error":{"type":"overloaded_error"}}"#)
                .is_rotatable_error()
        );
        // The old `delta.type` read still works as a fallback…
        assert!(
            StreamSignal::classify(r#"{"type":"error","delta":{"type":"rate_limit_error"}}"#)
                .is_rotatable_error()
        );
        // …but `error.type` wins when both are present.
        assert_eq!(
            StreamSignal::classify(
                r#"{"type":"error","error":{"type":"invalid_request_error","message":"bad"},"delta":{"type":"rate_limit_error"}}"#
            ),
            StreamSignal::StreamError {
                error_type: Some("invalid_request_error".into()),
                message: Some("bad".into())
            }
        );
    }

    #[test]
    fn other_errors_and_frames_are_not_rotatable() {
        assert!(
            !StreamSignal::classify(
                r#"{"type":"error","error":{"type":"api_error","message":"x"}}"#
            )
            .is_rotatable_error()
        );
        assert_eq!(
            StreamSignal::classify(r#"{"type":"message_start","message":{}}"#),
            StreamSignal::Other
        );
        assert_eq!(StreamSignal::classify("not json"), StreamSignal::Other);
        assert_eq!(
            StreamSignal::classify(r#"{"type":"error"}"#),
            StreamSignal::StreamError {
                error_type: None,
                message: None
            }
        );
    }

    #[test]
    fn message_delta_carries_stop_reason_details_and_usage() {
        let delta = r#"{"type":"message_delta","delta":{"stop_reason":"refusal","stop_details":{"category":"cyber","explanation":" declined "}},"usage":{"input_tokens":200000,"output_tokens":0}}"#;
        let StreamSignal::MessageDelta(signal) = StreamSignal::classify(delta) else {
            panic!("not a delta");
        };
        assert_eq!(signal.stop_reason.as_deref(), Some("refusal"));
        assert_eq!(signal.stop_details.category.as_deref(), Some("cyber"));
        assert_eq!(signal.stop_details.explanation.as_deref(), Some("declined"));
        assert_eq!(signal.input_tokens, Some(200_000));
        assert_eq!(signal.output_tokens, Some(0));
        let plain = StreamSignal::classify(
            r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":1}}"#,
        );
        let StreamSignal::MessageDelta(signal) = plain else {
            panic!("not a delta");
        };
        assert_eq!(signal.stop_details, StopDetails::default());
        assert_eq!(signal.input_tokens, None);
    }

    #[test]
    fn stop_reason_mapping_and_descriptions() {
        assert_eq!(map_stop_reason(Some("end_turn")), StopKind::Stop);
        assert_eq!(map_stop_reason(Some("pause_turn")), StopKind::Stop);
        assert_eq!(map_stop_reason(Some("max_tokens")), StopKind::Length);
        assert_eq!(map_stop_reason(Some("tool_use")), StopKind::ToolUse);
        assert_eq!(map_stop_reason(Some("refusal")), StopKind::Error);
        assert_eq!(
            map_stop_reason(Some("model_context_window_exceeded")),
            StopKind::Error
        );
        assert_eq!(map_stop_reason(None), StopKind::Error);
        let refusal = describe_stop_reason_failure(
            "refusal",
            &StopDetails {
                category: Some("cyber".into()),
                explanation: Some("declined".into()),
            },
        );
        assert!(refusal.contains("stop_reason: refusal"));
        assert!(refusal.ends_with("Category: cyber. declined"));
        assert!(
            describe_stop_reason_failure("model_context_window_exceeded", &StopDetails::default())
                .contains("Compact or split")
        );
        assert!(describe_stop_reason_failure("weird", &StopDetails::default()).contains("weird"));
    }

    #[test]
    fn refusal_fallback_decision_is_bounded_and_content_aware() {
        let cyber = StopDetails {
            category: Some("cyber".into()),
            explanation: None,
        };
        assert_eq!(
            decide_refusal_fallback("claude-fable-5", &cyber, &[], RefusalContext::default()),
            RefusalDecision::Reroute {
                model: "claude-opus-4-8"
            }
        );
        assert_eq!(
            decide_refusal_fallback(
                "claude-fable-5",
                &StopDetails::default(),
                &[],
                RefusalContext::default()
            ),
            RefusalDecision::Reroute {
                model: "claude-opus-4-8"
            }
        );
        // On the floor itself the category is surfaced, never re-routed.
        assert_eq!(
            decide_refusal_fallback(
                "claude-opus-4-8",
                &cyber,
                &["claude-fable-5"],
                RefusalContext {
                    hops_taken: 1,
                    ..Default::default()
                }
            ),
            RefusalDecision::Surface
        );
        // Visible content or a completed tool call preserves the turn unchanged.
        assert_eq!(
            decide_refusal_fallback(
                "claude-fable-5",
                &cyber,
                &[],
                RefusalContext {
                    visible_content_streamed: true,
                    ..Default::default()
                }
            ),
            RefusalDecision::Surface
        );
        assert_eq!(
            decide_refusal_fallback(
                "claude-fable-5",
                &cyber,
                &[],
                RefusalContext {
                    completed_tool_call: true,
                    ..Default::default()
                }
            ),
            RefusalDecision::Surface
        );
        assert_eq!(
            decide_refusal_fallback(
                "claude-fable-5",
                &cyber,
                &[],
                RefusalContext {
                    hops_taken: MAX_REFUSAL_FALLBACK_HOPS,
                    ..Default::default()
                }
            ),
            RefusalDecision::Surface
        );
    }
}
