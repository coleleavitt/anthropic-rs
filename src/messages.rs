//! A deliberately small Messages API surface: enough to send a request and read
//! a streamed response, with no agent loop, tool runtime, or session model.
//!
//! Consumers that want a full agent framework build it on top; this layer only
//! owns the wire types, auth application, and SSE framing.

#[cfg(feature = "client")]
use chrono::Utc;
use serde::{Deserialize, Serialize};

#[cfg(feature = "client")]
use crate::{
    endpoints::Endpoints,
    error::{Error, Result, redacted_response_body},
    request::HeaderMutation,
    token::{AuthHeader, Credential},
};

/// Who authored a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// The end user.
    User,
    /// The model.
    Assistant,
}

/// One content block within a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ContentBlock {
    /// Plain text.
    Text {
        /// The text body.
        text: String,
    },
    /// Extended-thinking output.
    Thinking {
        /// The reasoning text.
        thinking: String,
        /// Server signature for replay.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
    },
    /// A tool invocation requested by the model.
    ToolUse {
        /// Tool call id.
        id: String,
        /// Tool name.
        name: String,
        /// Tool arguments.
        input: serde_json::Value,
    },
    /// A tool result supplied by the caller.
    ToolResult {
        /// The id of the call being answered.
        tool_use_id: String,
        /// Result payload.
        content: String,
        /// Whether the tool failed.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        is_error: bool,
    },
}

impl ContentBlock {
    /// Convenience constructor for a text block.
    pub fn text(body: impl Into<String>) -> Self {
        Self::Text { text: body.into() }
    }

    /// The text carried by this block, if any.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            ContentBlock::Text { text } => Some(text),
            _ => None,
        }
    }
}

/// One turn in the conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Turn author.
    pub role: Role,
    /// Turn content.
    pub content: Vec<ContentBlock>,
}

impl Message {
    /// A user turn carrying a single text block.
    pub fn user(text: impl Into<String>) -> Self {
        Self {
            role: Role::User,
            content: vec![ContentBlock::text(text)],
        }
    }

    /// An assistant turn carrying a single text block.
    pub fn assistant(text: impl Into<String>) -> Self {
        Self {
            role: Role::Assistant,
            content: vec![ContentBlock::text(text)],
        }
    }

    /// All text across this turn's blocks, concatenated.
    pub fn text(&self) -> String {
        self.content
            .iter()
            .filter_map(ContentBlock::as_text)
            .collect::<Vec<_>>()
            .join("")
    }
}

/// A Messages API request body.
#[derive(Debug, Clone, Serialize)]
pub struct MessagesRequest {
    /// Model id.
    pub model: String,
    /// Maximum tokens to generate.
    pub max_tokens: u32,
    /// Conversation turns.
    pub messages: Vec<Message>,
    /// Optional system prompt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    /// Sampling temperature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    /// Whether to stream the response.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub stream: bool,
}

impl MessagesRequest {
    /// A non-streaming request for `model` with a single user message.
    pub fn new(model: impl Into<String>, max_tokens: u32, messages: Vec<Message>) -> Self {
        Self {
            model: model.into(),
            max_tokens,
            messages,
            system: None,
            temperature: None,
            stream: false,
        }
    }

    /// Attach a system prompt.
    pub fn with_system(mut self, system: impl Into<String>) -> Self {
        self.system = Some(system.into());
        self
    }

    /// Enable streaming.
    pub fn streaming(mut self) -> Self {
        self.stream = true;
        self
    }
}

/// Token accounting returned with a response.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Usage {
    /// Input tokens billed.
    #[serde(default)]
    pub input_tokens: u32,
    /// Output tokens billed.
    #[serde(default)]
    pub output_tokens: u32,
    /// Tokens read from the prompt cache.
    #[serde(default)]
    pub cache_read_input_tokens: u32,
    /// Tokens written to the prompt cache.
    #[serde(default)]
    pub cache_creation_input_tokens: u32,
}

/// A completed Messages API response.
#[derive(Debug, Clone, Deserialize)]
pub struct MessagesResponse {
    /// Response id.
    pub id: String,
    /// Model that produced it.
    pub model: String,
    /// Response content blocks.
    #[serde(default)]
    pub content: Vec<ContentBlock>,
    /// Why generation stopped.
    #[serde(default)]
    pub stop_reason: Option<String>,
    /// Token accounting.
    #[serde(default)]
    pub usage: Usage,
}

impl MessagesResponse {
    /// All text across the response's blocks.
    pub fn text(&self) -> String {
        self.content
            .iter()
            .filter_map(ContentBlock::as_text)
            .collect::<Vec<_>>()
            .join("")
    }
}

/// One decoded server-sent event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    /// The `event:` name, empty when the frame omitted one.
    pub event: String,
    /// The concatenated `data:` payload.
    pub data: String,
}

/// Incremental SSE frame decoder.
///
/// Kept separate from the HTTP client so the framing rules are unit-testable
/// without a network: feed it chunks, take whole events out.
#[derive(Debug, Default)]
pub struct SseDecoder {
    buffer: String,
}

impl SseDecoder {
    /// A fresh decoder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a chunk of the response body and drain any complete events.
    pub fn push(&mut self, chunk: &str) -> Vec<SseEvent> {
        self.buffer.push_str(chunk);
        let mut events = Vec::new();
        // Frames are separated by a blank line. Normalize CRLF first so a
        // proxy that rewrites line endings does not stall the stream.
        while let Some(idx) = find_frame_end(&self.buffer) {
            let (frame, rest) = self.buffer.split_at(idx.0);
            let frame = frame.to_owned();
            self.buffer = rest[idx.1..].to_owned();
            if let Some(event) = parse_frame(&frame) {
                events.push(event);
            }
        }
        events
    }

    /// Drain any trailing frame that arrived without a terminating blank line.
    pub fn finish(&mut self) -> Option<SseEvent> {
        let frame = std::mem::take(&mut self.buffer);
        parse_frame(&frame)
    }
}

/// Offset of the end of the first complete frame and the separator length.
fn find_frame_end(buf: &str) -> Option<(usize, usize)> {
    let lf = buf.find("\n\n").map(|i| (i, 2));
    let crlf = buf.find("\r\n\r\n").map(|i| (i, 4));
    match (lf, crlf) {
        (Some(a), Some(b)) => Some(if a.0 <= b.0 { a } else { b }),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn parse_frame(frame: &str) -> Option<SseEvent> {
    let mut event = String::new();
    let mut data = String::new();
    let mut saw_field = false;
    for line in frame.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        let (field, value) = match line.split_once(':') {
            Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
            None => (line, ""),
        };
        match field {
            "event" => {
                event = value.to_owned();
                saw_field = true;
            }
            "data" => {
                if !data.is_empty() {
                    data.push('\n');
                }
                data.push_str(value);
                saw_field = true;
            }
            _ => {}
        }
    }
    saw_field.then_some(SseEvent { event, data })
}

/// Minimal Messages API client.
#[cfg(feature = "client")]
#[derive(Clone)]
pub struct MessagesClient {
    http: reqwest::Client,
    endpoints: Endpoints,
}

#[cfg(feature = "client")]
impl MessagesClient {
    /// Client with a fresh default [`reqwest::Client`].
    pub fn new(endpoints: Endpoints) -> Self {
        Self {
            http: reqwest::Client::new(),
            endpoints,
        }
    }

    /// Client reusing a caller-provided [`reqwest::Client`].
    pub fn with_http(http: reqwest::Client, endpoints: Endpoints) -> Self {
        Self { http, endpoints }
    }

    fn build(&self, credential: &Credential, request: &MessagesRequest) -> reqwest::RequestBuilder {
        self.build_with_mutation(HeaderMutation::for_credential(credential), request)
    }

    #[cfg(feature = "federation")]
    fn build_federated(
        &self,
        token: &crate::federation::FederatedToken,
        request: &MessagesRequest,
    ) -> reqwest::RequestBuilder {
        self.build_with_mutation(HeaderMutation::for_federated_token(token), request)
    }

    fn build_with_mutation(
        &self,
        mutation: HeaderMutation,
        request: &MessagesRequest,
    ) -> reqwest::RequestBuilder {
        let mut headers = reqwest::header::HeaderMap::new();
        mutation.apply_to_header_map(&mut headers);
        self.http
            .post(self.endpoints.messages_url())
            .headers(headers)
            .header("content-type", "application/json")
            .json(request)
    }

    /// Send a non-streaming request.
    pub async fn send(
        &self,
        credential: &Credential,
        request: &MessagesRequest,
    ) -> Result<MessagesResponse> {
        credential.validate_for_request(Utc::now())?;
        let resp = self.build(credential, request).send().await?;
        let status = resp.status();
        if status.is_success() {
            return Ok(resp.json().await?);
        }
        // Snapshot the headers before the body consumes the response.
        let headers = resp.headers().clone();
        let auth = credential.auth_header();
        let secret = match &auth {
            AuthHeader::Bearer(value) | AuthHeader::ApiKey(value) => value.as_str(),
        };
        let body = redacted_response_body(resp, &[secret]).await;
        Err(api_error(
            status.as_u16(),
            &headers,
            body,
            credential.is_oauth(),
        ))
    }

    /// Send a streaming request and return the raw byte stream, already
    /// checked for a non-success status.
    pub async fn stream(
        &self,
        credential: &Credential,
        request: &MessagesRequest,
    ) -> Result<reqwest::Response> {
        credential.validate_for_request(Utc::now())?;
        let mut request = request.clone();
        request.stream = true;
        let resp = self.build(credential, &request).send().await?;
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        let headers = resp.headers().clone();
        let auth = credential.auth_header();
        let secret = match &auth {
            AuthHeader::Bearer(value) | AuthHeader::ApiKey(value) => value.as_str(),
        };
        let body = redacted_response_body(resp, &[secret]).await;
        Err(api_error(
            status.as_u16(),
            &headers,
            body,
            credential.is_oauth(),
        ))
    }

    /// Send a non-streaming request with a Workload Identity Federation token.
    /// This path uses standard bearer auth without Claude subscription betas or
    /// identity emulation.
    #[cfg(feature = "federation")]
    pub async fn send_federated(
        &self,
        token: &crate::federation::FederatedToken,
        request: &MessagesRequest,
    ) -> Result<MessagesResponse> {
        let resp = self.build_federated(token, request).send().await?;
        let status = resp.status();
        if status.is_success() {
            return Ok(resp.json().await?);
        }
        let headers = resp.headers().clone();
        let body = redacted_response_body(resp, &[token.access.expose()]).await;
        Err(api_error(status.as_u16(), &headers, body, true))
    }

    /// Send a streaming request with Workload Identity Federation auth.
    #[cfg(feature = "federation")]
    pub async fn stream_federated(
        &self,
        token: &crate::federation::FederatedToken,
        request: &MessagesRequest,
    ) -> Result<reqwest::Response> {
        let mut request = request.clone();
        request.stream = true;
        let resp = self.build_federated(token, &request).send().await?;
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        let headers = resp.headers().clone();
        let body = redacted_response_body(resp, &[token.access.expose()]).await;
        Err(api_error(status.as_u16(), &headers, body, true))
    }
}

#[cfg(feature = "client")]
fn api_error(
    status: u16,
    headers: &reqwest::header::HeaderMap,
    body: String,
    oauth_bearer: bool,
) -> Error {
    let permanent = match status {
        400 | 404 | 422 => true,
        401 => !oauth_bearer,
        403 => true,
        _ => false,
    };
    Error::Endpoint {
        status,
        permanent,
        error_code: crate::oauth::parse_error_code(&body),
        retry_after_ms: crate::oauth::parse_retry_after_ms(headers),
        body,
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::*;
    use crate::token::{AccessToken, ApiKey, OAuthTokens, RefreshToken};

    #[test]
    fn message_helpers_build_text_turns_normal() {
        let m = Message::user("hello");
        assert_eq!(m.role, Role::User);
        assert_eq!(m.text(), "hello");
        assert_eq!(Message::assistant("hi").role, Role::Assistant);
    }

    #[cfg(feature = "client")]
    #[test]
    fn oauth_401_is_not_classified_as_permanent() {
        let headers = reqwest::header::HeaderMap::new();
        let credential = Credential::Oauth(OAuthTokens {
            access: AccessToken::new("sk-ant-oat01-accessaccessaccessaccess"),
            refresh: RefreshToken::new("sk-ant-ort01-refreshrefreshrefreshref"),
            expires_at: Utc.timestamp_opt(1_900_000_000, 0).unwrap(),
            refresh_expires_at: Some(Utc.timestamp_opt(2_000_000_000, 0).unwrap()),
            scopes: vec!["user:inference".into()],
            account: None,
            organization: None,
        });
        let error = api_error(401, &headers, "unauthorized".into(), credential.is_oauth());
        assert!(!error.is_permanent());
    }

    #[cfg(feature = "client")]
    #[test]
    fn api_key_401_remains_permanent() {
        let headers = reqwest::header::HeaderMap::new();
        let credential = Credential::ApiKey {
            key: ApiKey::new("sk-ant-api01-abcdefghijklmnopqrstuvwxyz012345"),
        };
        let error = api_error(401, &headers, "unauthorized".into(), credential.is_oauth());
        assert!(error.is_permanent());
    }

    #[test]
    fn request_serializes_only_the_fields_it_sets_normal() {
        let req = MessagesRequest::new("claude-x", 100, vec![Message::user("hi")]);
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["model"], "claude-x");
        assert_eq!(json["max_tokens"], 100);
        // Unset optionals and `stream: false` stay off the wire.
        assert!(json.get("system").is_none());
        assert!(json.get("temperature").is_none());
        assert!(json.get("stream").is_none());

        let streaming = req.clone().with_system("be terse").streaming();
        let json = serde_json::to_value(&streaming).unwrap();
        assert_eq!(json["system"], "be terse");
        assert_eq!(json["stream"], true);
    }

    #[test]
    fn response_concatenates_text_blocks_normal() {
        let resp: MessagesResponse = serde_json::from_str(
            r#"{
                "id": "msg_1",
                "model": "claude-x",
                "content": [
                    {"type":"text","text":"Hello, "},
                    {"type":"thinking","thinking":"hidden"},
                    {"type":"text","text":"world"}
                ],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 5, "output_tokens": 2}
            }"#,
        )
        .unwrap();
        assert_eq!(resp.text(), "Hello, world");
        assert_eq!(resp.usage.input_tokens, 5);
    }

    #[test]
    fn sse_decoder_emits_complete_frames_normal() {
        let mut d = SseDecoder::new();
        let events = d.push("event: message_start\ndata: {\"a\":1}\n\n");
        assert_eq!(
            events,
            vec![SseEvent {
                event: "message_start".into(),
                data: "{\"a\":1}".into()
            }]
        );
    }

    #[test]
    fn sse_decoder_handles_split_chunks_robust() {
        let mut d = SseDecoder::new();
        assert!(d.push("event: content_bl").is_empty());
        assert!(d.push("ock_delta\ndata: {\"x\"").is_empty());
        let events = d.push(":2}\n\n");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "content_block_delta");
        assert_eq!(events[0].data, "{\"x\":2}");
    }

    #[test]
    fn sse_decoder_handles_crlf_and_multiline_data_robust() {
        let mut d = SseDecoder::new();
        let events = d.push("event: e\r\ndata: line1\r\ndata: line2\r\n\r\n");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "line1\nline2");
    }

    #[test]
    fn sse_decoder_skips_comments_and_keepalives_robust() {
        let mut d = SseDecoder::new();
        // A bare comment frame carries no field and must not surface.
        assert!(d.push(": ping\n\n").is_empty());
        let events = d.push("data: real\n\n");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "real");
    }

    #[test]
    fn sse_decoder_finish_drains_unterminated_frame_robust() {
        let mut d = SseDecoder::new();
        assert!(d.push("data: tail").is_empty());
        let last = d.finish().expect("trailing frame");
        assert_eq!(last.data, "tail");
        // Draining twice yields nothing.
        assert!(d.finish().is_none());
    }
}
