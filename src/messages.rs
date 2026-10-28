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

    #[test]
    fn sse_decoder_picks_the_earliest_frame_boundary_when_both_styles_present_robust() {
        let mut d = SseDecoder::new();
        // The first frame closes with LF-LF, the second with CRLF-CRLF. The
        // decoder must cut at whichever boundary comes first in the buffer, not
        // whichever style it looks for first.
        let events = d.push("event: a\ndata: 1\n\nevent: b\r\ndata: 2\r\n\r\n");
        assert_eq!(
            events,
            vec![
                SseEvent {
                    event: "a".into(),
                    data: "1".into(),
                },
                SseEvent {
                    event: "b".into(),
                    data: "2".into(),
                },
            ]
        );
    }

    #[test]
    fn sse_decoder_cuts_at_a_crlf_boundary_before_a_later_lf_boundary_robust() {
        let mut d = SseDecoder::new();
        // Mirror image: a CRLF-CRLF separator precedes a later LF-LF one, so the
        // CRLF offset must win the comparison.
        let events = d.push("data: first\r\n\r\ndata: second\n\n");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].data, "first");
        assert_eq!(events[1].data, "second");
    }

    #[test]
    fn sse_decoder_ignores_unknown_fields_and_bare_lines_robust() {
        let mut d = SseDecoder::new();
        // `id:` and `retry:` are SSE fields this client does not consume, and a
        // line with no colon is a bare field name carrying an empty value. None
        // of the three may surface, but a real `data:` in the same frame still
        // produces an event whose `event` name stayed empty.
        let events = d.push("id: 99\nretry: 3000\nbarefield\ndata: payload\n\n");
        assert_eq!(
            events,
            vec![SseEvent {
                event: String::new(),
                data: "payload".into(),
            }]
        );
    }

    #[cfg(feature = "client")]
    const TEST_API_KEY: &str = "sk-ant-api01-abcdefghijklmnopqrstuvwxyz012345";

    #[cfg(feature = "client")]
    fn endpoints_at(base: &str) -> Endpoints {
        let mut endpoints = Endpoints::prod();
        endpoints.base_api_url = base.to_owned();
        endpoints
    }

    #[cfg(feature = "client")]
    fn api_key_credential() -> Credential {
        Credential::ApiKey {
            key: ApiKey::new(TEST_API_KEY),
        }
    }

    /// A live (non-expired, inference-scoped) OAuth session, so
    /// `validate_for_request` lets the request through to the mock endpoint.
    #[cfg(feature = "client")]
    fn live_oauth_credential() -> Credential {
        Credential::Oauth(OAuthTokens {
            access: AccessToken::new("sk-ant-oat01-liveaccessliveaccessliveacc"),
            refresh: RefreshToken::new("sk-ant-ort01-liverefreshliverefreshlive"),
            expires_at: Utc.timestamp_opt(1_900_000_000, 0).unwrap(),
            refresh_expires_at: Some(Utc.timestamp_opt(2_000_000_000, 0).unwrap()),
            scopes: vec!["user:inference".into()],
            account: None,
            organization: None,
        })
    }

    /// A loopback HTTP server that answers every request with the same
    /// `status`/`body` and records each raw request (head and body) it read.
    #[cfg(feature = "client")]
    async fn mock_messages_server(
        status: u16,
        body: &'static str,
    ) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = captured.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let sink = sink.clone();
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        let Ok(read) = stream.read(&mut chunk).await else {
                            return;
                        };
                        if read == 0 {
                            return;
                        }
                        request.extend_from_slice(&chunk[..read]);
                        if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                            let headers =
                                String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                            let length = headers
                                .lines()
                                .find_map(|l| {
                                    l.strip_prefix("content-length:")
                                        .and_then(|v| v.trim().parse::<usize>().ok())
                                })
                                .unwrap_or(0);
                            if request.len() >= end + 4 + length {
                                break;
                            }
                        }
                    }
                    sink.lock()
                        .unwrap()
                        .push(String::from_utf8_lossy(&request).into_owned());
                    let reason = if (200..300).contains(&status) {
                        "OK"
                    } else {
                        "Error"
                    };
                    let response = format!(
                        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        (format!("http://{address}"), captured)
    }

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn send_parses_a_successful_response_and_sends_the_request_body_normal() {
        const BODY: &str = r#"{
            "id": "msg_42",
            "model": "claude-opus-4",
            "content": [{"type":"text","text":"pong"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 11, "output_tokens": 3}
        }"#;
        let (base, requests) = mock_messages_server(200, BODY).await;
        let client = MessagesClient::new(endpoints_at(&base));
        let request = MessagesRequest::new("claude-opus-4", 64, vec![Message::user("ping")]);

        let response = client.send(&api_key_credential(), &request).await.unwrap();

        assert_eq!(response.id, "msg_42");
        assert_eq!(response.model, "claude-opus-4");
        assert_eq!(response.text(), "pong");
        assert_eq!(response.stop_reason.as_deref(), Some("end_turn"));
        assert_eq!(response.usage.input_tokens, 11);
        assert_eq!(response.usage.output_tokens, 3);

        let raw = requests.lock().unwrap();
        assert_eq!(raw.len(), 1);
        let sent = &raw[0];
        assert!(
            sent.starts_with("POST /v1/messages "),
            "request line: {sent}"
        );
        assert!(sent.contains(&format!("x-api-key: {TEST_API_KEY}")));
        assert!(sent.contains("content-type: application/json"));
        assert!(sent.contains("anthropic-version: 2023-06-01"));
        // A non-streaming request leaves `stream` off the wire entirely.
        assert!(sent.contains(r#""model":"claude-opus-4""#));
        assert!(!sent.contains(r#""stream":true"#));
    }

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn send_maps_a_client_error_status_to_a_permanent_endpoint_error_and_redacts_the_key() {
        // The server echoes the caller's API key back in the body; it must never
        // survive into the error the caller can log.
        let body: &'static str = concat!(
            r#"{"error":{"type":"invalid_request_error","message":"bad"},"#,
            r#""leaked":"sk-ant-api01-abcdefghijklmnopqrstuvwxyz012345"}"#
        );
        let (base, _requests) = mock_messages_server(400, body).await;
        let client = MessagesClient::new(endpoints_at(&base));
        let request = MessagesRequest::new("claude-x", 16, vec![Message::user("hi")]);

        let error = client
            .send(&api_key_credential(), &request)
            .await
            .unwrap_err();

        match error {
            Error::Endpoint {
                status,
                permanent,
                error_code,
                body,
                ..
            } => {
                assert_eq!(status, 400);
                assert!(permanent, "400 is not retryable");
                assert_eq!(error_code.as_deref(), Some("invalid_request_error"));
                assert!(
                    !body.contains(TEST_API_KEY),
                    "the raw key leaked into the error body: {body}"
                );
                assert!(body.contains("sk-ant-***REDACTED***"));
            }
            other => panic!("expected an endpoint error, got {other:?}"),
        }
    }

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn stream_flips_the_stream_flag_and_returns_a_decodable_body_normal() {
        const STREAM_BODY: &str = concat!(
            "event: message_start\n",
            "data: {\"type\":\"message_start\"}\n\n",
            "event: content_block_delta\n",
            "data: {\"delta\":\"hi\"}\n\n",
        );
        let (base, requests) = mock_messages_server(200, STREAM_BODY).await;
        // Exercise the caller-provided-client constructor on this path.
        let client = MessagesClient::with_http(reqwest::Client::new(), endpoints_at(&base));
        // Built non-streaming on purpose: `stream` must set the flag itself.
        let request = MessagesRequest::new("claude-x", 32, vec![Message::user("hi")]);

        let response = client
            .stream(&api_key_credential(), &request)
            .await
            .unwrap();
        assert!(response.status().is_success());
        let text = response.text().await.unwrap();

        let mut decoder = SseDecoder::new();
        let events = decoder.push(&text);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event, "message_start");
        assert_eq!(events[1].event, "content_block_delta");
        assert_eq!(events[1].data, r#"{"delta":"hi"}"#);

        let raw = requests.lock().unwrap();
        assert!(
            raw[0].contains(r#""stream":true"#),
            "stream() must enable streaming on the wire: {}",
            raw[0]
        );
    }

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn stream_maps_an_oauth_401_to_a_transient_endpoint_error() {
        let (base, _requests) =
            mock_messages_server(401, r#"{"error":{"type":"authentication_error"}}"#).await;
        let client = MessagesClient::new(endpoints_at(&base));
        let request = MessagesRequest::new("claude-x", 32, vec![Message::user("hi")]);

        let error = client
            .stream(&live_oauth_credential(), &request)
            .await
            .unwrap_err();

        match error {
            Error::Endpoint {
                status,
                permanent,
                error_code,
                ..
            } => {
                assert_eq!(status, 401);
                // An OAuth 401 is recoverable by refreshing the token.
                assert!(!permanent);
                assert_eq!(error_code.as_deref(), Some("authentication_error"));
            }
            other => panic!("expected an endpoint error, got {other:?}"),
        }
    }

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn send_refuses_an_expired_oauth_credential_before_any_request_is_sent() {
        // A session past its refresh-token lifetime must be rejected locally;
        // the mock endpoint must see zero requests.
        let (base, requests) = mock_messages_server(200, "{}").await;
        let client = MessagesClient::new(endpoints_at(&base));
        let credential = Credential::Oauth(OAuthTokens {
            access: AccessToken::new("sk-ant-oat01-deadaccessdeadaccessdeadac"),
            refresh: RefreshToken::new("sk-ant-ort01-deadrefreshdeadrefreshdea"),
            expires_at: Utc.timestamp_opt(1_000_000_000, 0).unwrap(),
            refresh_expires_at: Some(Utc.timestamp_opt(1_000_000_100, 0).unwrap()),
            scopes: vec!["user:inference".into()],
            account: None,
            organization: None,
        });
        let request = MessagesRequest::new("claude-x", 16, vec![Message::user("hi")]);

        let error = client.send(&credential, &request).await.unwrap_err();

        assert!(matches!(error, Error::RefreshTokenExpired), "got {error:?}");
        assert!(
            requests.lock().unwrap().is_empty(),
            "no request should reach the endpoint"
        );
    }

    #[cfg(feature = "client")]
    #[test]
    fn api_error_classifies_client_errors_as_permanent() {
        let headers = reqwest::header::HeaderMap::new();
        for status in [400u16, 403, 404, 422] {
            let error = api_error(status, &headers, r#"{"error":"bad_request"}"#.into(), false);
            match error {
                Error::Endpoint {
                    status: got,
                    permanent,
                    error_code,
                    ..
                } => {
                    assert_eq!(got, status);
                    assert!(permanent, "status {status} should be permanent");
                    assert_eq!(error_code.as_deref(), Some("bad_request"));
                }
                other => panic!("expected an endpoint error, got {other:?}"),
            }
        }
    }

    #[cfg(feature = "client")]
    #[test]
    fn api_error_classifies_server_and_throttle_errors_as_transient_with_retry_after() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "retry-after-ms",
            reqwest::header::HeaderValue::from_static("2500"),
        );
        let throttled = api_error(
            429,
            &headers,
            r#"{"error":{"type":"rate_limit_error"}}"#.into(),
            false,
        );
        match throttled {
            Error::Endpoint {
                status,
                permanent,
                error_code,
                retry_after_ms,
                ..
            } => {
                assert_eq!(status, 429);
                assert!(!permanent);
                assert_eq!(error_code.as_deref(), Some("rate_limit_error"));
                assert_eq!(retry_after_ms, Some(2500));
            }
            other => panic!("expected an endpoint error, got {other:?}"),
        }

        // 5xx statuses are transient and carry no retry hint here.
        let empty = reqwest::header::HeaderMap::new();
        for status in [500u16, 503] {
            let error = api_error(status, &empty, "upstream".into(), false);
            match error {
                Error::Endpoint {
                    permanent,
                    retry_after_ms,
                    ..
                } => {
                    assert!(!permanent, "status {status} should be transient");
                    assert_eq!(retry_after_ms, None);
                }
                other => panic!("expected an endpoint error, got {other:?}"),
            }
        }
    }
}
