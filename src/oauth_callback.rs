//! Loopback OAuth callback completion for interactive local logins.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Instant, timeout};

use crate::endpoints::Endpoints;
use crate::error::{Error, Result};
use crate::pkce::constant_time_eq;
use crate::{LoginStart, start_login};

const CALLBACK_PATH: &str = "/callback";
const MAX_REQUEST_BYTES: usize = 16 * 1024;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

/// A bound loopback listener plus the authorization URL and matching PKCE state.
pub struct LoopbackLogin {
    /// Authorization URL to open in the user's browser.
    pub authorize_url: url::Url,
    /// PKCE verifier required by the token exchange.
    pub verifier: crate::PkceVerifier,
    /// Anti-CSRF state embedded in the authorization request.
    pub state: String,
    /// Endpoint set whose redirect URI matches this listener.
    pub endpoints: Endpoints,
    listener: TcpListener,
    wait_timeout: Duration,
}

impl LoopbackLogin {
    /// Bind `127.0.0.1`, build the matching authorization URL, and return a
    /// pending one-shot callback flow.
    pub async fn bind(endpoints: &Endpoints, wait_timeout: Duration) -> Result<Self> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        let mut callback_endpoints = endpoints.clone();
        callback_endpoints.redirect_uri = format!("http://localhost:{port}{CALLBACK_PATH}");
        let LoginStart {
            authorize_url,
            verifier,
            state,
        } = start_login(&callback_endpoints)?;
        Ok(Self {
            authorize_url,
            verifier,
            state,
            endpoints: callback_endpoints,
            listener,
            wait_timeout,
        })
    }

    /// Wait for one valid callback and return its authorization code.
    pub async fn wait_for_code(self) -> Result<String> {
        let deadline = Instant::now() + self.wait_timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(Error::Callback(
                    "timed out waiting for browser callback".into(),
                ));
            }
            let (mut stream, _) = timeout(remaining, self.listener.accept())
                .await
                .map_err(|_| Error::Callback("timed out waiting for browser callback".into()))??;
            match read_callback(&mut stream, &self.state).await {
                Ok(CallbackOutcome::Code(code)) => {
                    write_response(
                        &mut stream,
                        200,
                        "Authentication complete. You may close this window.",
                    )
                    .await;
                    return Ok(code);
                }
                Ok(CallbackOutcome::Ignore(status, message)) => {
                    write_response(&mut stream, status, message).await;
                }
                Err(error) => {
                    write_response(&mut stream, 400, "Authentication callback rejected.").await;
                    return Err(error);
                }
            }
        }
    }
}

enum CallbackOutcome {
    Code(String),
    Ignore(u16, &'static str),
}

async fn read_callback(stream: &mut TcpStream, expected_state: &str) -> Result<CallbackOutcome> {
    let mut request = Vec::with_capacity(1024);
    loop {
        let remaining_capacity = MAX_REQUEST_BYTES.saturating_sub(request.len());
        if remaining_capacity == 0 {
            return Err(Error::Callback("callback request exceeded 16 KiB".into()));
        }
        let mut chunk = [0u8; 1024];
        let chunk_capacity = remaining_capacity.min(chunk.len());
        let read = timeout(
            CONNECTION_TIMEOUT,
            stream.read(&mut chunk[..chunk_capacity]),
        )
        .await
        .map_err(|_| Error::Callback("callback request read timed out".into()))??;
        if read == 0 {
            return Err(Error::Callback("callback connection closed early".into()));
        }
        request.extend_from_slice(&chunk[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }

    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut parsed = httparse::Request::new(&mut headers);
    parsed
        .parse(&request)
        .map_err(|error| Error::Callback(format!("invalid callback HTTP request: {error}")))?;
    if parsed.method != Some("GET") {
        return Ok(CallbackOutcome::Ignore(405, "Only GET is accepted."));
    }
    let target = parsed
        .path
        .ok_or_else(|| Error::Callback("callback request had no target".into()))?;
    let url = url::Url::parse(&format!("http://localhost{target}"))?;
    if url.path() != CALLBACK_PATH {
        return Ok(CallbackOutcome::Ignore(404, "Not found."));
    }
    let mut code = None;
    let mut state = None;
    let mut oauth_error = None;
    let mut error_description = None;
    for (name, value) in url.query_pairs() {
        let slot = match name.as_ref() {
            "code" => &mut code,
            "state" => &mut state,
            "error" => &mut oauth_error,
            "error_description" => &mut error_description,
            _ => continue,
        };
        if slot.replace(value.into_owned()).is_some() {
            return Err(Error::Callback(format!(
                "callback repeated the {name} parameter"
            )));
        }
    }
    let state = state.ok_or_else(|| Error::Callback("callback omitted state".into()))?;
    if !constant_time_eq(state.as_bytes(), expected_state.as_bytes()) {
        return Err(Error::StateMismatch);
    }
    if let Some(error) = oauth_error {
        let _ = error_description;
        return Err(Error::Callback(format!(
            "oauth {error}: authorization server rejected the request"
        )));
    }
    let code = code
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::Callback("callback omitted authorization code".into()))?;
    Ok(CallbackOutcome::Code(code))
}

async fn write_response(stream: &mut TcpStream, status: u16, message: &str) {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Bad Request",
    };
    let body =
        format!("<!doctype html><meta charset=utf-8><title>Claude OAuth</title><p>{message}</p>");
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;

    use super::*;

    #[tokio::test]
    async fn accepts_exact_callback_and_state() {
        let login = LoopbackLogin::bind(&Endpoints::prod(), Duration::from_secs(2))
            .await
            .unwrap();
        let state = login.state.clone();
        let address = login.listener.local_addr().unwrap();
        let waiter = tokio::spawn(login.wait_for_code());
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream
            .write_all(
                format!("GET /callback?code=abc&state={state} HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        assert_eq!(waiter.await.unwrap().unwrap(), "abc");
    }

    async fn send_request(address: std::net::SocketAddr, request: &[u8]) -> String {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(request).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut response = String::new();
        let _ = stream.read_to_string(&mut response).await;
        response
    }

    #[tokio::test]
    async fn rejects_wrong_state() {
        let login = LoopbackLogin::bind(&Endpoints::prod(), Duration::from_secs(2))
            .await
            .unwrap();
        let address = login.listener.local_addr().unwrap();
        let waiter = tokio::spawn(login.wait_for_code());
        let response = send_request(
            address,
            b"GET /callback?code=abc&state=wrong HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 400"));
        assert!(matches!(waiter.await.unwrap(), Err(Error::StateMismatch)));
    }

    #[tokio::test]
    async fn ignores_wrong_method_and_path_then_accepts_the_callback() {
        let login = LoopbackLogin::bind(&Endpoints::prod(), Duration::from_secs(2))
            .await
            .unwrap();
        let state = login.state.clone();
        let address = login.listener.local_addr().unwrap();
        let waiter = tokio::spawn(login.wait_for_code());

        let response = send_request(
            address,
            b"POST /callback HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 405"));
        let response =
            send_request(address, b"GET /wrong HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 404"));
        let response = send_request(
            address,
            format!("GET /callback?code=ok&state={state} HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .as_bytes(),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(response.contains("Content-Security-Policy: default-src 'none'"));
        assert_eq!(waiter.await.unwrap().unwrap(), "ok");
    }

    #[tokio::test]
    async fn rejects_duplicate_security_parameters() {
        let login = LoopbackLogin::bind(&Endpoints::prod(), Duration::from_secs(2))
            .await
            .unwrap();
        let state = login.state.clone();
        let address = login.listener.local_addr().unwrap();
        let waiter = tokio::spawn(login.wait_for_code());
        let request = format!(
            "GET /callback?code=abc&state={state}&state={state} HTTP/1.1\r\nHost: localhost\r\n\r\n"
        );
        let response = send_request(address, request.as_bytes()).await;
        assert!(response.starts_with("HTTP/1.1 400"));
        assert!(matches!(waiter.await.unwrap(), Err(Error::Callback(_))));
    }

    #[tokio::test]
    async fn bounds_request_size_and_total_wait() {
        let login = LoopbackLogin::bind(&Endpoints::prod(), Duration::from_secs(2))
            .await
            .unwrap();
        let address = login.listener.local_addr().unwrap();
        let waiter = tokio::spawn(login.wait_for_code());
        let oversized = format!(
            "GET /callback?{} HTTP/1.1\r\nHost: localhost\r\n\r\n",
            "x".repeat(MAX_REQUEST_BYTES)
        );
        let response = send_request(address, oversized.as_bytes()).await;
        assert!(response.starts_with("HTTP/1.1 400"));
        assert!(matches!(waiter.await.unwrap(), Err(Error::Callback(_))));

        let login = LoopbackLogin::bind(&Endpoints::prod(), Duration::from_millis(20))
            .await
            .unwrap();
        assert!(matches!(
            login.wait_for_code().await,
            Err(Error::Callback(_))
        ));
    }
}
