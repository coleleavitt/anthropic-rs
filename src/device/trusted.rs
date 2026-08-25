use serde::{Deserialize, Serialize};

use crate::device::validate_device_base_url;
use crate::endpoints::BASE_API_URL;
use crate::error::{Error, Result, redacted_response_body};
use crate::token::{AccessToken, redact_secrets};

/// Native environment override for trusted-device authentication.
pub const TRUSTED_DEVICE_TOKEN_ENV: &str = "CLAUDE_TRUSTED_DEVICE_TOKEN";

/// Opaque token returned by trusted-device enrollment. Redacted from `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct TrustedDeviceToken(String);

impl TrustedDeviceToken {
    /// Wrap an opaque server token.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty() || value.len() > 16 * 1024 {
            return Err(Error::Protocol(
                "trusted-device token length is invalid".into(),
            ));
        }
        Ok(Self(value))
    }

    /// Deliberately expose the token for an authenticated Remote Control request.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Persist this token in an auxiliary secret store, outside account JSON.
    pub fn store(&self, secrets: &dyn crate::credentials::SecretStore, key: &str) -> Result<()> {
        secrets.put(key, self.0.as_bytes())
    }

    /// Restore a token from an auxiliary secret store.
    pub fn load(secrets: &dyn crate::credentials::SecretStore, key: &str) -> Result<Option<Self>> {
        let Some(raw) = secrets.get(key)? else {
            return Ok(None);
        };
        let value = String::from_utf8(raw)
            .map_err(|_| Error::Protocol("trusted-device token is not UTF-8".into()))?;
        Self::new(value).map(Some)
    }

    /// Remove a persisted trusted-device token.
    pub fn delete(secrets: &dyn crate::credentials::SecretStore, key: &str) -> Result<()> {
        secrets.delete(key)
    }
}

/// Resolve the native environment override without touching persistent state.
pub fn trusted_device_token_from_env() -> Result<Option<TrustedDeviceToken>> {
    std::env::var(TRUSTED_DEVICE_TOKEN_ENV)
        .ok()
        .filter(|value| !value.is_empty())
        .map(TrustedDeviceToken::new)
        .transpose()
}

impl std::fmt::Debug for TrustedDeviceToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TrustedDeviceToken(***)")
    }
}

/// Successful trusted-device enrollment response.
#[derive(Debug, Clone)]
pub struct TrustedDeviceEnrollment {
    /// Opaque header token.
    pub token: TrustedDeviceToken,
    /// Optional server-side device identifier.
    pub device_id: Option<String>,
}

#[derive(Serialize)]
struct EnrollmentRequest<'a> {
    display_name: &'a str,
}

#[derive(Deserialize)]
struct EnrollmentResponse {
    device_token: String,
    #[serde(default)]
    device_id: Option<String>,
}

/// Client for the native trusted-device enrollment endpoint.
pub struct TrustedDeviceClient {
    http: reqwest::Client,
    base_url: String,
}

impl TrustedDeviceClient {
    /// Production client.
    pub fn prod() -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: BASE_API_URL.to_owned(),
        }
    }

    /// Client with an injected pool/base URL for tests or private deployments.
    /// Plain HTTP is accepted only on loopback so bearer tokens cannot be sent
    /// to a cleartext remote origin.
    pub fn new(http: reqwest::Client, base_url: impl Into<String>) -> Result<Self> {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        validate_device_base_url(&base_url)?;
        Ok(Self { http, base_url })
    }

    /// Enroll this machine and return the opaque trusted-device token.
    pub async fn enroll(
        &self,
        access: &AccessToken,
        display_name: &str,
    ) -> Result<TrustedDeviceEnrollment> {
        let display_name = display_name.trim();
        if display_name.is_empty() || display_name.len() > 255 {
            return Err(Error::Protocol(
                "trusted-device display name is invalid".into(),
            ));
        }
        let response = self
            .http
            .post(format!("{}/api/auth/trusted_devices", self.base_url))
            .header("authorization", format!("Bearer {}", access.expose()))
            .header("content-type", "application/json")
            .json(&EnrollmentRequest { display_name })
            .send()
            .await?;
        let status = response.status();
        if status.as_u16() != 200 && status.as_u16() != 201 {
            let body = redacted_response_body(response, &[access.expose()]).await;
            return Err(Error::Endpoint {
                status: status.as_u16(),
                permanent: status.as_u16() == 400
                    || status.as_u16() == 401
                    || status.as_u16() == 403,
                error_code: None,
                retry_after_ms: None,
                body: redact_secrets(&body),
            });
        }
        let body: EnrollmentResponse = response.json().await?;
        Ok(TrustedDeviceEnrollment {
            token: TrustedDeviceToken::new(body.device_token)?,
            device_id: body.device_id,
        })
    }
}

/// Add the opaque token to a Remote Control/Cowork request.
pub fn trusted_device_header(token: &TrustedDeviceToken) -> (&'static str, String) {
    ("X-Trusted-Device-Token", token.expose().to_owned())
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;
    use crate::credentials::{FileSecretStore, SecretStore};

    #[test]
    fn token_debug_is_redacted_and_secret_store_round_trips() {
        let token = TrustedDeviceToken::new("opaque-token").unwrap();
        assert_eq!(format!("{token:?}"), "TrustedDeviceToken(***)");
        assert_eq!(trusted_device_header(&token).0, "X-Trusted-Device-Token");

        let root =
            std::env::temp_dir().join(format!("anthropic-trusted-device-{}", uuid::Uuid::new_v4()));
        let store = FileSecretStore::new(&root);
        token.store(&store, "trusted:account").unwrap();
        assert_eq!(
            TrustedDeviceToken::load(&store, "trusted:account")
                .unwrap()
                .unwrap(),
            token
        );
        store.delete("trusted:account").unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    async fn serve_once() -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let header_end = loop {
                let mut chunk = [0u8; 1024];
                let read = stream.read(&mut chunk).await.unwrap();
                request.extend_from_slice(&chunk[..read]);
                if let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n")
                {
                    break position + 4;
                }
            };
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let lower = line.to_ascii_lowercase();
                    lower
                        .strip_prefix("content-length:")
                        .and_then(|value| value.trim().parse::<usize>().ok())
                })
                .unwrap();
            while request.len() < header_end + content_length {
                let mut chunk = [0u8; 1024];
                let read = stream.read(&mut chunk).await.unwrap();
                request.extend_from_slice(&chunk[..read]);
            }
            let body = r#"{"device_token":"trusted-token","device_id":"device-id"}"#;
            let response = format!(
                "HTTP/1.1 201 Created\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8(request).unwrap()
        });
        (format!("http://{address}"), handle)
    }

    #[tokio::test]
    async fn enroll_uses_exact_endpoint_header_and_body() {
        let (base_url, request) = serve_once().await;
        let client = TrustedDeviceClient::new(reqwest::Client::new(), base_url).unwrap();
        let enrolled = client
            .enroll(
                &AccessToken::new("sk-ant-oat01-abcdefghijklmnopqrstuvwxyz012345"),
                "Workstation",
            )
            .await
            .unwrap();
        assert_eq!(enrolled.token.expose(), "trusted-token");
        assert_eq!(enrolled.device_id.as_deref(), Some("device-id"));
        let request = request.await.unwrap();
        let (headers, body) = request.split_once("\r\n\r\n").unwrap();
        assert!(headers.starts_with("POST /api/auth/trusted_devices HTTP/1.1"));
        assert!(
            headers
                .to_ascii_lowercase()
                .contains("authorization: bearer sk-ant-oat01-abcdefghijklmnopqrstuvwxyz012345")
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(body).unwrap(),
            serde_json::json!({ "display_name": "Workstation" })
        );
    }

    #[test]
    fn refuses_cleartext_remote_base_urls() {
        assert!(TrustedDeviceClient::new(reqwest::Client::new(), "http://example.com").is_err());
    }
}
