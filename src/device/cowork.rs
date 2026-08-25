use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, Utc};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::rand_core::OsRng;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::device::validate_device_base_url;
use crate::endpoints::{BASE_API_URL, OAUTH_BETA};
use crate::error::{Error, Result, redacted_response_body};
use crate::token::{AccessToken, redact_secrets};

const BIND_DOMAIN: &[u8] = b"anthropic.ccr.create_session_bind.v1";

/// Software P-256 key used for Cowork remote-device binding.
pub struct CoworkDeviceKey(SigningKey);

impl CoworkDeviceKey {
    /// Generate a fresh key with the operating-system CSPRNG.
    pub fn generate() -> Self {
        Self(SigningKey::random(&mut OsRng))
    }

    /// Restore a PKCS#8 DER key.
    pub fn from_pkcs8_der(bytes: &[u8]) -> Result<Self> {
        SigningKey::from_pkcs8_der(bytes)
            .map(Self)
            .map_err(|error| Error::Crypto(error.to_string()))
    }

    /// Encode the private key as PKCS#8 DER for secure-vault storage.
    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>> {
        self.0
            .to_pkcs8_der()
            .map(|document| document.as_bytes().to_vec())
            .map_err(|error| Error::Crypto(error.to_string()))
    }

    /// Persist the PKCS#8 private key in an auxiliary secret store. The
    /// temporary encoding is overwritten before it is dropped.
    pub fn store(&self, secrets: &dyn crate::credentials::SecretStore, key: &str) -> Result<()> {
        let mut encoded = self.to_pkcs8_der()?;
        let result = secrets.put(key, &encoded);
        encoded.fill(0);
        result
    }

    /// Restore a private key from an auxiliary secret store.
    pub fn load(secrets: &dyn crate::credentials::SecretStore, key: &str) -> Result<Option<Self>> {
        let Some(mut encoded) = secrets.get(key)? else {
            return Ok(None);
        };
        let result = Self::from_pkcs8_der(&encoded).map(Some);
        encoded.fill(0);
        result
    }

    /// Standard Base64 of DER SubjectPublicKeyInfo, matching native registration.
    pub fn public_key_spki_base64(&self) -> Result<String> {
        self.0
            .verifying_key()
            .to_public_key_der()
            .map(|document| STANDARD.encode(document.as_bytes()))
            .map_err(|error| Error::Crypto(error.to_string()))
    }

    /// Sign a create-session binding with fixed 64-byte IEEE-P1363 encoding.
    pub fn sign_binding(
        &self,
        organization_uuid: Uuid,
        account_uuid: Uuid,
        device_uuid: Uuid,
        issued_at: DateTime<Utc>,
    ) -> Result<CreateSessionBinding> {
        let timestamp_ms = issued_at.timestamp_millis();
        if timestamp_ms < 0 {
            return Err(Error::Protocol(
                "binding timestamp predates Unix epoch".into(),
            ));
        }
        let preimage = build_bind_preimage(
            organization_uuid,
            account_uuid,
            device_uuid,
            timestamp_ms as u64,
        );
        let signature: Signature = self.0.sign(&preimage);
        Ok(CreateSessionBinding {
            device_uuid,
            kid: format!("creg_{device_uuid}"),
            signature: STANDARD.encode(signature.to_bytes()),
            issued_at,
        })
    }
}

/// Build the exact domain-separated native bind preimage.
pub fn build_bind_preimage(
    organization_uuid: Uuid,
    account_uuid: Uuid,
    device_uuid: Uuid,
    timestamp_ms: u64,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(BIND_DOMAIN.len() + 56);
    bytes.extend_from_slice(BIND_DOMAIN);
    bytes.extend_from_slice(organization_uuid.as_bytes());
    bytes.extend_from_slice(account_uuid.as_bytes());
    bytes.extend_from_slice(device_uuid.as_bytes());
    bytes.extend_from_slice(&timestamp_ms.to_be_bytes());
    bytes
}

/// Signed native create-session binder.
#[derive(Debug, Clone)]
pub struct CreateSessionBinding {
    /// Registered remote-device UUID.
    device_uuid: Uuid,
    /// Key id (`creg_<device UUID>`).
    kid: String,
    /// Standard-Base64 64-byte P1363 ECDSA signature.
    signature: String,
    /// RFC3339 timestamp matching the preimage millisecond timestamp.
    issued_at: DateTime<Utc>,
}

impl CreateSessionBinding {
    /// Registered remote-device UUID.
    pub fn device_uuid(&self) -> Uuid {
        self.device_uuid
    }

    /// Native key identifier (`creg_<device UUID>`).
    pub fn key_id(&self) -> &str {
        &self.kid
    }

    /// Standard-Base64 64-byte P1363 signature.
    pub fn signature(&self) -> &str {
        &self.signature
    }

    /// Timestamp used for both the signed preimage and request body.
    pub fn issued_at(&self) -> DateTime<Utc> {
        self.issued_at
    }

    /// Fields inserted into the v1/code/sessions create body.
    pub fn body_fields(&self) -> serde_json::Value {
        serde_json::json!({
            "target_device_id": self.device_uuid,
            "bind_attestation": {
                "kid": self.kid,
                "signature": self.signature,
            },
            "bind_attestation_issued_at": self.issued_at.to_rfc3339_opts(
                chrono::SecondsFormat::Millis,
                true,
            ),
        })
    }
}

#[derive(Serialize)]
struct RegistrationRequest<'a> {
    display_name: &'a str,
    platform: &'a str,
    public_key: &'a str,
}

#[derive(Deserialize)]
struct RegistrationResponse {
    id: String,
    #[serde(default)]
    revoked_at: Option<serde_json::Value>,
}

/// Registered Cowork remote device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredCoworkDevice {
    /// Lowercase UUID returned by the server.
    pub device_uuid: Uuid,
}

/// Native platform literal sent during Cowork remote-device registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoworkPlatform {
    /// Node/Bun `process.platform === "linux"`.
    Linux,
    /// Node/Bun `process.platform === "darwin"`.
    MacOs,
    /// Node/Bun `process.platform === "win32"`.
    Windows,
}

impl CoworkPlatform {
    /// Exact native wire literal.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::MacOs => "darwin",
            Self::Windows => "win32",
        }
    }

    /// Current supported host platform.
    pub fn current() -> Result<Self> {
        if cfg!(target_os = "linux") {
            Ok(Self::Linux)
        } else if cfg!(target_os = "macos") {
            Ok(Self::MacOs)
        } else if cfg!(target_os = "windows") {
            Ok(Self::Windows)
        } else {
            Err(Error::Protocol(
                "Cowork registration does not define a native platform literal for this OS".into(),
            ))
        }
    }
}

/// Cowork remote-device registration client.
pub struct CoworkDeviceClient {
    http: reqwest::Client,
    base_url: String,
}

impl CoworkDeviceClient {
    /// Production client.
    pub fn prod() -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: BASE_API_URL.to_owned(),
        }
    }

    /// Client with injected transport/base URL. Plain HTTP is accepted only on
    /// loopback so an OAuth bearer cannot be sent to a cleartext remote origin.
    pub fn new(http: reqwest::Client, base_url: impl Into<String>) -> Result<Self> {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        validate_device_base_url(&base_url)?;
        Ok(Self { http, base_url })
    }

    /// Register a P-256 public key for an account in an organization.
    pub async fn register(
        &self,
        access: &AccessToken,
        organization_uuid: Uuid,
        display_name: &str,
        platform: CoworkPlatform,
        key: &CoworkDeviceKey,
    ) -> Result<RegisteredCoworkDevice> {
        let display_name = display_name.trim();
        if display_name.is_empty() || display_name.len() > 255 {
            return Err(Error::Protocol(
                "Cowork device display name is invalid".into(),
            ));
        }
        let public_key = key.public_key_spki_base64()?;
        let response = self
            .http
            .post(format!(
                "{}/api/organizations/{organization_uuid}/cowork/remote_devices",
                self.base_url
            ))
            .header("authorization", format!("Bearer {}", access.expose()))
            .header("anthropic-beta", OAUTH_BETA)
            .json(&RegistrationRequest {
                display_name,
                platform: platform.as_str(),
                public_key: &public_key,
            })
            .send()
            .await?;
        let status = response.status();
        if status.as_u16() != 201 {
            let body = redacted_response_body(response, &[access.expose()]).await;
            return Err(Error::Endpoint {
                status: status.as_u16(),
                permanent: matches!(status.as_u16(), 400 | 401 | 403 | 404),
                error_code: None,
                retry_after_ms: None,
                body: redact_secrets(&body),
            });
        }
        let body: RegistrationResponse = response.json().await?;
        if body.revoked_at.is_some() {
            return Err(Error::Protocol("Cowork device key is revoked".into()));
        }
        let device_uuid = Uuid::parse_str(&body.id)
            .map_err(|_| Error::Protocol("Cowork registration returned an invalid UUID".into()))?;
        Ok(RegisteredCoworkDevice { device_uuid })
    }
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::signature::Verifier;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;
    use crate::credentials::{FileSecretStore, SecretStore};

    #[test]
    fn preimage_is_domain_plus_three_uuids_plus_u64_be() {
        let org = Uuid::parse_str("11111111-2222-4333-8444-555555555555").unwrap();
        let account = Uuid::parse_str("66666666-7777-4888-9999-aaaaaaaaaaaa").unwrap();
        let device = Uuid::parse_str("bbbbbbbb-cccc-4ddd-8eee-ffffffffffff").unwrap();
        let bytes = build_bind_preimage(org, account, device, 0x0102030405060708);
        assert_eq!(&bytes[..BIND_DOMAIN.len()], BIND_DOMAIN);
        assert_eq!(
            &bytes[bytes.len() - 8..],
            &0x0102030405060708u64.to_be_bytes()
        );
        assert_eq!(bytes.len(), BIND_DOMAIN.len() + 56);
    }

    #[test]
    fn fixed_key_binding_matches_golden_signature() {
        let key = CoworkDeviceKey(SigningKey::from_slice(&[1u8; 32]).unwrap());
        let issued = DateTime::from_timestamp_millis(1_700_000_000_123).unwrap();
        let org = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        let account = Uuid::parse_str("10213243-5465-7687-98a9-bacbdcedfe0f").unwrap();
        let device = Uuid::parse_str("ffeeddcc-bbaa-4988-b766-554433221100").unwrap();
        let binding = key.sign_binding(org, account, device, issued).unwrap();
        assert_eq!(
            binding.signature(),
            "tweEdflT2rE8cHj6ppZPpUZOTLuJimnXKskJm1tlLlwHo27O10QnYRA3hsingbiE2Fa3dMrCTw6Mn6Is92L03Q=="
        );
    }

    #[test]
    fn p1363_signature_verifies_and_pkcs8_round_trips() {
        let key = CoworkDeviceKey::generate();
        let restored = CoworkDeviceKey::from_pkcs8_der(&key.to_pkcs8_der().unwrap()).unwrap();
        let issued = DateTime::from_timestamp_millis(1_700_000_000_000).unwrap();
        let org = Uuid::new_v4();
        let account = Uuid::new_v4();
        let device = Uuid::new_v4();
        let binding = restored.sign_binding(org, account, device, issued).unwrap();
        let signature_bytes = STANDARD.decode(&binding.signature).unwrap();
        assert_eq!(signature_bytes.len(), 64);
        let signature = Signature::from_slice(&signature_bytes).unwrap();
        restored
            .0
            .verifying_key()
            .verify(
                &build_bind_preimage(org, account, device, issued.timestamp_millis() as u64),
                &signature,
            )
            .unwrap();
        assert_eq!(binding.kid, format!("creg_{device}"));
        assert_eq!(
            binding.body_fields(),
            serde_json::json!({
                "target_device_id": device,
                "bind_attestation": {
                    "kid": format!("creg_{device}"),
                    "signature": binding.signature,
                },
                "bind_attestation_issued_at": "2023-11-14T22:13:20.000Z",
            })
        );

        let root =
            std::env::temp_dir().join(format!("anthropic-cowork-key-{}", uuid::Uuid::new_v4()));
        let secrets = FileSecretStore::new(&root);
        restored.store(&secrets, "cowork:account").unwrap();
        let loaded = CoworkDeviceKey::load(&secrets, "cowork:account")
            .unwrap()
            .unwrap();
        assert_eq!(
            loaded.public_key_spki_base64().unwrap(),
            restored.public_key_spki_base64().unwrap()
        );
        secrets.delete("cowork:account").unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    async fn serve_registration_once(device: Uuid) -> (String, tokio::task::JoinHandle<String>) {
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
            let body = serde_json::json!({ "id": device, "revoked_at": null }).to_string();
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
    async fn registration_uses_exact_endpoint_headers_and_spki_body() {
        let organization = Uuid::parse_str("11111111-2222-4333-8444-555555555555").unwrap();
        let device = Uuid::parse_str("bbbbbbbb-cccc-4ddd-8eee-ffffffffffff").unwrap();
        let (base_url, request) = serve_registration_once(device).await;
        let key = CoworkDeviceKey::generate();
        let expected_public_key = key.public_key_spki_base64().unwrap();
        let client = CoworkDeviceClient::new(reqwest::Client::new(), base_url).unwrap();
        let registered = client
            .register(
                &AccessToken::new("sk-ant-oat01-abcdefghijklmnopqrstuvwxyz012345"),
                organization,
                "Workstation",
                CoworkPlatform::Linux,
                &key,
            )
            .await
            .unwrap();
        assert_eq!(registered.device_uuid, device);
        let request = request.await.unwrap();
        let (headers, body) = request.split_once("\r\n\r\n").unwrap();
        assert!(headers.starts_with(&format!(
            "POST /api/organizations/{organization}/cowork/remote_devices HTTP/1.1"
        )));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("anthropic-beta: oauth-2025-04-20"));
        assert!(
            lower.contains("authorization: bearer sk-ant-oat01-abcdefghijklmnopqrstuvwxyz012345")
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(body).unwrap(),
            serde_json::json!({
                "display_name": "Workstation",
                "platform": "linux",
                "public_key": expected_public_key,
            })
        );
    }

    #[test]
    fn refuses_cleartext_remote_base_urls() {
        assert!(CoworkDeviceClient::new(reqwest::Client::new(), "http://example.com").is_err());
    }
}
