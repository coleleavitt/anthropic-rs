//! Native Claude credential import and pluggable secure secret storage.

mod file;
#[cfg(feature = "secure-store")]
mod keyring;

use std::path::{Path, PathBuf};

use chrono::{TimeZone, Utc};
pub use file::FileSecretStore;
#[cfg(feature = "secure-store")]
pub use keyring::KeyringSecretStore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::error::{Error, Result};
use crate::token::{
    AccessToken, MAX_TOKEN_LEN, OAuthTokens, RefreshToken, is_valid_access_token,
    is_valid_refresh_token,
};

const MAX_NATIVE_DOCUMENT_BYTES: u64 = 64 * 1024;
const MAX_TRUSTED_DEVICE_TOKEN_BYTES: usize = 16 * 1024;

/// Production secure-storage service name used by native Claude Code.
pub const NATIVE_CLAUDE_KEYRING_SERVICE: &str = "Claude Code";

/// Derive native Claude's production secure-storage service name. A custom
/// config directory adds the same first-eight-hex SHA-256 suffix as Claude Code;
/// the default `~/.claude` directory uses the unsuffixed service.
pub fn native_claude_keyring_service() -> String {
    let custom_directory = match std::env::var_os("CLAUDE_SECURESTORAGE_CONFIG_DIR") {
        Some(value) if value.is_empty() => None,
        Some(value) => Some(PathBuf::from(value)),
        None => std::env::var_os("CLAUDE_CONFIG_DIR")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from),
    };
    let Some(directory) = custom_directory else {
        return NATIVE_CLAUDE_KEYRING_SERVICE.into();
    };
    let normalized = directory.to_string_lossy().nfc().collect::<String>();
    let digest = Sha256::digest(normalized.as_bytes());
    let suffix = digest[..4]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{NATIVE_CLAUDE_KEYRING_SERVICE}-{suffix}")
}

/// Minimal interface used for OAuth, API-key, trusted-device-token, and private-key secrets.
pub trait SecretStore: Send + Sync {
    /// Read a secret by stable opaque key.
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    /// Atomically replace a secret.
    fn put(&self, key: &str, value: &[u8]) -> Result<()>;
    /// Delete a secret if present.
    fn delete(&self, key: &str) -> Result<()>;
}

/// Where a read-only native Claude credential snapshot was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeClaudeCredentialSource {
    /// An operating-system credential vault entry.
    SecureStorage {
        /// Native Claude service name.
        service: String,
        /// Native Claude account/user name.
        account: String,
    },
    /// The native plaintext fallback file.
    CredentialsFile(PathBuf),
}

/// Native trusted-device token found alongside Claude OAuth credentials.
///
/// This auxiliary secret is intentionally not part of [`OAuthTokens`] and must
/// never be written to the shared account JSON document.
#[derive(Clone, PartialEq, Eq)]
pub struct NativeTrustedDeviceToken(String);

impl NativeTrustedDeviceToken {
    fn parse(value: String) -> Result<Self> {
        if value.is_empty() || value.len() > MAX_TRUSTED_DEVICE_TOKEN_BYTES {
            return Err(Error::Protocol(
                "native trusted-device token length is invalid".into(),
            ));
        }
        Ok(Self(value))
    }

    /// Deliberately expose the token for migration into an auxiliary secret
    /// store or a trusted-device request.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for NativeTrustedDeviceToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("NativeTrustedDeviceToken(***)")
    }
}

/// Native Claude Code credential discovery and import result.
#[derive(Debug, Clone)]
pub struct NativeClaudeImport {
    /// Imported OAuth token set.
    pub tokens: OAuthTokens,
    /// Subscription label retained for display only.
    pub subscription_type: Option<String>,
    /// Rate-limit tier retained for display only.
    pub rate_limit_tier: Option<String>,
    /// OAuth client id associated with the native token.
    pub client_id: Option<String>,
    /// Optional Remote Control/Cowork token. Keep this in a secret store, never
    /// in the project-neutral account document.
    pub trusted_device_token: Option<NativeTrustedDeviceToken>,
    /// Source snapshot. The importer never modifies it.
    pub source: NativeClaudeCredentialSource,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NativeDocument {
    claude_ai_oauth: Option<NativeOauth>,
    #[serde(default)]
    trusted_device_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NativeOauth {
    access_token: String,
    refresh_token: String,
    expires_at: i64,
    #[serde(default)]
    refresh_token_expires_at: Option<i64>,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    subscription_type: Option<String>,
    #[serde(default)]
    rate_limit_tier: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
}

/// Resolve Claude Code's plaintext fallback credential path.
pub fn native_claude_credentials_path() -> PathBuf {
    if let Some(directory) = std::env::var_os("CLAUDE_SECURESTORAGE_CONFIG_DIR") {
        let directory = if directory.is_empty() {
            default_claude_directory()
        } else {
            PathBuf::from(directory)
        };
        return directory.join(".credentials.json");
    }
    if let Some(directory) = std::env::var_os("CLAUDE_CONFIG_DIR").filter(|value| !value.is_empty())
    {
        return PathBuf::from(directory).join(".credentials.json");
    }
    default_claude_directory().join(".credentials.json")
}

fn default_claude_directory() -> PathBuf {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .unwrap_or_else(|| ".".into());
    PathBuf::from(home).join(".claude")
}

/// Native Claude's secure-storage account name. Unsafe characters fall back to
/// the same fixed account used by the official client.
pub fn native_claude_keyring_account() -> String {
    let candidate = std::env::var("USER")
        .ok()
        .or_else(|| std::env::var("USERNAME").ok())
        .unwrap_or_else(|| "claude-code-user".into());
    if !candidate.is_empty()
        && candidate
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        candidate
    } else {
        "claude-code-user".into()
    }
}

/// Read a native Claude credential snapshot from the plaintext fallback without
/// taking refresh ownership or modifying the source file.
pub fn import_native_claude_file(path: Option<&Path>) -> Result<NativeClaudeImport> {
    let path = path
        .map(Path::to_path_buf)
        .unwrap_or_else(native_claude_credentials_path);
    let raw = crate::file_security::read_bounded_regular(
        &path,
        MAX_NATIVE_DOCUMENT_BYTES,
        true,
        "native credential file",
    )?;
    parse_native_document(&raw, NativeClaudeCredentialSource::CredentialsFile(path))
}

/// Read native Claude credentials from its operating-system credential-vault
/// item. `None` means the vault contained no matching entry.
#[cfg(feature = "secure-store")]
pub fn import_native_claude_keyring(
    service: Option<&str>,
    account: Option<&str>,
) -> Result<Option<NativeClaudeImport>> {
    let service = service
        .map(str::to_owned)
        .unwrap_or_else(native_claude_keyring_service);
    let account = account
        .map(str::to_owned)
        .unwrap_or_else(native_claude_keyring_account);
    let store = KeyringSecretStore::new(&service);
    let Some(raw) = store.get(&account)? else {
        return Ok(None);
    };
    parse_native_document(
        &raw,
        NativeClaudeCredentialSource::SecureStorage {
            service: service.to_owned(),
            account,
        },
    )
    .map(Some)
}

/// Discover native Claude credentials in native order: operating-system secure
/// storage on platforms where Claude Code uses it, then the plaintext fallback.
/// A malformed secure value is returned as an error rather than silently
/// falling through to a potentially stale file.
pub fn discover_native_claude_credentials(path: Option<&Path>) -> Result<NativeClaudeImport> {
    #[cfg(all(
        feature = "secure-store",
        any(target_os = "macos", target_os = "windows")
    ))]
    {
        let service = native_claude_keyring_service();
        let account = native_claude_keyring_account();
        let store = KeyringSecretStore::new(&service);
        match store.get(&account) {
            Ok(Some(raw)) => {
                return parse_native_document(
                    &raw,
                    NativeClaudeCredentialSource::SecureStorage {
                        service: service.to_owned(),
                        account,
                    },
                );
            }
            Ok(None) => {}
            Err(error) => return Err(error),
        }
    }
    import_native_claude_file(path)
}

fn parse_native_document(
    raw: &[u8],
    source: NativeClaudeCredentialSource,
) -> Result<NativeClaudeImport> {
    if raw.len() as u64 > MAX_NATIVE_DOCUMENT_BYTES {
        return Err(Error::Protocol(
            "native credential document exceeds 64 KiB".into(),
        ));
    }
    let document: NativeDocument = serde_json::from_slice(raw)?;
    let oauth = document.claude_ai_oauth.ok_or_else(|| {
        Error::Protocol("native credential document has no claudeAiOauth entry".into())
    })?;
    if oauth.access_token.len() > MAX_TOKEN_LEN || !is_valid_access_token(&oauth.access_token) {
        return Err(Error::MalformedTokenResponse("access_token"));
    }
    if oauth.refresh_token.len() > MAX_TOKEN_LEN || !is_valid_refresh_token(&oauth.refresh_token) {
        return Err(Error::MalformedTokenResponse("refresh_token"));
    }
    let expires_at = Utc
        .timestamp_millis_opt(oauth.expires_at)
        .single()
        .ok_or_else(|| Error::Protocol("native access-token expiry is invalid".into()))?;
    let refresh_expires_at = oauth
        .refresh_token_expires_at
        .map(|value| {
            Utc.timestamp_millis_opt(value)
                .single()
                .ok_or_else(|| Error::Protocol("native refresh-token expiry is invalid".into()))
        })
        .transpose()?;
    let trusted_device_token = document
        .trusted_device_token
        .map(NativeTrustedDeviceToken::parse)
        .transpose()?;
    if !oauth.scopes.is_empty() && !crate::endpoints::grants_inference(&oauth.scopes) {
        return Err(Error::MalformedTokenResponse(
            "granted scopes lack user:inference",
        ));
    }
    Ok(NativeClaudeImport {
        tokens: OAuthTokens {
            access: AccessToken::new(oauth.access_token),
            refresh: RefreshToken::new(oauth.refresh_token),
            expires_at,
            refresh_expires_at,
            scopes: oauth.scopes,
            account: None,
            organization: None,
        },
        subscription_type: oauth.subscription_type,
        rate_limit_tier: oauth.rate_limit_tier,
        client_id: oauth.client_id,
        trusted_device_token,
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCESS: &str = "sk-ant-oat01-abcdefghijklmnopqrstuvwxyz012345";
    const REFRESH: &str = "sk-ant-ort01-abcdefghijklmnopqrstuvwxyz012345";

    fn temporary_directory(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("anthropic-native-{tag}-{}", uuid::Uuid::new_v4()))
    }

    fn native_json() -> String {
        format!(
            r#"{{"claudeAiOauth":{{"accessToken":"{ACCESS}","refreshToken":"{REFRESH}","expiresAt":1700000000000,"refreshTokenExpiresAt":1800000000000,"scopes":["user:inference"],"subscriptionType":"max","rateLimitTier":"tier","clientId":"client"}},"trustedDeviceToken":"trusted-secret","mcpOAuth":{{"must":"not import"}}}}"#
        )
    }

    #[test]
    fn native_import_rejects_scope_sets_without_inference() {
        let raw = format!(
            r#"{{"claudeAiOauth":{{"accessToken":"{ACCESS}","refreshToken":"{REFRESH}","expiresAt":1700000000000,"scopes":["user:profile"]}}}}"#
        );
        let error = parse_native_document(
            raw.as_bytes(),
            NativeClaudeCredentialSource::CredentialsFile(PathBuf::from("/tmp/native.json")),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            Error::MalformedTokenResponse("granted scopes lack user:inference")
        ));
    }

    #[test]
    fn imports_native_camel_case_document_read_only() {
        let root = temporary_directory("read-only");
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join(".credentials.json");
        let original = native_json();
        std::fs::write(&path, &original).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let imported = import_native_claude_file(Some(&path)).unwrap();
        assert_eq!(imported.tokens.access.expose(), ACCESS);
        assert_eq!(imported.tokens.refresh.expose(), REFRESH);
        assert!(imported.tokens.refresh_expires_at.is_some());
        assert_eq!(
            imported.trusted_device_token.as_ref().unwrap().expose(),
            "trusted-secret"
        );
        assert_eq!(
            imported.source,
            NativeClaudeCredentialSource::CredentialsFile(path.clone())
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn native_debug_redacts_all_secret_material() {
        let imported = parse_native_document(
            native_json().as_bytes(),
            NativeClaudeCredentialSource::CredentialsFile("test".into()),
        )
        .unwrap();
        let debug = format!("{imported:?}");
        assert!(!debug.contains(ACCESS));
        assert!(!debug.contains(REFRESH));
        assert!(!debug.contains("trusted-secret"));
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_or_public_native_files() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let root = temporary_directory("permissions");
        std::fs::create_dir_all(&root).unwrap();
        let real = root.join("real.json");
        std::fs::write(&real, native_json()).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            import_native_claude_file(Some(&real)),
            Err(Error::Protocol(_))
        ));
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = root.join(".credentials.json");
        symlink(&real, &link).unwrap();
        assert!(matches!(
            import_native_claude_file(Some(&link)),
            Err(Error::StoreIsSymlink)
        ));
        let _ = std::fs::remove_dir_all(root);
    }
}
