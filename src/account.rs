//! A single stored Anthropic account: its credential plus the routing metadata
//! needed to rotate between subscriptions (enabled/disabled, rate-limit
//! cooldown, last use, last error).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::token::{Credential, OAuthTokens};

/// Why an account is not currently usable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unavailable {
    /// The user (or a permanent auth failure) disabled it.
    Disabled,
    /// It is in a rate-limit cooldown until the given instant.
    RateLimited(DateTime<Utc>),
}

/// One credential the caller can route requests through.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    /// Stable key for this account within the store.
    pub id: String,
    /// Optional human label for pickers and logs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Account email, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// The credential itself.
    pub credential: Credential,
    /// Whether this account participates in routing.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// When the account was added.
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
    /// When a request last used it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,
    /// Cooldown end after a 429; the account is skipped until then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limited_until: Option<DateTime<Utc>>,
    /// Last error recorded against this account, already secret-redacted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

fn default_true() -> bool {
    true
}

fn oauth_email(tokens: &OAuthTokens) -> Option<String> {
    tokens
        .account
        .as_ref()
        .and_then(|account| account.email_address.clone())
}

impl Account {
    /// A new enabled account holding `credential`.
    pub fn new(id: impl Into<String>, credential: Credential) -> Self {
        let email = match &credential {
            Credential::Oauth(tokens) => oauth_email(tokens),
            Credential::ApiKey { .. } => None,
        };
        Self {
            id: id.into(),
            label: None,
            email,
            credential,
            enabled: true,
            created_at: Utc::now(),
            last_used_at: None,
            rate_limited_until: None,
            last_error: None,
        }
    }

    /// Attach a display label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Attach an email.
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    /// Why this account cannot serve a request at `now`, or `None` when it can.
    pub fn unavailable_reason(&self, now: DateTime<Utc>) -> Option<Unavailable> {
        if !self.enabled {
            return Some(Unavailable::Disabled);
        }
        match self.rate_limited_until {
            Some(until) if now < until => Some(Unavailable::RateLimited(until)),
            _ => None,
        }
    }

    /// Whether this account can serve a request at `now`.
    pub fn is_available(&self, now: DateTime<Utc>) -> bool {
        self.unavailable_reason(now).is_none()
    }

    /// Record a successful use.
    pub fn mark_used(&mut self, now: DateTime<Utc>) {
        self.last_used_at = Some(now);
        self.last_error = None;
    }

    /// Put the account into a rate-limit cooldown ending at `until`.
    pub fn mark_rate_limited(&mut self, until: DateTime<Utc>) {
        self.rate_limited_until = Some(until);
    }

    /// Clear any rate-limit cooldown.
    pub fn clear_rate_limit(&mut self) {
        self.rate_limited_until = None;
    }

    /// Disable the account and record why. The reason is stored redacted.
    pub fn disable(&mut self, reason: impl AsRef<str>) {
        self.enabled = false;
        self.last_error = Some(crate::token::redact_secrets(reason.as_ref()));
    }

    /// Re-enable the account and clear its cooldown and last error.
    pub fn enable(&mut self) {
        self.enabled = true;
        self.rate_limited_until = None;
        self.last_error = None;
    }

    /// Replace the stored OAuth session and synchronize derived account
    /// metadata from the token payload.
    pub fn replace_oauth_tokens(&mut self, tokens: OAuthTokens) -> Result<()> {
        let email = oauth_email(&tokens);
        let Credential::Oauth(current) = &mut self.credential else {
            return Err(Error::Protocol(format!(
                "account {} is not an OAuth account",
                self.id
            )));
        };
        *current = tokens;
        self.email = email;
        Ok(())
    }

    /// The display name for pickers: label, else email, else id.
    pub fn display_name(&self) -> &str {
        self.label
            .as_deref()
            .or(self.email.as_deref())
            .unwrap_or(&self.id)
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::token::{AccessToken, ApiKey, OAuthTokens, RefreshToken};

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0).unwrap()
    }

    fn api_account() -> Account {
        Account::new(
            "primary",
            Credential::ApiKey {
                key: ApiKey::new("sk-ant-api01-aaaaaaaaaaaaaaaaaaaaaa"),
            },
        )
    }

    #[test]
    fn new_account_is_available_normal() {
        let account = api_account();
        assert!(account.is_available(at(0)));
        assert_eq!(account.unavailable_reason(at(0)), None);
        assert_eq!(account.display_name(), "primary");
    }

    #[test]
    fn disabled_account_is_unavailable_and_redacts_reason_robust() {
        let mut account = api_account();
        account.disable("revoked token sk-ant-ort01-supersecretvaluehere1");
        assert_eq!(
            account.unavailable_reason(at(0)),
            Some(Unavailable::Disabled)
        );
        let err = account.last_error.as_deref().unwrap();
        assert!(
            !err.contains("supersecret"),
            "secret leaked into store: {err}"
        );
        assert!(err.contains("sk-ant-***REDACTED***"));
    }

    #[test]
    fn rate_limit_expires_on_its_own_normal() {
        let mut account = api_account();
        account.mark_rate_limited(at(100));
        assert_eq!(
            account.unavailable_reason(at(50)),
            Some(Unavailable::RateLimited(at(100)))
        );
        // At and past the cooldown end the account is usable again.
        assert!(account.is_available(at(100)));
        assert!(account.is_available(at(101)));
    }

    #[test]
    fn enable_clears_cooldown_and_error_normal() {
        let mut account = api_account();
        account.mark_rate_limited(at(100));
        account.disable("boom");
        account.enable();
        assert!(account.is_available(at(0)));
        assert!(account.last_error.is_none());
        assert!(account.rate_limited_until.is_none());
    }

    #[test]
    fn display_name_prefers_label_then_email_normal() {
        let mut account = api_account();
        assert_eq!(account.display_name(), "primary");
        account.email = Some("me@example.com".into());
        assert_eq!(account.display_name(), "me@example.com");
        account.label = Some("Work".into());
        assert_eq!(account.display_name(), "Work");
    }

    #[test]
    fn oauth_account_roundtrips_through_json_normal() {
        let account = Account::new(
            "oauth-1",
            Credential::Oauth(OAuthTokens {
                access: AccessToken::new("sk-ant-oat01-aaaaaaaaaaaaaaaaaaaaaa"),
                refresh: RefreshToken::new("sk-ant-ort01-aaaaaaaaaaaaaaaaaaaaaa"),
                expires_at: at(1_700_000_000),
                refresh_expires_at: Some(at(1_800_000_000)),
                scopes: vec!["user:inference".into()],
                account: None,
                organization: None,
            }),
        )
        .with_label("Personal");

        let json = serde_json::to_string(&account).unwrap();
        let back: Account = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "oauth-1");
        assert_eq!(back.label.as_deref(), Some("Personal"));
        assert!(back.credential.is_oauth());
        let Credential::Oauth(tokens) = &back.credential else {
            unreachable!("round-tripped OAuth account changed credential type");
        };
        assert_eq!(tokens.refresh_expires_at, Some(at(1_800_000_000)));
        assert!(back.enabled);
    }

    #[test]
    fn replacing_oauth_tokens_keeps_account_email_in_sync() {
        let mut account = Account::new(
            "oauth-1",
            Credential::Oauth(OAuthTokens {
                access: AccessToken::new("sk-ant-oat01-aaaaaaaaaaaaaaaaaaaaaa"),
                refresh: RefreshToken::new("sk-ant-ort01-aaaaaaaaaaaaaaaaaaaaaa"),
                expires_at: at(1_700_000_000),
                refresh_expires_at: Some(at(1_800_000_000)),
                scopes: vec!["user:profile".into(), "user:inference".into()],
                account: Some(crate::token::TokenAccount {
                    uuid: "acct".into(),
                    email_address: Some("first@example.com".into()),
                }),
                organization: None,
            }),
        );
        assert_eq!(account.email.as_deref(), Some("first@example.com"));
        account
            .replace_oauth_tokens(OAuthTokens {
                access: AccessToken::new("sk-ant-oat01-bbbbbbbbbbbbbbbbbbbbbb"),
                refresh: RefreshToken::new("sk-ant-ort01-bbbbbbbbbbbbbbbbbbbbbb"),
                expires_at: at(1_700_000_100),
                refresh_expires_at: Some(at(1_800_000_100)),
                scopes: vec!["user:profile".into(), "user:inference".into()],
                account: Some(crate::token::TokenAccount {
                    uuid: "acct".into(),
                    email_address: Some("second@example.com".into()),
                }),
                organization: None,
            })
            .unwrap();
        assert_eq!(account.email.as_deref(), Some("second@example.com"));
    }

    #[test]
    fn missing_enabled_field_defaults_to_true_robust() {
        // Older stores omit `enabled`; they must not silently become disabled.
        let json = r#"{
            "id": "legacy",
            "credential": { "type": "api_key", "0": "x" }
        }"#;
        // The tagged ApiKey variant serializes as a newtype; build the exact
        // shape serde emits instead of hand-guessing.
        let expected = serde_json::to_string(&Account::new(
            "legacy",
            Credential::ApiKey {
                key: ApiKey::new("x"),
            },
        ))
        .unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&expected).unwrap();
        value.as_object_mut().unwrap().remove("enabled");
        let stripped = serde_json::to_string(&value).unwrap();
        let _ = json;

        let back: Account = serde_json::from_str(&stripped).unwrap();
        assert!(back.enabled, "absent `enabled` must default to true");
    }
}
