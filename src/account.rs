//! A single stored Anthropic account: its credential plus the routing metadata
//! needed to rotate between subscriptions (enabled/disabled, rate-limit
//! cooldown, last use, last error).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::token::{Credential, OAuthTokens};

/// Why an account is not currently usable.
#[derive(Debug, Clone, PartialEq)]
pub enum Unavailable {
    /// The user (or a permanent auth failure) disabled it.
    Disabled,
    /// It is in a rate-limit cooldown until the given instant.
    RateLimited(DateTime<Utc>),
    /// A fresh quota reading says a plan window is exhausted. Anthropic
    /// reports exhaustion through the usage API, not through a cooldown, so
    /// an account at 100% of its weekly window would otherwise look available.
    QuotaExhausted(QuotaObservation),
}

/// Utilisation at or above this is treated as no headroom left.
pub const QUOTA_EXHAUSTED_PERCENT: f64 = 100.0;

/// A quota reading older than this is too stale to disqualify an account.
pub const QUOTA_OBSERVATION_MAX_AGE_SECS: i64 = 30 * 60;

/// Last observed plan-window utilisation, as percentages (0–100).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuotaObservation {
    /// Five-hour window utilisation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub five_hour_percent: Option<f64>,
    /// Seven-day window utilisation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seven_day_percent: Option<f64>,
    /// When the reading was taken.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<DateTime<Utc>>,
}

impl QuotaObservation {
    /// Whether this reading says no headroom is left. Deliberately fails
    /// open: a missing timestamp, a stale reading, or non-finite numbers
    /// leave the account selectable, so a bad snapshot can never strand
    /// every account.
    pub fn is_exhausted(&self, now: DateTime<Utc>) -> bool {
        let Some(checked_at) = self.checked_at else {
            return false;
        };
        if (now - checked_at).num_seconds() > QUOTA_OBSERVATION_MAX_AGE_SECS {
            return false;
        }
        [self.five_hour_percent, self.seven_day_percent]
            .into_iter()
            .flatten()
            .any(|percent| percent.is_finite() && percent >= QUOTA_EXHAUSTED_PERCENT)
    }
}

/// An in-flight refresh claim. Anthropic revokes an entire token family when
/// the same refresh token is presented twice, so concurrent processes must
/// not both POST it — the store CAS alone is too late, because by then both
/// network calls have already happened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshLease {
    /// Random lease id (never a PID: PIDs are recycled).
    pub id: String,
    /// Lease expiry, epoch milliseconds.
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub until: DateTime<Utc>,
    /// Fingerprint of the refresh token being spent — never the token.
    pub token_fingerprint: String,
    /// The process holding the claim; diagnostics only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder_pid: Option<u32>,
    /// When the claim was taken.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed_at: Option<DateTime<Utc>>,
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
    /// Last observed plan-window utilisation, so selection can skip an
    /// exhausted account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota: Option<QuotaObservation>,
    /// In-flight cross-process refresh claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_lease: Option<RefreshLease>,
    /// Fingerprint of a refresh token Anthropic already rejected with
    /// `invalid_grant`. A revoked family never recovers, but the credential
    /// stays on disk, so without this the router re-presents it on every pass.
    /// Mirrors Claude Code's in-memory `u2n` set, persisted so a restart does
    /// not start asking again; scoped to the token, not the account, so a
    /// later re-login is not stranded by its predecessor's verdict.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dead_refresh_fingerprint: Option<String>,
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
            quota: None,
            refresh_lease: None,
            dead_refresh_fingerprint: None,
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
        if let Some(quota) = &self.quota
            && quota.is_exhausted(now)
        {
            return Some(Unavailable::QuotaExhausted(quota.clone()));
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
    ///
    /// A custody tombstone (`claustrum-tombstone:v1:*`) is refused: the merged
    /// anthropic-auth never mirrors a host's tombstone into the shared account
    /// store, where other apps would present it.
    pub fn replace_oauth_tokens(&mut self, tokens: OAuthTokens) -> Result<()> {
        crate::token::ensure_not_custody_tombstone(tokens.refresh.expose(), "anthropic")?;
        crate::token::ensure_not_custody_tombstone(tokens.access.expose(), "anthropic")?;
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

    /// The OAuth session, when this is an OAuth account.
    pub fn oauth(&self) -> Option<&OAuthTokens> {
        match &self.credential {
            Credential::Oauth(tokens) => Some(tokens),
            Credential::ApiKey { .. } => None,
        }
    }

    /// Whether this is an enabled OAuth account whose access token has not
    /// expired at `now` — i.e. its bearer can be sent without a refresh.
    pub fn oauth_credential_is_live(&self, now: DateTime<Utc>) -> bool {
        self.enabled
            && self
                .oauth()
                .is_some_and(|tokens| !tokens.access.expose().is_empty() && !tokens.is_expired(now))
    }

    /// Whether the stored refresh token is already known-dead (rejected with
    /// `invalid_grant`).
    pub fn refresh_token_is_dead(&self) -> bool {
        match (&self.dead_refresh_fingerprint, self.oauth()) {
            (Some(dead), Some(tokens)) => {
                *dead == crate::token::token_fingerprint(tokens.refresh.expose())
            }
            _ => false,
        }
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

        // Merge post-fix: a custody tombstone is never mirrored into the
        // shared store; the live session is left untouched.
        let refused = account.replace_oauth_tokens(OAuthTokens {
            access: AccessToken::new(""),
            refresh: RefreshToken::new("claustrum-tombstone:v1:anthropic"),
            expires_at: at(1_700_000_200),
            refresh_expires_at: None,
            scopes: Vec::new(),
            account: None,
            organization: None,
        });
        assert!(matches!(
            refused,
            Err(crate::Error::CustodyTombstone { .. })
        ));
        assert_eq!(
            account.oauth().map(|t| t.refresh.expose().to_owned()),
            Some("sk-ant-ort01-bbbbbbbbbbbbbbbbbbbbbb".to_owned())
        );
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
