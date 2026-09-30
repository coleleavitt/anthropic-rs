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
///
/// Serialization goes through a private wire form that keeps every field this
/// crate does not know about, both on the row (`extra`) and inside the
/// credential object (`credential_extra`). The store is shared with other
/// writers (the TypeScript plugin, older crate versions); a row update that
/// dropped their fields would be a silent rebuild of the row, which is exactly
/// the bug class that left stale `invalid_grant` flags and lost quota readings
/// behind (doc 23 §1.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "AccountWire", into = "AccountWire")]
pub struct Account {
    /// Stable key for this account within the store.
    pub id: String,
    /// Optional human label for pickers and logs.
    pub label: Option<String>,
    /// Account email, when known.
    pub email: Option<String>,
    /// The credential itself.
    pub credential: Credential,
    /// Whether this account participates in routing.
    pub enabled: bool,
    /// When the account was added.
    pub created_at: DateTime<Utc>,
    /// When a request last used it.
    pub last_used_at: Option<DateTime<Utc>>,
    /// Cooldown end after a 429; the account is skipped until then.
    pub rate_limited_until: Option<DateTime<Utc>>,
    /// Last error recorded against this account, already secret-redacted.
    ///
    /// Read it through [`Account::current_error`]: the raw field can be stale
    /// (written by another tool, or about a token the row no longer holds).
    pub last_error: Option<String>,
    /// Fingerprint of the credential `last_error` was recorded against. An
    /// error bound to a token the row no longer holds is stale and clears
    /// itself (see [`Account::current_error`]).
    pub last_error_fingerprint: Option<String>,
    /// When a refresh of this row last succeeded (this crate's own commit
    /// path). Independent of the server echoing a refresh-token expiry.
    pub last_refreshed_at: Option<DateTime<Utc>>,
    /// Last observed plan-window utilisation, so selection can skip an
    /// exhausted account.
    pub quota: Option<QuotaObservation>,
    /// In-flight cross-process refresh claim.
    pub refresh_lease: Option<RefreshLease>,
    /// Fingerprint of a refresh token Anthropic already rejected with
    /// `invalid_grant`. A revoked family never recovers, but the credential
    /// stays on disk, so without this the router re-presents it on every pass.
    /// Mirrors Claude Code's in-memory `u2n` set, persisted so a restart does
    /// not start asking again; scoped to the token, not the account, so a
    /// later re-login is not stranded by its predecessor's verdict.
    pub dead_refresh_fingerprint: Option<String>,
    /// Credential-object fields this crate does not model, preserved verbatim.
    pub credential_extra: serde_json::Map<String, serde_json::Value>,
    /// Row fields this crate does not model, preserved verbatim.
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Keys of the `credential` object this crate models, per credential type.
const OAUTH_CREDENTIAL_KEYS: [&str; 8] = [
    "type",
    "access",
    "refresh",
    "expires_at",
    "refresh_expires_at",
    "scopes",
    "account",
    "organization",
];
const API_KEY_CREDENTIAL_KEYS: [&str; 2] = ["type", "key"];

/// Keys of the row object this crate models.
const ACCOUNT_KEYS: [&str; 14] = [
    "id",
    "label",
    "email",
    "credential",
    "enabled",
    "created_at",
    "last_used_at",
    "rate_limited_until",
    "last_error",
    "last_error_fingerprint",
    "last_refreshed_at",
    "quota",
    "refresh_lease",
    "dead_refresh_fingerprint",
];

/// The on-disk row shape. Private: [`Account`] is the API.
#[derive(Serialize, Deserialize)]
struct AccountWire {
    id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    credential: serde_json::Map<String, serde_json::Value>,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default = "Utc::now")]
    created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_used_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rate_limited_until: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_error_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_refreshed_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    quota: Option<QuotaObservation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refresh_lease: Option<RefreshLease>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dead_refresh_fingerprint: Option<String>,
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

fn credential_keys(credential: &Credential) -> &'static [&'static str] {
    match credential {
        Credential::Oauth(_) => &OAUTH_CREDENTIAL_KEYS,
        Credential::ApiKey { .. } => &API_KEY_CREDENTIAL_KEYS,
    }
}

impl TryFrom<AccountWire> for Account {
    type Error = serde_json::Error;

    fn try_from(wire: AccountWire) -> std::result::Result<Self, Self::Error> {
        let credential: Credential =
            serde_json::from_value(serde_json::Value::Object(wire.credential.clone()))?;
        let known = credential_keys(&credential);
        let credential_extra = wire
            .credential
            .into_iter()
            .filter(|(key, _)| !known.contains(&key.as_str()))
            .collect();
        Ok(Self {
            id: wire.id,
            label: wire.label,
            email: wire.email,
            credential,
            enabled: wire.enabled,
            created_at: wire.created_at,
            last_used_at: wire.last_used_at,
            rate_limited_until: wire.rate_limited_until,
            last_error: wire.last_error,
            last_error_fingerprint: wire.last_error_fingerprint,
            last_refreshed_at: wire.last_refreshed_at,
            quota: wire.quota,
            refresh_lease: wire.refresh_lease,
            dead_refresh_fingerprint: wire.dead_refresh_fingerprint,
            credential_extra,
            extra: wire.extra,
        })
    }
}

impl From<Account> for AccountWire {
    fn from(account: Account) -> Self {
        let known = credential_keys(&account.credential);
        let mut credential = match serde_json::to_value(&account.credential) {
            Ok(serde_json::Value::Object(map)) => map,
            // `Credential` is an internally tagged enum of structs; it always
            // serializes to an object.
            _ => serde_json::Map::new(),
        };
        for (key, value) in account.credential_extra {
            if !known.contains(&key.as_str()) && !credential.contains_key(&key) {
                credential.insert(key, value);
            }
        }
        let extra = account
            .extra
            .into_iter()
            .filter(|(key, _)| !ACCOUNT_KEYS.contains(&key.as_str()))
            .collect();
        Self {
            id: account.id,
            label: account.label,
            email: account.email,
            credential,
            enabled: account.enabled,
            created_at: account.created_at,
            last_used_at: account.last_used_at,
            rate_limited_until: account.rate_limited_until,
            last_error: account.last_error,
            last_error_fingerprint: account.last_error_fingerprint,
            last_refreshed_at: account.last_refreshed_at,
            quota: account.quota,
            refresh_lease: account.refresh_lease,
            dead_refresh_fingerprint: account.dead_refresh_fingerprint,
            extra,
        }
    }
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
            last_error_fingerprint: None,
            last_refreshed_at: None,
            quota: None,
            refresh_lease: None,
            dead_refresh_fingerprint: None,
            credential_extra: serde_json::Map::new(),
            extra: serde_json::Map::new(),
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
        self.clear_error();
    }

    /// Fingerprint of the credential an error or verdict is bound to: the
    /// refresh token of an OAuth row, the key of an API-key row. `None` for an
    /// OAuth row with no refresh token.
    pub fn credential_fingerprint(&self) -> Option<String> {
        match &self.credential {
            Credential::Oauth(tokens) => {
                let refresh = tokens.refresh.expose();
                (!refresh.is_empty()).then(|| crate::token::token_fingerprint(refresh))
            }
            Credential::ApiKey { key } => Some(crate::token::token_fingerprint(key.expose())),
        }
    }

    /// Record an error against the credential the row holds right now. The
    /// text is stored redacted and bound to the credential's fingerprint, so
    /// it expires by itself once the token rotates.
    pub fn record_error(&mut self, reason: impl AsRef<str>) {
        self.last_error = Some(crate::token::redact_secrets(reason.as_ref()));
        self.last_error_fingerprint = self.credential_fingerprint();
    }

    /// Forget the last error and its binding.
    pub fn clear_error(&mut self) {
        self.last_error = None;
        self.last_error_fingerprint = None;
    }

    /// The last error, when it still describes the credential the row holds.
    ///
    /// - A bound error (`last_error_fingerprint` set) is current only while
    ///   the row holds the token it was recorded against.
    /// - An unbound error (written by an older crate or another tool) that
    ///   claims `invalid_grant` is current only while the row's refresh token
    ///   is recorded dead. Every real `invalid_grant` verdict records the
    ///   dead fingerprint, so an unbound one without it is a leftover
    ///   (doc 23 §1: four live accounts carried exactly this).
    /// - Any other unbound error is returned as-is.
    pub fn current_error(&self) -> Option<&str> {
        let error = self.last_error.as_deref()?;
        match &self.last_error_fingerprint {
            Some(bound) => {
                (self.credential_fingerprint().as_deref() == Some(bound.as_str())).then_some(error)
            }
            None if error.contains("invalid_grant") => {
                self.refresh_token_is_dead().then_some(error)
            }
            None => Some(error),
        }
    }

    /// Drop `last_error` when [`Account::current_error`] says it is stale.
    /// Returns whether anything changed.
    pub fn clear_stale_error(&mut self) -> bool {
        if self.last_error.is_some() && self.current_error().is_none() {
            self.clear_error();
            return true;
        }
        false
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
        self.record_error(reason);
    }

    /// Re-enable the account and clear its cooldown and last error.
    pub fn enable(&mut self) {
        self.enabled = true;
        self.rate_limited_until = None;
        self.clear_error();
    }

    /// Replace the stored OAuth session and synchronize derived account
    /// metadata from the token payload.
    ///
    /// Only the credential and the email change. When the refresh token
    /// changes, every record bound to the old token goes with it: the last
    /// error, a dead-token verdict for a different token, and a refresh claim
    /// on a different token. Quota, lease-free metadata and unknown fields are
    /// kept.
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
        let token_changed = current.refresh != tokens.refresh;
        *current = tokens;
        if email.is_some() {
            self.email = email;
        }
        if token_changed {
            let fingerprint = self.credential_fingerprint();
            self.clear_error();
            if self.dead_refresh_fingerprint.is_some()
                && self.dead_refresh_fingerprint != fingerprint
            {
                self.dead_refresh_fingerprint = None;
            }
            if self
                .refresh_lease
                .as_ref()
                .is_some_and(|lease| Some(&lease.token_fingerprint) != fingerprint.as_ref())
            {
                self.refresh_lease = None;
            }
        }
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

    fn oauth_row(refresh: &str) -> Account {
        Account::new(
            "row",
            Credential::Oauth(OAuthTokens {
                access: AccessToken::new("sk-ant-oat01-aaaaaaaaaaaaaaaaaaaaaa"),
                refresh: RefreshToken::new(refresh),
                expires_at: at(1_700_000_000),
                refresh_expires_at: None,
                scopes: vec!["user:inference".into()],
                account: None,
                organization: None,
            }),
        )
    }

    #[test]
    fn unknown_row_and_credential_fields_survive_a_round_trip() {
        let json = serde_json::json!({
            "id": "row",
            "credential": {
                "type": "oauth",
                "access": "sk-ant-oat01-aaaaaaaaaaaaaaaaaaaaaa",
                "refresh": "sk-ant-ort01-aaaaaaaaaaaaaaaaaaaaaa",
                "expires_at": 1_700_000_000_000i64,
                "subscription_type": "max",
                "rate_limit_tier": { "tier": 20 }
            },
            "enabled": true,
            "created_at": "2026-09-01T00:00:00Z",
            "host_state": { "opencode": { "pinned": true } },
            "future_flag": 7
        });
        let account: Account = serde_json::from_value(json).unwrap();
        assert_eq!(account.extra["future_flag"], 7);
        assert_eq!(account.credential_extra["subscription_type"], "max");
        let back = serde_json::to_value(&account).unwrap();
        assert_eq!(back["host_state"]["opencode"]["pinned"], true);
        assert_eq!(back["future_flag"], 7);
        assert_eq!(back["credential"]["subscription_type"], "max");
        assert_eq!(back["credential"]["rate_limit_tier"]["tier"], 20);
        assert_eq!(back["credential"]["type"], "oauth");
        // Known keys are never duplicated into the extras.
        assert!(!account.extra.contains_key("credential"));
        assert!(!account.credential_extra.contains_key("refresh"));
    }

    #[test]
    fn an_error_is_bound_to_the_token_it_was_recorded_against() {
        let mut account = oauth_row("sk-ant-ort01-firstfirstfirstfirst00");
        account.record_error("refresh failed: 503");
        assert_eq!(account.current_error(), Some("refresh failed: 503"));
        // The token rotates: the error was about the old one.
        account
            .replace_oauth_tokens(OAuthTokens {
                refresh: RefreshToken::new("sk-ant-ort01-secondsecondsecond000"),
                ..account.oauth().unwrap().clone()
            })
            .unwrap();
        assert_eq!(account.current_error(), None);
        assert_eq!(account.last_error, None);
    }

    #[test]
    fn a_stale_unbound_invalid_grant_flag_clears_itself() {
        // doc 23 §1: the flag another writer left on a row whose token
        // refreshed fine afterwards, with no dead-token record.
        let mut account = oauth_row("sk-ant-ort01-liveliveliveliveliv00");
        account.last_error = Some("invalid_grant".into());
        assert_eq!(account.current_error(), None);
        assert!(account.clear_stale_error());
        assert_eq!(account.last_error, None);

        // A flag bound to a different token is stale too.
        let mut bound_elsewhere = oauth_row("sk-ant-ort01-liveliveliveliveliv00");
        bound_elsewhere.last_error = Some("invalid_grant".into());
        bound_elsewhere.last_error_fingerprint = Some("0000000000000000".into());
        assert!(bound_elsewhere.clear_stale_error());

        // A real verdict on the current token stays.
        let mut dead = oauth_row("sk-ant-ort01-deaddeaddeaddeaddead0");
        dead.dead_refresh_fingerprint = dead.credential_fingerprint();
        dead.last_error = Some("invalid_grant".into());
        assert_eq!(dead.current_error(), Some("invalid_grant"));
        assert!(!dead.clear_stale_error());

        // Unbound errors that are not about the grant are left alone.
        let mut other = oauth_row("sk-ant-ort01-otherotherotherother0");
        other.last_error = Some("user disabled".into());
        assert!(!other.clear_stale_error());
    }
}
