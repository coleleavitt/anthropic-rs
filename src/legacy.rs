//! Adoption of the flat per-application account schema that predates the
//! shared store.
//!
//! jfc, grok, and older OpenCode builds wrote accounts as
//! `{uuid, accessToken, refreshToken, expiresAt, email, enabled, …}` rather
//! than the shared `{id, credential: {type, access, refresh, expires_at}}`.
//! Without a reader for that shape the canonical loader rejects every such row,
//! so a machine holding several logged-in accounts presents none of them and a
//! router is left with nothing to rotate to.
//!
//! Adoption is deliberately lossy in one direction only: a row that cannot
//! yield a usable credential is dropped rather than surfaced as a broken
//! account. That includes a row a predecessor disabled with `invalid_grant`:
//! its refresh token is dead by definition, and importing it (disabled, or
//! live, or as a bare `last_error` flag) only re-plants the stale verdicts
//! doc 23 traced back to these files.

use chrono::{DateTime, TimeZone, Utc};
use serde::Deserialize;

use crate::account::Account;
use crate::token::{
    AccessToken,
    Credential,
    OAuthTokens,
    RefreshToken,
    TokenAccount,
    TokenOrganization,
    redact_secrets,
};

/// Longest stored error text kept from a legacy row.
const MAX_STORED_ERROR_LEN: usize = 512;

/// A legacy store document. Only the account list is meaningful here; the
/// sibling `active_index` pointer is positional and does not survive a merge.
#[derive(Debug, Deserialize)]
pub(crate) struct LegacyStore {
    #[serde(default)]
    pub(crate) accounts: Vec<LegacyAccount>,
}

/// One account in the flat schema. Every field is optional: these files were
/// written by several tools across several versions.
#[derive(Debug, Deserialize)]
pub(crate) struct LegacyAccount {
    uuid: Option<String>,
    name: Option<String>,
    email: Option<String>,
    #[serde(rename = "accessToken")]
    access_token: Option<String>,
    #[serde(rename = "refreshToken")]
    refresh_token: Option<String>,
    #[serde(rename = "expiresAt")]
    expires_at: Option<i64>,
    #[serde(rename = "addedAt")]
    added_at: Option<i64>,
    #[serde(rename = "lastUsed")]
    last_used: Option<i64>,
    #[serde(rename = "rateLimitResetTime")]
    rate_limit_reset_time: Option<i64>,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(rename = "organizationUuid")]
    organization_uuid: Option<String>,
    enabled: Option<bool>,
    #[serde(rename = "disabledReason")]
    disabled_reason: Option<String>,
    #[serde(rename = "lastAuthError")]
    last_auth_error: Option<String>,
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|v| !v.trim().is_empty())
}

fn timestamp_from_epoch_ms(value: Option<i64>) -> Option<DateTime<Utc>> {
    let millis = value.filter(|v| *v > 0)?;
    Utc.timestamp_millis_opt(millis).single()
}

impl LegacyAccount {
    /// Convert to a shared-store account, or `None` when the row cannot produce
    /// a usable credential.
    pub(crate) fn into_account(self) -> Option<Account> {
        let id = non_empty(self.uuid)?;
        let access = non_empty(self.access_token)?;
        // A row stripped of its refresh token can never obtain a working access
        // token again; adopting it would only add a permanently failing route.
        let refresh = non_empty(self.refresh_token)?;
        // A custody tombstone is a vault marker, never an importable credential.
        if crate::token::is_custody_tombstone(&access)
            || crate::token::is_custody_tombstone(&refresh)
        {
            return None;
        }

        let email = non_empty(self.email);
        let organization = non_empty(self.organization_uuid).map(|uuid| TokenOrganization { uuid });

        let credential = Credential::Oauth(OAuthTokens {
            access: AccessToken::new(access),
            refresh: RefreshToken::new(refresh),
            // A missing expiry is treated as already elapsed so the first use
            // refreshes rather than sending a token of unknown age.
            expires_at: timestamp_from_epoch_ms(self.expires_at)
                .unwrap_or_else(|| Utc.timestamp_millis_opt(0).single().unwrap_or_default()),
            refresh_expires_at: None,
            scopes: self.scopes,
            account: Some(TokenAccount {
                uuid: id.clone(),
                email_address: email.clone(),
            }),
            organization,
        });

        let enabled = self.enabled.unwrap_or(true);
        let reason = non_empty(self.disabled_reason).or_else(|| non_empty(self.last_auth_error));
        let invalid_grant = reason
            .as_deref()
            .is_some_and(|reason| reason.contains("invalid_grant"));
        if invalid_grant && !enabled {
            return None;
        }
        // An enabled row whose last recorded error was `invalid_grant` was
        // re-enabled after it (a re-login): the verdict is about an older
        // token, so it is not carried over.
        let last_error = reason.filter(|_| !invalid_grant).map(|reason| {
            // Legacy `lastAuthError` sometimes held a whole OAuth error
            // body, so scrub it before it enters the shared store.
            let mut redacted = redact_secrets(&reason);
            let mut end = MAX_STORED_ERROR_LEN.min(redacted.len());
            while !redacted.is_char_boundary(end) {
                end -= 1;
            }
            redacted.truncate(end);
            redacted
        });

        let mut account = Account::new(id, credential);
        account.label = non_empty(self.name).or_else(|| email.clone());
        account.email = email;
        account.enabled = enabled;
        account.created_at = timestamp_from_epoch_ms(self.added_at).unwrap_or_default();
        account.last_used_at = timestamp_from_epoch_ms(self.last_used);
        account.rate_limited_until = timestamp_from_epoch_ms(self.rate_limit_reset_time);
        if let Some(error) = last_error {
            // Bound to the token it was recorded against, so it clears itself
            // on the next rotation.
            account.record_error(error);
        }
        Some(account)
    }
}

impl LegacyStore {
    /// Every row that yields a usable credential, in file order.
    pub(crate) fn into_accounts(self) -> Vec<Account> {
        self.accounts
            .into_iter()
            .filter_map(LegacyAccount::into_account)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flat_row() -> serde_json::Value {
        serde_json::json!({
            "uuid": "11111111-2222-3333-4444-555555555555",
            "name": "fallback@example.com",
            "email": "fallback@example.com",
            "accessToken": "sk-ant-oat01-aaaaaaaaaaaaaaaaaaaaaaaa",
            "refreshToken": "sk-ant-ort01-bbbbbbbbbbbbbbbbbbbbbbbb",
            "expiresAt": 1_786_603_416_722i64,
            "addedAt": 1_778_606_812_194i64,
            "lastUsed": 1_785_253_979_028i64,
            "scopes": ["user:inference", "user:profile"],
            "organizationUuid": "66666666-7777-8888-9999-000000000000",
            "enabled": true,
        })
    }

    #[test]
    fn never_adopts_a_custody_tombstone() {
        let mut row = flat_row();
        row["refreshToken"] = serde_json::json!("claustrum-tombstone:v1:anthropic");
        let store: LegacyStore =
            serde_json::from_value(serde_json::json!({ "accounts": [row] })).unwrap();
        assert!(store.into_accounts().is_empty());
    }

    #[test]
    fn adopts_a_flat_legacy_row() {
        let store: LegacyStore =
            serde_json::from_value(serde_json::json!({ "accounts": [flat_row()] })).unwrap();
        let accounts = store.into_accounts();

        assert_eq!(accounts.len(), 1);
        let account = &accounts[0];
        assert_eq!(account.id, "11111111-2222-3333-4444-555555555555");
        assert_eq!(account.email.as_deref(), Some("fallback@example.com"));
        assert!(account.enabled);
        let Credential::Oauth(tokens) = &account.credential else {
            panic!("expected an OAuth credential");
        };
        assert_eq!(
            tokens.refresh.expose(),
            "sk-ant-ort01-bbbbbbbbbbbbbbbbbbbbbbbb"
        );
        assert_eq!(tokens.scopes, vec!["user:inference", "user:profile"]);
        assert_eq!(
            tokens.organization.as_ref().map(|o| o.uuid.as_str()),
            Some("66666666-7777-8888-9999-000000000000")
        );
        assert_eq!(tokens.expires_at.timestamp_millis(), 1_786_603_416_722);
    }

    #[test]
    fn keeps_a_disabled_row_disabled_with_its_reason() {
        let mut row = flat_row();
        row["enabled"] = serde_json::json!(false);
        row["disabledReason"] = serde_json::json!("user paused this account");
        let store: LegacyStore =
            serde_json::from_value(serde_json::json!({ "accounts": [row] })).unwrap();

        let accounts = store.into_accounts();
        assert!(!accounts[0].enabled);
        assert_eq!(
            accounts[0].current_error(),
            Some("user paused this account")
        );
    }

    #[test]
    fn never_imports_a_row_disabled_with_invalid_grant() {
        // doc 23 §2.2: four legacy files still hold rows disabled with
        // `invalid_grant`. Their tokens are dead by definition.
        let mut disabled = flat_row();
        disabled["enabled"] = serde_json::json!(false);
        disabled["disabledReason"] = serde_json::json!("invalid_grant");
        let mut grok_style = flat_row();
        grok_style["uuid"] = serde_json::json!("grok-row");
        grok_style["enabled"] = serde_json::json!(false);
        grok_style["lastAuthError"] = serde_json::json!(
            "HTTP 400 {\"error\":\"invalid_grant\",\"error_description\":\"Refresh token not found or invalid\"}"
        );
        let store: LegacyStore =
            serde_json::from_value(serde_json::json!({ "accounts": [disabled, grok_style] }))
                .unwrap();
        assert!(store.into_accounts().is_empty());
    }

    #[test]
    fn an_enabled_row_never_carries_an_invalid_grant_flag_over() {
        let mut row = flat_row();
        row["lastAuthError"] = serde_json::json!("invalid_grant");
        let store: LegacyStore =
            serde_json::from_value(serde_json::json!({ "accounts": [row] })).unwrap();
        let accounts = store.into_accounts();
        assert_eq!(accounts.len(), 1);
        assert!(accounts[0].enabled);
        assert_eq!(accounts[0].last_error, None);
        assert_eq!(accounts[0].dead_refresh_fingerprint, None);
    }

    #[test]
    fn drops_a_row_without_a_refresh_token() {
        let mut row = flat_row();
        row["refreshToken"] = serde_json::json!("");
        let store: LegacyStore =
            serde_json::from_value(serde_json::json!({ "accounts": [row, flat_row()] })).unwrap();

        assert_eq!(store.into_accounts().len(), 1);
    }

    #[test]
    fn redacts_a_token_bearing_legacy_error() {
        let mut row = flat_row();
        row["lastAuthError"] =
            serde_json::json!("refresh rejected for sk-ant-ort01-leakedsecretvalue");
        let store: LegacyStore =
            serde_json::from_value(serde_json::json!({ "accounts": [row] })).unwrap();

        let stored = store.into_accounts()[0].last_error.clone().unwrap();
        assert!(!stored.contains("leakedsecret"));
        assert!(stored.contains("sk-ant-***REDACTED***"));
    }

    #[test]
    fn a_missing_expiry_reads_as_already_elapsed() {
        let mut row = flat_row();
        row.as_object_mut().unwrap().remove("expiresAt");
        let store: LegacyStore =
            serde_json::from_value(serde_json::json!({ "accounts": [row] })).unwrap();

        let accounts = store.into_accounts();
        let Credential::Oauth(tokens) = &accounts[0].credential else {
            panic!("expected an OAuth credential");
        };
        assert!(tokens.is_expired(Utc::now()));
    }
}
