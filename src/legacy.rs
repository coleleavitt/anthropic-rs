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
//! account.

use chrono::{DateTime, TimeZone, Utc};
use serde::Deserialize;

use crate::account::Account;
use crate::token::{
    AccessToken, Credential, OAuthTokens, RefreshToken, TokenAccount, TokenOrganization,
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

        let last_error = non_empty(self.disabled_reason)
            .or_else(|| non_empty(self.last_auth_error))
            .map(|reason| {
                // Legacy `lastAuthError` sometimes held a whole OAuth error
                // body, so scrub it before it enters the shared store.
                let mut redacted = redact_secrets(&reason);
                redacted.truncate(MAX_STORED_ERROR_LEN);
                redacted
            });

        Some(Account {
            label: non_empty(self.name).or_else(|| email.clone()),
            email,
            credential,
            enabled: self.enabled.unwrap_or(true),
            created_at: timestamp_from_epoch_ms(self.added_at).unwrap_or_default(),
            last_used_at: timestamp_from_epoch_ms(self.last_used),
            rate_limited_until: timestamp_from_epoch_ms(self.rate_limit_reset_time),
            last_error,
            id,
        })
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
        row["disabledReason"] = serde_json::json!("invalid_grant");
        let store: LegacyStore =
            serde_json::from_value(serde_json::json!({ "accounts": [row] })).unwrap();

        let accounts = store.into_accounts();
        assert!(!accounts[0].enabled);
        assert_eq!(accounts[0].last_error.as_deref(), Some("invalid_grant"));
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
