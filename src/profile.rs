//! Who a token belongs to, as reported by `GET /api/oauth/profile` rather than
//! inferred from the grant.
//!
//! The token response only carries `account.email_address` when the grant
//! happens to include it; the profile endpoint always does. Deriving identity
//! from the API is what lets a login name itself, lets a re-login collapse
//! onto the row it supersedes, and lets an imported native credential (token
//! pair only — no uuid, email, or organization) stop hiding a duplicate.

use serde::Deserialize;

use crate::account::Account;
use crate::token::{Credential, TokenAccount, TokenOrganization};

/// `https://api.anthropic.com/api/oauth/profile`
pub const PROFILE_URL: &str = "https://api.anthropic.com/api/oauth/profile";

/// Identity fields from the profile endpoint. Every field is optional: a
/// transport or shape failure yields an empty identity rather than an error,
/// because naming an account is a convenience and a login that already
/// holds a valid credential must not be discarded because this lookup failed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OAuthAccountIdentity {
    /// `account.uuid`
    pub account_uuid: Option<String>,
    /// `account.email`
    pub email: Option<String>,
    /// `account.display_name`
    pub display_name: Option<String>,
    /// `organization.uuid`
    pub organization_uuid: Option<String>,
    /// `organization.name`
    pub organization_name: Option<String>,
    /// `organization.organization_type` (e.g. `claude_team`)
    pub organization_type: Option<String>,
    /// `organization.rate_limit_tier` (e.g. `default_claude_max_20x`)
    pub rate_limit_tier: Option<String>,
}

#[derive(Deserialize, Default)]
struct RawAccount {
    uuid: Option<String>,
    email: Option<String>,
    display_name: Option<String>,
}

#[derive(Deserialize, Default)]
struct RawOrganization {
    uuid: Option<String>,
    name: Option<String>,
    organization_type: Option<String>,
    rate_limit_tier: Option<String>,
}

#[derive(Deserialize, Default)]
struct RawProfile {
    account: Option<RawAccount>,
    organization: Option<RawOrganization>,
}

fn optional_text(value: Option<String>) -> Option<String> {
    value.map(|v| v.trim().to_owned()).filter(|v| !v.is_empty())
}

impl OAuthAccountIdentity {
    /// Parse a profile response body. Malformed JSON yields an empty identity.
    pub fn parse(body: &str) -> Self {
        let Ok(raw) = serde_json::from_str::<RawProfile>(body) else {
            return Self::default();
        };
        let account = raw.account.unwrap_or_default();
        let organization = raw.organization.unwrap_or_default();
        Self {
            account_uuid: optional_text(account.uuid),
            email: optional_text(account.email),
            display_name: optional_text(account.display_name),
            organization_uuid: optional_text(organization.uuid),
            organization_name: optional_text(organization.name),
            organization_type: optional_text(organization.organization_type),
            rate_limit_tier: optional_text(organization.rate_limit_tier),
        }
    }

    /// `Max Nx` / `Team · Max Nx` for a `default_claude_max_<N>x` tier.
    pub fn tier_label(&self) -> Option<String> {
        let tier = self.rate_limit_tier.as_deref()?;
        let multiplier = tier
            .strip_prefix("default_claude_max_")?
            .strip_suffix('x')?;
        if multiplier.is_empty() || !multiplier.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let label = format!("Max {multiplier}x");
        Some(
            if self.organization_type.as_deref() == Some("claude_team") {
                format!("Team · {label}")
            } else {
                label
            },
        )
    }

    /// Whether the account itself is identified (an imported credential is
    /// not until backfilled).
    pub fn is_identified(&self) -> bool {
        self.account_uuid.is_some()
    }
}

/// Fetch the signed-in identity for `access_token`. Any failure resolves to
/// an empty identity.
#[cfg(feature = "client")]
pub async fn fetch_oauth_account_identity(
    http: &reqwest::Client,
    access_token: &str,
) -> OAuthAccountIdentity {
    fetch_oauth_account_identity_from(http, PROFILE_URL, access_token).await
}

/// [`fetch_oauth_account_identity`] against an explicit URL (tests).
#[cfg(feature = "client")]
pub async fn fetch_oauth_account_identity_from(
    http: &reqwest::Client,
    url: &str,
    access_token: &str,
) -> OAuthAccountIdentity {
    // Test mode: a non-loopback profile host is never contacted.
    if crate::endpoints::ensure_oauth_url_allowed(url).is_err() {
        return OAuthAccountIdentity::default();
    }
    let Ok(response) = http
        .get(url)
        .header("authorization", format!("Bearer {access_token}"))
        .header("accept", "application/json")
        .header("anthropic-beta", crate::endpoints::OAUTH_BETA)
        .send()
        .await
    else {
        return OAuthAccountIdentity::default();
    };
    if !response.status().is_success() {
        return OAuthAccountIdentity::default();
    }
    match response.text().await {
        Ok(body) => OAuthAccountIdentity::parse(&body),
        Err(_) => OAuthAccountIdentity::default(),
    }
}

/// Why an account was not backfilled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackfillSkip {
    /// API-key accounts have no profile.
    NotOauth,
    /// The row already carries an account uuid.
    AlreadyIdentified,
    /// The lookup returned no account uuid; the row is left untouched rather
    /// than stamped with a guess.
    ProfileUnavailable,
}

/// Whether `account` needs an identity backfill (an OAuth row with no account
/// uuid).
pub fn needs_identity_backfill(account: &Account) -> Result<(), BackfillSkip> {
    match &account.credential {
        Credential::ApiKey { .. } => Err(BackfillSkip::NotOauth),
        Credential::Oauth(tokens) => {
            if tokens.account.as_ref().is_some_and(|a| !a.uuid.is_empty()) {
                Err(BackfillSkip::AlreadyIdentified)
            } else {
                Ok(())
            }
        }
    }
}

/// Write a fetched identity onto an OAuth row that lacks one: account uuid
/// and email, organization uuid, and the top-level email when unset. Returns
/// `Err` (and leaves the row untouched) when the row does not need it or the
/// identity has no account uuid.
pub fn apply_identity_backfill(
    account: &mut Account,
    identity: &OAuthAccountIdentity,
) -> Result<(), BackfillSkip> {
    needs_identity_backfill(account)?;
    let Some(uuid) = identity.account_uuid.clone() else {
        return Err(BackfillSkip::ProfileUnavailable);
    };
    let Credential::Oauth(tokens) = &mut account.credential else {
        return Err(BackfillSkip::NotOauth);
    };
    tokens.account = Some(TokenAccount {
        uuid,
        email_address: identity.email.clone(),
    });
    if let Some(org) = identity.organization_uuid.clone() {
        tokens.organization = Some(TokenOrganization { uuid: org });
    }
    if account.email.is_none() {
        account.email = identity.email.clone();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::{AccessToken, ApiKey, OAuthTokens, RefreshToken};

    const PROFILE: &str = r#"{"account":{"uuid":"acc-1","email":" me@example.com ","display_name":"Me"},"organization":{"uuid":"org-1","name":"Acme","organization_type":"claude_team","rate_limit_tier":"default_claude_max_20x"}}"#;

    fn oauth_account() -> Account {
        Account::new(
            "imported",
            Credential::Oauth(OAuthTokens {
                access: AccessToken::new("sk-ant-oat01-aaaaaaaaaaaaaaaaaaaaaaaa"),
                refresh: RefreshToken::new("sk-ant-ort01-aaaaaaaaaaaaaaaaaaaaaaaa"),
                expires_at: chrono::Utc::now(),
                refresh_expires_at: None,
                scopes: vec![],
                account: None,
                organization: None,
            }),
        )
    }

    #[test]
    fn parses_profile_and_tier() {
        let identity = OAuthAccountIdentity::parse(PROFILE);
        assert_eq!(identity.account_uuid.as_deref(), Some("acc-1"));
        assert_eq!(identity.email.as_deref(), Some("me@example.com"));
        assert_eq!(identity.organization_uuid.as_deref(), Some("org-1"));
        assert_eq!(identity.organization_name.as_deref(), Some("Acme"));
        assert_eq!(identity.tier_label().as_deref(), Some("Team · Max 20x"));
        let personal = OAuthAccountIdentity {
            rate_limit_tier: Some("default_claude_max_5x".into()),
            ..Default::default()
        };
        assert_eq!(personal.tier_label().as_deref(), Some("Max 5x"));
        assert_eq!(OAuthAccountIdentity::parse("{}").tier_label(), None);
        assert_eq!(
            OAuthAccountIdentity::parse("nope"),
            OAuthAccountIdentity::default()
        );
        assert!(!OAuthAccountIdentity::parse(r#"{"account":{"uuid":"  "}}"#).is_identified());
    }

    #[test]
    fn backfill_identifies_imported_rows_and_skips_the_rest() {
        let identity = OAuthAccountIdentity::parse(PROFILE);
        let mut account = oauth_account();
        assert_eq!(apply_identity_backfill(&mut account, &identity), Ok(()));
        let tokens = account.oauth().unwrap();
        assert_eq!(tokens.account.as_ref().unwrap().uuid, "acc-1");
        assert_eq!(
            tokens.account.as_ref().unwrap().email_address.as_deref(),
            Some("me@example.com")
        );
        assert_eq!(tokens.organization.as_ref().unwrap().uuid, "org-1");
        assert_eq!(account.email.as_deref(), Some("me@example.com"));
        // Safe to run repeatedly.
        assert_eq!(
            apply_identity_backfill(&mut account, &identity),
            Err(BackfillSkip::AlreadyIdentified)
        );
        // A failed lookup leaves the row untouched.
        let mut fresh = oauth_account();
        assert_eq!(
            apply_identity_backfill(&mut fresh, &OAuthAccountIdentity::default()),
            Err(BackfillSkip::ProfileUnavailable)
        );
        assert!(fresh.oauth().unwrap().account.is_none());
        let mut key = Account::new(
            "key",
            Credential::ApiKey {
                key: ApiKey::new("sk-ant-api01-aaaaaaaaaaaaaaaaaaaaaa"),
            },
        );
        assert_eq!(
            apply_identity_backfill(&mut key, &identity),
            Err(BackfillSkip::NotOauth)
        );
    }
}
