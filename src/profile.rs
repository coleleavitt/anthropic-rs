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

/// [`PROFILE_URL`], or [`crate::endpoints::PROFILE_URL_ENV`] when set.
pub fn profile_url_from_lookup(lookup: impl Fn(&str) -> Option<String>) -> String {
    lookup(crate::endpoints::PROFILE_URL_ENV)
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| PROFILE_URL.to_owned())
}

/// What an identity backfill did to one row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityBackfill {
    /// The row now carries the profile's account uuid (and email /
    /// organization when the profile had them).
    Filled {
        /// The email written, when the profile had one.
        email: Option<String>,
    },
    /// Left alone (API key, already identified, or the profile had no
    /// account uuid).
    Skipped(BackfillSkip),
    /// Left alone: its access token is not live, and a backfill never spends
    /// a refresh token.
    NoLiveAccessToken,
    /// Left alone: the row changed while the profile was being fetched.
    Changed,
}

/// Fill the identity of every OAuth row in the store at `path` that has
/// none (an imported native or host credential carries only a token pair),
/// from `GET profile_url` with the row's live access token. Rows whose access
/// token is expired are skipped, never refreshed. In OAuth test mode
/// (`test_mode`, or the environment) a non-loopback `profile_url` is never
/// contacted. Each write re-checks under the store lock that the row still
/// holds the same access token and still lacks an identity.
#[cfg(all(feature = "client", feature = "store"))]
pub async fn backfill_store_identities(
    http: &reqwest::Client,
    profile_url: &str,
    path: &std::path::Path,
    test_mode: bool,
) -> crate::Result<Vec<(String, IdentityBackfill)>> {
    crate::endpoints::check_oauth_url(
        profile_url,
        test_mode || crate::endpoints::oauth_test_mode(),
    )?;
    let now = chrono::Utc::now();
    let store = crate::store::AccountStore::load_or_migrate_from(path, &[])?.store;
    let mut report = Vec::new();
    for account in &store.accounts {
        if let Err(skip) = needs_identity_backfill(account) {
            report.push((account.id.clone(), IdentityBackfill::Skipped(skip)));
            continue;
        }
        let Some(tokens) = account.oauth() else {
            continue;
        };
        if tokens.access.expose().is_empty() || tokens.is_expired(now) {
            report.push((account.id.clone(), IdentityBackfill::NoLiveAccessToken));
            continue;
        }
        let access = tokens.access.clone();
        let identity = fetch_oauth_account_identity_from(http, profile_url, access.expose()).await;
        if !identity.is_identified() {
            report.push((
                account.id.clone(),
                IdentityBackfill::Skipped(BackfillSkip::ProfileUnavailable),
            ));
            continue;
        }
        let id = account.id.clone();
        let result = crate::store::AccountStore::mutate(path, |store| {
            let Ok(row) = store.get_mut(&id) else {
                return Ok(IdentityBackfill::Changed);
            };
            if row.oauth().map(|t| &t.access) != Some(&access) {
                return Ok(IdentityBackfill::Changed);
            }
            Ok(match apply_identity_backfill(row, &identity) {
                Ok(()) => IdentityBackfill::Filled {
                    email: identity.email.clone(),
                },
                Err(skip) => IdentityBackfill::Skipped(skip),
            })
        })?;
        report.push((id, result));
    }
    Ok(report)
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

    #[cfg(all(feature = "client", feature = "store"))]
    mod store_backfill {
        use chrono::{Duration, Utc};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        use super::super::*;
        use crate::store::AccountStore;
        use crate::token::{AccessToken, ApiKey, OAuthTokens, RefreshToken};

        /// A profile endpoint that answers `body` to any GET carrying
        /// `Bearer <live>`, 401 otherwise; counts requests.
        async fn profile_server(
            live: &'static str,
            body: &'static str,
        ) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
            let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let url = format!(
                "http://{}/api/oauth/profile",
                listener.local_addr().unwrap()
            );
            let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let counter = hits.clone();
            tokio::spawn(async move {
                while let Ok((mut stream, _)) = listener.accept().await {
                    counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let mut buf = vec![0u8; 8192];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let head = String::from_utf8_lossy(&buf[..n]).to_string();
                    let (status, reply) = if head.contains(&format!("Bearer {live}")) {
                        ("200 OK", body)
                    } else {
                        ("401 Unauthorized", "{}")
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
                        reply.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                }
            });
            (url, hits)
        }

        fn oauth(id: &str, access: &str, expires_in: Duration) -> Account {
            Account::new(
                id,
                Credential::Oauth(OAuthTokens {
                    access: AccessToken::new(access),
                    refresh: RefreshToken::new(format!("sk-ant-ort01-{id}-rrrrrrrrrrrrrrrrrrrr")),
                    expires_at: Utc::now() + expires_in,
                    refresh_expires_at: None,
                    scopes: vec!["user:inference".into()],
                    account: None,
                    organization: None,
                }),
            )
        }

        const LIVE: &str = "sk-ant-oat01-liveliveliveliveliveliveli";

        #[tokio::test]
        async fn fills_unidentified_live_rows_and_never_refreshes() {
            let (url, hits) = profile_server(LIVE, super::PROFILE).await;
            let dir = std::env::temp_dir().join(format!(
                "anthropic-backfill-{}",
                uuid::Uuid::new_v4().simple()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("accounts.json");
            let mut identified = oauth(
                "known",
                "sk-ant-oat01-knownknownknownknownkn",
                Duration::hours(1),
            );
            if let Credential::Oauth(t) = &mut identified.credential {
                t.account = Some(TokenAccount {
                    uuid: "acc-0".into(),
                    email_address: None,
                });
            }
            AccountStore {
                accounts: vec![
                    oauth("native", LIVE, Duration::hours(1)),
                    oauth(
                        "expired",
                        "sk-ant-oat01-expiredexpiredexpiredex",
                        Duration::hours(-1),
                    ),
                    identified,
                    Account::new(
                        "key",
                        Credential::ApiKey {
                            key: ApiKey::new("sk-ant-api03-kkkkkkkkkkkkkkkkkkkkkkkk"),
                        },
                    ),
                ],
                ..AccountStore::default()
            }
            .save(&path)
            .unwrap();
            let report = backfill_store_identities(&reqwest::Client::new(), &url, &path, true)
                .await
                .unwrap();
            assert_eq!(
                report,
                vec![
                    (
                        "native".into(),
                        IdentityBackfill::Filled {
                            email: Some("me@example.com".into())
                        }
                    ),
                    ("expired".into(), IdentityBackfill::NoLiveAccessToken),
                    (
                        "known".into(),
                        IdentityBackfill::Skipped(BackfillSkip::AlreadyIdentified)
                    ),
                    (
                        "key".into(),
                        IdentityBackfill::Skipped(BackfillSkip::NotOauth)
                    ),
                ]
            );
            assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
            let stored = AccountStore::load(&path).unwrap();
            let native = stored.get("native").unwrap();
            assert_eq!(native.email.as_deref(), Some("me@example.com"));
            let tokens = native.oauth().unwrap();
            assert_eq!(tokens.account.as_ref().unwrap().uuid, "acc-1");
            assert_eq!(tokens.organization.as_ref().unwrap().uuid, "org-1");
            std::fs::remove_dir_all(dir).ok();
        }

        #[tokio::test]
        async fn test_mode_never_contacts_a_production_profile_host() {
            let dir = std::env::temp_dir().join(format!(
                "anthropic-backfill-tm-{}",
                uuid::Uuid::new_v4().simple()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("accounts.json");
            AccountStore {
                accounts: vec![oauth("native", LIVE, Duration::hours(1))],
                ..AccountStore::default()
            }
            .save(&path)
            .unwrap();
            let error =
                backfill_store_identities(&reqwest::Client::new(), PROFILE_URL, &path, true)
                    .await
                    .unwrap_err();
            assert!(matches!(error, crate::Error::Config(_)), "{error}");
            assert!(
                AccountStore::load(&path)
                    .unwrap()
                    .get("native")
                    .unwrap()
                    .email
                    .is_none()
            );
            assert_eq!(
                profile_url_from_lookup(|_| None),
                PROFILE_URL,
                "production unless overridden"
            );
            assert_eq!(
                profile_url_from_lookup(|_| Some(" http://127.0.0.1:9/p ".into())),
                "http://127.0.0.1:9/p"
            );
            std::fs::remove_dir_all(dir).ok();
        }
    }
}
