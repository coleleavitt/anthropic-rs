//! Revoke a store account's refresh token at Anthropic, then remove or
//! disable the row.
//!
//! The refresh token never leaves the crate: the caller names the account,
//! and the revocation runs under the row's refresh claim so no other process
//! can spend the token in between (a refresh racing a revoke would hand out a
//! rotation of a family that is about to die). The order is
//!
//! 1. claim the row (a peer's newer rotation is followed and claimed instead;
//!    a token already recorded dead needs no request);
//! 2. `POST` the revocation ([`OAuthClient::revoke`]); an `invalid_grant` /
//!    `invalid_token` answer means already inactive, which is success;
//! 3. only then remove the row, or disable it with its token recorded dead.
//!
//! A failed request leaves the row as it was (claim released) and returns
//! the error: nothing local changes unless Anthropic confirmed the token is
//! gone.

use std::path::Path;

use chrono::{Duration, Utc};

use crate::error::{Error, Result};
use crate::oauth::{OAuthClient, RevokeOutcome};
use crate::refresh::{DeadRefreshTokens, SharedRefreshOptions, refresh_deadline};
use crate::refresh_claim::RefreshClaim;
use crate::store::AccountStore;
use crate::token::{Credential, RefreshToken};

/// What happens to the row once the token is revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokedRowDisposition {
    /// Delete the row (the final one too).
    Remove,
    /// Keep the row, disabled, with its token recorded dead.
    Disable,
}

/// Result of [`OAuthClient::revoke_account`]. Carries no token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountRevocation {
    /// The row acted on.
    pub account_id: String,
    /// What the endpoint said, or `None` when no request was needed (the
    /// token was already recorded dead, or the row held no refresh token).
    pub outcome: Option<RevokeOutcome>,
    /// Whether the row was removed (else it was disabled).
    pub removed: bool,
}

impl OAuthClient {
    /// Revoke the refresh token of store row `account_id` and then remove or
    /// disable the row (module docs). API-key rows are refused with
    /// [`Error::Config`]: they have no token to revoke; remove them instead.
    pub async fn revoke_account(
        &self,
        path: &Path,
        account_id: &str,
        disposition: RevokedRowDisposition,
        options: &SharedRefreshOptions,
    ) -> Result<AccountRevocation> {
        let row = AccountStore::read_locked(path, |store| {
            Ok(store.get(account_id).map(|a| a.credential.clone()))
        })?
        .ok_or_else(|| Error::UnknownAccount(account_id.to_owned()))?;
        let mut refresh = match row {
            Credential::ApiKey { .. } => {
                return Err(Error::Config(
                    "an API-key account has no refresh token to revoke; remove it instead".into(),
                ));
            }
            Credential::Oauth(tokens) => tokens.refresh,
        };

        let usable = |token: &RefreshToken| {
            !token.expose().trim().is_empty() && !crate::token::is_custody_tombstone(token.expose())
        };
        let mut lease_id = None;
        let mut outcome = None;
        if usable(&refresh) {
            let mut attempt = 0u32;
            loop {
                let claim = AccountStore::mutate(path, |store| {
                    Ok(store.claim_refresh(
                        account_id,
                        &refresh,
                        Utc::now(),
                        Duration::seconds(options.lease_ttl_secs),
                        Some(std::process::id()),
                    ))
                })?;
                match claim {
                    RefreshClaim::Claimed { lease_id: id } => {
                        lease_id = Some(id);
                        break;
                    }
                    // A peer rotated it meanwhile: revoke the live token.
                    RefreshClaim::AlreadyRefreshed(tokens) => refresh = tokens.refresh,
                    // Anthropic already rejected it: nothing to send.
                    RefreshClaim::DeadToken => break,
                    RefreshClaim::UnknownAccount => {
                        return Err(Error::UnknownAccount(account_id.to_owned()));
                    }
                    RefreshClaim::Held { .. } => {
                        if attempt >= options.claim_max_attempts {
                            return Err(Error::RefreshRefused(
                                "a refresh of this account is in flight elsewhere; nothing was revoked"
                                    .into(),
                            ));
                        }
                        attempt += 1;
                        tokio::time::sleep(std::time::Duration::from_millis(options.claim_wait_ms))
                            .await;
                    }
                }
            }
        }

        if let Some(lease) = &lease_id {
            let sent = tokio::time::timeout(
                refresh_deadline(options.lease_ttl_secs),
                self.revoke(&refresh),
            )
            .await
            .unwrap_or_else(|_| Err(Error::Timeout("oauth token revoke".into())));
            match sent {
                Ok(answer) => {
                    DeadRefreshTokens::remember(refresh.expose());
                    outcome = Some(answer);
                }
                Err(error) => {
                    let _ = AccountStore::release_refresh_claim_at(path, account_id, lease);
                    return Err(error);
                }
            }
        }

        let removed = disposition == RevokedRowDisposition::Remove;
        AccountStore::mutate_allow_empty(path, |store| {
            if removed {
                store.remove(account_id);
                return Ok(());
            }
            store.mark_refresh_token_dead(account_id, &refresh);
            if let Ok(account) = store.get_mut(account_id) {
                account.disable("revoked");
                account.refresh_lease = None;
            }
            if store.current.as_deref() == Some(account_id) {
                store.current = None;
            }
            Ok(())
        })?;
        Ok(AccountRevocation {
            account_id: account_id.to_owned(),
            outcome,
            removed,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;
    use crate::account::Account;
    use crate::endpoints::Endpoints;
    use crate::token::{AccessToken, ApiKey, OAuthTokens};

    /// A revoke endpoint answering `status`/`body`, recording request bodies.
    async fn revoke_server(
        status: u16,
        body: &'static str,
    ) -> (String, Arc<AtomicUsize>, Arc<std::sync::Mutex<Vec<String>>>) {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let bodies = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (counter, seen) = (hits.clone(), bodies.clone());
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let (counter, seen) = (counter.clone(), seen.clone());
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        let Ok(read) = stream.read(&mut chunk).await else {
                            return;
                        };
                        if read == 0 {
                            return;
                        }
                        request.extend_from_slice(&chunk[..read]);
                        if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head =
                                String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                            let length = head
                                .lines()
                                .find_map(|l| {
                                    l.strip_prefix("content-length:")
                                        .and_then(|v| v.trim().parse::<usize>().ok())
                                })
                                .unwrap_or(0);
                            if request.len() >= end + 4 + length {
                                seen.lock().unwrap().push(
                                    String::from_utf8_lossy(&request[end + 4..]).into_owned(),
                                );
                                break;
                            }
                        }
                    }
                    counter.fetch_add(1, Ordering::SeqCst);
                    let response = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        (
            format!("http://{address}/v1/oauth/token/revoke"),
            hits,
            bodies,
        )
    }

    fn client(revoke_url: &str) -> OAuthClient {
        let mut endpoints = Endpoints::prod();
        endpoints.revoke_url = revoke_url.to_owned();
        endpoints.token_url = "http://127.0.0.1:9/v1/oauth/token".into();
        OAuthClient::new(endpoints)
    }

    fn oauth_row(id: &str) -> Account {
        Account::new(
            id,
            Credential::Oauth(OAuthTokens {
                access: AccessToken::new(format!("sk-ant-oat01-{id}-aaaaaaaaaaaaaaaaaaaa")),
                refresh: crate::token::RefreshToken::new(format!(
                    "sk-ant-ort01-{id}-rrrrrrrrrrrrrrrrrrrr"
                )),
                expires_at: Utc::now() + Duration::hours(1),
                refresh_expires_at: None,
                scopes: vec!["user:inference".into()],
                account: None,
                organization: None,
            }),
        )
    }

    fn store(tag: &str, accounts: Vec<Account>) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "anthropic-revoke-{tag}-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("accounts.json");
        AccountStore {
            current: accounts.first().map(|a| a.id.clone()),
            accounts,
            ..AccountStore::default()
        }
        .save(&path)
        .unwrap();
        path
    }

    fn fast() -> SharedRefreshOptions {
        SharedRefreshOptions {
            claim_max_attempts: 1,
            claim_wait_ms: 10,
            ..SharedRefreshOptions::default()
        }
    }

    #[tokio::test]
    async fn revokes_the_stored_token_then_removes_the_row() {
        let (url, hits, bodies) = revoke_server(200, "{}").await;
        let path = store("remove", vec![oauth_row("a"), oauth_row("b")]);
        let report = client(&url)
            .revoke_account(&path, "a", RevokedRowDisposition::Remove, &fast())
            .await
            .unwrap();
        assert_eq!(report.outcome, Some(RevokeOutcome::Revoked));
        assert!(report.removed);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        let sent = bodies.lock().unwrap()[0].clone();
        assert!(
            sent.contains("sk-ant-ort01-a-rrrrrrrrrrrrrrrrrrrr"),
            "{sent}"
        );
        assert!(
            sent.contains("\"token_type_hint\":\"refresh_token\""),
            "{sent}"
        );
        let stored = AccountStore::load(&path).unwrap();
        assert!(stored.get("a").is_none());
        assert!(stored.get("b").is_some());
        assert_eq!(stored.current, None, "a removed pin is cleared");
        // The final row can go too.
        client(&url)
            .revoke_account(&path, "b", RevokedRowDisposition::Remove, &fast())
            .await
            .unwrap();
        assert!(AccountStore::load(&path).unwrap().accounts.is_empty());
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[tokio::test]
    async fn an_already_inactive_token_counts_and_disable_records_it_dead() {
        let (url, hits, _) = revoke_server(400, r#"{"error":"invalid_grant"}"#).await;
        let path = store("disable", vec![oauth_row("a")]);
        let report = client(&url)
            .revoke_account(&path, "a", RevokedRowDisposition::Disable, &fast())
            .await
            .unwrap();
        assert_eq!(report.outcome, Some(RevokeOutcome::AlreadyInactive));
        assert!(!report.removed);
        let stored = AccountStore::load(&path).unwrap();
        let row = stored.get("a").unwrap();
        assert!(!row.enabled);
        assert!(row.refresh_token_is_dead(), "never presented again");
        assert!(row.refresh_lease.is_none());
        assert_eq!(stored.current, None);
        // A second revoke of the dead row sends nothing.
        let again = client(&url)
            .revoke_account(&path, "a", RevokedRowDisposition::Remove, &fast())
            .await
            .unwrap();
        assert_eq!(again.outcome, None);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert!(AccountStore::load(&path).unwrap().get("a").is_none());
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[tokio::test]
    async fn a_failed_revoke_changes_nothing_and_releases_the_claim() {
        let (url, hits, _) = revoke_server(503, r#"{"error":"unavailable"}"#).await;
        let path = store("failed", vec![oauth_row("a")]);
        let before = std::fs::read(&path).unwrap();
        let error = client(&url)
            .revoke_account(&path, "a", RevokedRowDisposition::Remove, &fast())
            .await
            .unwrap_err();
        assert!(
            matches!(error, Error::Endpoint { status: 503, .. }),
            "{error}"
        );
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        let row = AccountStore::load(&path)
            .unwrap()
            .get("a")
            .cloned()
            .unwrap();
        assert!(row.enabled && row.refresh_lease.is_none() && !row.refresh_token_is_dead());
        let after = AccountStore::load(&path).unwrap();
        let before: AccountStore = serde_json::from_slice(&before).unwrap();
        assert_eq!(
            after.get("a").unwrap().oauth().unwrap().refresh,
            before.get("a").unwrap().oauth().unwrap().refresh
        );
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[tokio::test]
    async fn a_held_claim_refuses_without_sending_and_unknown_or_api_rows_are_refused() {
        let (url, hits, _) = revoke_server(200, "{}").await;
        let mut api = Account::new(
            "key",
            Credential::ApiKey {
                key: ApiKey::new("sk-ant-api03-kkkkkkkkkkkkkkkkkkkkkkkk"),
            },
        );
        api.label = Some("key".into());
        let path = store("held", vec![oauth_row("a"), api]);
        AccountStore::mutate(&path, |store| {
            let token = store.get("a").unwrap().oauth().unwrap().refresh.clone();
            Ok(store.claim_refresh("a", &token, Utc::now(), Duration::seconds(30), Some(1)))
        })
        .unwrap();
        let error = client(&url)
            .revoke_account(&path, "a", RevokedRowDisposition::Remove, &fast())
            .await
            .unwrap_err();
        assert!(matches!(error, Error::RefreshRefused(_)), "{error}");
        assert!(AccountStore::load(&path).unwrap().get("a").is_some());
        let error = client(&url)
            .revoke_account(&path, "ghost", RevokedRowDisposition::Remove, &fast())
            .await
            .unwrap_err();
        assert!(matches!(error, Error::UnknownAccount(_)), "{error}");
        let error = client(&url)
            .revoke_account(&path, "key", RevokedRowDisposition::Remove, &fast())
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Config(_)), "{error}");
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[tokio::test]
    async fn test_mode_refuses_a_production_revoke_before_sending() {
        let path = store("testmode", vec![oauth_row("a")]);
        let error = OAuthClient::new(Endpoints::prod())
            .revoke_account(&path, "a", RevokedRowDisposition::Remove, &fast())
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Config(_)), "{error}");
        let row = AccountStore::load(&path)
            .unwrap()
            .get("a")
            .cloned()
            .unwrap();
        assert!(row.enabled && row.refresh_lease.is_none());
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }
}
