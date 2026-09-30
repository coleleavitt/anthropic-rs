//! Fail-closed refresh of a shared-store OAuth credential.
//!
//! Three faults compounded in the wild before this existed: two processes
//! presented the same refresh token at once and Anthropic revoked the
//! family; a revoked token was re-presented 156 times in an hour because the
//! dead-token guard only covered accounts the store knew; and a rotation was
//! written to a host sidecar instead of the shared store, so the next pass
//! re-presented the spent token. [`OAuthClient::refresh_shared`] is the one
//! path that spends a refresh token for a shared credential and it
//! serializes, remembers, and persists accordingly:
//!
//! 1. The store is loaded. If it cannot be read the refresh is **refused**:
//!    without the store there is no way to prove the token is not being
//!    spent elsewhere.
//! 2. If the presented token is not in the store, a live peer-rotated
//!    `current` credential is adopted instead of spending anything.
//! 3. Otherwise the caller claims the account's refresh lease (bounded,
//!    jittered retries). `already-refreshed` adopts the peer's rotation;
//!    `dead-token` refuses; a claim that never comes through refuses — the
//!    token is never presented on an uncertain claim.
//! 4. A process-local dead set short-circuits a token the store cannot
//!    remember (a credential the store has never seen).
//! 5. The token endpoint is called once. `invalid_grant` records the
//!    fingerprint as dead (locally and, when known, durably) before the error
//!    is returned.
//! 6. The rotation is committed with compare-and-swap on the presented
//!    token; a lost race adopts the winner's session when it is usable and
//!    refuses otherwise. The lease is released on every path.

use std::collections::HashSet;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use chrono::{Duration, Utc};

use crate::error::{Error, Result};
use crate::oauth::OAuthClient;
use crate::refresh_claim::{REFRESH_LEASE_TTL_SECS, RefreshClaim};
use crate::store::AccountStore;
use crate::token::{OAuthTokens, token_fingerprint};

/// Bounded like the CLI's refresh lock retry.
pub const REFRESH_CLAIM_MAX_ATTEMPTS: u32 = 5;

/// Where a returned credential came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshSource {
    /// This caller presented the refresh token and received a rotation.
    Refreshed,
    /// The presented token is unknown to the store; the store's live
    /// `current` credential was adopted instead.
    AdoptedShared,
    /// A peer process rotated the token first; its session was adopted.
    AdoptedPeer,
    /// This caller refreshed but lost the commit race; the winner's session
    /// was adopted.
    AdoptedWinner,
}

/// A credential obtained by [`OAuthClient::refresh_shared`].
#[derive(Debug, Clone)]
pub struct SharedRefreshOutcome {
    /// The session to use.
    pub tokens: OAuthTokens,
    /// How it was obtained.
    pub source: RefreshSource,
    /// The store account it belongs to, when known.
    pub account_id: Option<String>,
}

/// Tunables for [`OAuthClient::refresh_shared`].
#[derive(Debug, Clone, Copy)]
pub struct SharedRefreshOptions {
    /// Claim attempts before refusing (each waits a jittered 1–2 s).
    pub claim_max_attempts: u32,
    /// Base wait between claim attempts, in milliseconds; a random 0–100%
    /// extra is added.
    pub claim_wait_ms: u64,
    /// Lease TTL for the claim. The token-endpoint call must complete inside
    /// it; the crate's HTTP timeout must be shorter.
    pub lease_ttl_secs: i64,
}

impl Default for SharedRefreshOptions {
    fn default() -> Self {
        Self {
            claim_max_attempts: REFRESH_CLAIM_MAX_ATTEMPTS,
            claim_wait_ms: 1_000,
            lease_ttl_secs: REFRESH_LEASE_TTL_SECS,
        }
    }
}

/// Process-local registry of refresh-token fingerprints Anthropic rejected
/// with `invalid_grant`. The store persists this for accounts it knows; a
/// token absent from the store has no durable home, and this is enough to
/// stop a long-lived process hammering the endpoint with a dead token.
pub struct DeadRefreshTokens;

fn dead_set() -> &'static Mutex<HashSet<String>> {
    static SET: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    SET.get_or_init(|| Mutex::new(HashSet::new()))
}

impl DeadRefreshTokens {
    /// Remember that `refresh_token` was rejected with `invalid_grant`.
    pub fn remember(refresh_token: &str) {
        if let Ok(mut set) = dead_set().lock() {
            set.insert(token_fingerprint(refresh_token));
        }
    }

    /// Whether `refresh_token` is known-dead in this process.
    pub fn is_dead(refresh_token: &str) -> bool {
        dead_set()
            .lock()
            .map(|set| set.contains(&token_fingerprint(refresh_token)))
            .unwrap_or(false)
    }

    /// Forget every verdict (tests).
    pub fn forget_all() {
        if let Ok(mut set) = dead_set().lock() {
            set.clear();
        }
    }
}

/// Outcome class of a failed refresh, for spans and account bookkeeping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshFailure {
    /// The plugin declined to spend (claim timeout, unknown account,
    /// unreadable store, superseded commit). Nothing reached the endpoint.
    Refused,
    /// The token family is gone (`invalid_grant`, expired refresh token, or
    /// another permanent endpoint verdict). Re-login is required.
    Revoked,
    /// Everything else: transport, 5xx, malformed response.
    Error,
}

/// Classify a refresh failure.
pub fn classify_refresh_failure(error: &Error) -> RefreshFailure {
    match error {
        Error::RefreshRefused(_) => RefreshFailure::Refused,
        Error::RefreshTokenRevoked | Error::RefreshTokenExpired => RefreshFailure::Revoked,
        Error::Endpoint {
            permanent: true, ..
        } => RefreshFailure::Revoked,
        other if other.is_invalid_grant() => RefreshFailure::Revoked,
        _ => RefreshFailure::Error,
    }
}

fn jitter_ms(base: u64) -> u64 {
    let mut byte = [0u8; 1];
    let extra = if getrandom::fill(&mut byte).is_ok() {
        u64::from(byte[0])
    } else {
        128
    };
    base + base * extra / 255
}

impl OAuthClient {
    /// Refresh `presented` through the shared store at `path` with the
    /// fail-closed protocol described in the module docs.
    pub async fn refresh_shared(
        &self,
        path: &Path,
        presented: &OAuthTokens,
        options: &SharedRefreshOptions,
    ) -> Result<SharedRefreshOutcome> {
        let loaded = AccountStore::load_or_migrate_from(path, &[])
            .map_err(|error| Error::RefreshRefused(format!("shared store unreadable: {error}")))?;
        let store = loaded.store;
        let now = Utc::now();
        let shared = store.find_by_refresh_token(&presented.refresh).cloned();

        let Some(shared) = shared else {
            if let Some(adopted) =
                crate::routing::adoptable_shared_credential(&store, &presented.refresh, now)
            {
                return Ok(SharedRefreshOutcome {
                    tokens: adopted.clone(),
                    source: RefreshSource::AdoptedShared,
                    account_id: crate::routing::current_shared_account(&store, now)
                        .map(|a| a.id.clone()),
                });
            }
            // A credential the store has never seen: only the process-local
            // dead guard can protect it.
            if DeadRefreshTokens::is_dead(presented.refresh.expose()) {
                return Err(Error::RefreshTokenRevoked);
            }
            let refreshed = self
                .refresh(presented)
                .await
                .map_err(|error| remember_if_revoked(error, presented))?;
            return Ok(SharedRefreshOutcome {
                tokens: refreshed,
                source: RefreshSource::Refreshed,
                account_id: None,
            });
        };

        // Claim first and re-read under the claim: the store CAS after the
        // network call is too late, both POSTs have already happened by then.
        let mut attempt = 0u32;
        let lease_id = loop {
            let claim = AccountStore::mutate(path, |store| {
                Ok(store.claim_refresh(
                    &shared.id,
                    &presented.refresh,
                    Utc::now(),
                    Duration::seconds(options.lease_ttl_secs),
                    Some(std::process::id()),
                ))
            })?;
            match claim {
                RefreshClaim::Claimed { lease_id } => break lease_id,
                RefreshClaim::AlreadyRefreshed(tokens) => {
                    return Ok(SharedRefreshOutcome {
                        tokens,
                        source: RefreshSource::AdoptedPeer,
                        account_id: Some(shared.id.clone()),
                    });
                }
                RefreshClaim::DeadToken => return Err(Error::RefreshTokenRevoked),
                RefreshClaim::UnknownAccount => {
                    return Err(Error::RefreshRefused(
                        "refresh claim account disappeared".into(),
                    ));
                }
                RefreshClaim::Held { .. } => {
                    if attempt >= options.claim_max_attempts {
                        return Err(Error::RefreshRefused(format!(
                            "refresh claim held by another process after {} attempts; refresh was not attempted",
                            attempt + 1
                        )));
                    }
                    attempt += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(jitter_ms(
                        options.claim_wait_ms,
                    )))
                    .await;
                }
            }
        };

        let result = self
            .refresh_claimed(path, &shared.id, &lease_id, presented, shared.oauth())
            .await;
        if result.is_err() {
            let _ = AccountStore::release_refresh_claim_at(path, &shared.id, &lease_id);
        }
        result
    }

    async fn refresh_claimed(
        &self,
        path: &Path,
        account_id: &str,
        lease_id: &str,
        presented: &OAuthTokens,
        stored: Option<&OAuthTokens>,
    ) -> Result<SharedRefreshOutcome> {
        if DeadRefreshTokens::is_dead(presented.refresh.expose()) {
            return Err(Error::RefreshTokenRevoked);
        }
        // Prefer the store's row for prior metadata (refresh expiry, account,
        // organization); the presented token is the same by construction.
        let prior = stored.unwrap_or(presented);
        let refreshed = match self.refresh(prior).await {
            Ok(tokens) => tokens,
            Err(error) => {
                if error.is_invalid_grant() {
                    DeadRefreshTokens::remember(presented.refresh.expose());
                    let _ = AccountStore::mark_refresh_token_dead_at(
                        path,
                        account_id,
                        &presented.refresh,
                    );
                }
                return Err(remember_if_revoked(error, presented));
            }
        };
        let committed = AccountStore::commit_refresh_at(
            path,
            account_id,
            &presented.refresh,
            Some(lease_id),
            refreshed.clone(),
        )?;
        if committed {
            return Ok(SharedRefreshOutcome {
                tokens: refreshed,
                source: RefreshSource::Refreshed,
                account_id: Some(account_id.to_owned()),
            });
        }
        let winner = AccountStore::load_or_migrate_from(path, &[])
            .map_err(|error| {
                Error::RefreshRefused(format!(
                    "shared store unreadable after commit race: {error}"
                ))
            })?
            .store
            .get(account_id)
            .and_then(|account| account.oauth().cloned())
            .ok_or_else(|| {
                Error::RefreshRefused("oauth refresh was superseded by an unusable row".into())
            })?;
        Ok(SharedRefreshOutcome {
            tokens: winner,
            source: RefreshSource::AdoptedWinner,
            account_id: Some(account_id.to_owned()),
        })
    }
}

/// Non-secret receipt for the shared-store credential a request was sent
/// with: the store row id, the provider account behind it (the token's
/// account uuid, else the row id), and the access token's fingerprint as the
/// rotation marker.
pub fn shared_credential_receipt(
    store_account_id: &str,
    tokens: &OAuthTokens,
) -> crate::retry::CredentialReceipt {
    crate::retry::CredentialReceipt {
        credential_id: store_account_id.to_owned(),
        account_id: tokens
            .account
            .as_ref()
            .map_or_else(|| store_account_id.to_owned(), |a| a.uuid.clone()),
        version: token_fingerprint(tokens.access.expose()),
    }
}

/// Result of [`OAuthClient::recover_unauthorized`].
#[derive(Debug)]
pub struct UnauthorizedRecovery {
    /// Whether to re-send once, and why (safe to log).
    pub decision: crate::retry::RetryAfter401,
    /// The refreshed credential, present only when `decision.retry`.
    pub outcome: Option<SharedRefreshOutcome>,
    /// The refresh failure, when re-authorization itself failed. A
    /// [`Error::RefreshTokenRevoked`] here means the token is dead.
    pub failure: Option<Error>,
}

impl OAuthClient {
    /// Recover from a genuine upstream 401 on a shared-store credential.
    ///
    /// The server can revoke an access token before its stored expiry (a
    /// peer rotated the family, a logout, a server-side invalidation). This
    /// forces one refresh of the store row that owns `rejected_access`
    /// through [`Self::refresh_shared`] — under the cross-process claim, so
    /// it adopts a peer's rotation instead of double-spending — and then
    /// applies [`crate::retry::decide_retry_after_401`]: only a new access
    /// token for the same row and provider account earns the single retry,
    /// so a still-rejected credential is never re-sent in a loop. A token
    /// unknown to the store yields `ReauthorizeFailed` without any I/O
    /// beyond the store read.
    ///
    /// Port of the fork's `recoverSharedAccessTokenAfter401` (c327d6e) with
    /// upstream's `decideScopedRetryAfter401` classification.
    pub async fn recover_unauthorized(
        &self,
        path: &Path,
        rejected_access: &str,
        options: &SharedRefreshOptions,
    ) -> Result<UnauthorizedRecovery> {
        use crate::retry::{RetryAfter401, RetryAfter401Reason, decide_retry_after_401};
        let failed = |failure: Option<Error>| UnauthorizedRecovery {
            decision: RetryAfter401 {
                retry: false,
                reason: RetryAfter401Reason::ReauthorizeFailed,
            },
            outcome: None,
            failure,
        };
        let Ok(loaded) = AccountStore::load_or_migrate_from(path, &[]) else {
            return Ok(failed(None));
        };
        let Some(account) = loaded.store.find_by_access_token(rejected_access) else {
            return Ok(failed(None));
        };
        let Some(stored) = account
            .oauth()
            .filter(|t| !t.refresh.expose().trim().is_empty())
        else {
            return Ok(failed(None));
        };
        let served = shared_credential_receipt(&account.id, stored);
        let outcome = match self.refresh_shared(path, stored, options).await {
            Ok(outcome) => outcome,
            Err(error) => return Ok(failed(Some(error))),
        };
        let current_id = outcome
            .account_id
            .clone()
            .unwrap_or_else(|| account.id.clone());
        let current = shared_credential_receipt(&current_id, &outcome.tokens);
        // A refresh response usually omits the account block; the row's
        // identity carries over, so compare against the served identity.
        let current = crate::retry::CredentialReceipt {
            account_id: if outcome.tokens.account.is_some() {
                current.account_id
            } else {
                served.account_id.clone()
            },
            ..current
        };
        let decision = decide_retry_after_401(&served, Some(&current));
        Ok(UnauthorizedRecovery {
            decision,
            outcome: decision.retry.then_some(outcome),
            failure: None,
        })
    }
}

fn remember_if_revoked(error: Error, presented: &OAuthTokens) -> Error {
    if error.is_invalid_grant() {
        DeadRefreshTokens::remember(presented.refresh.expose());
        return Error::RefreshTokenRevoked;
    }
    error
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use chrono::{DateTime, TimeZone};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;
    use crate::account::Account;
    use crate::endpoints::Endpoints;
    use crate::token::{AccessToken, Credential, RefreshToken};

    const NEW_REFRESH: &str = "sk-ant-ort01-newnewnewnewnewnewnewnew";
    const NEW_ACCESS: &str = "sk-ant-oat01-newnewnewnewnewnewnewnew";

    /// The process-local dead set is global, so each test presents its own
    /// token to stay independent of its parallel siblings.
    fn old_tokens(tag: &str) -> OAuthTokens {
        tokens(
            &format!("sk-ant-ort01-old-{tag}-aaaaaaaaaaaaaaaaaaaaaa"),
            &format!("sk-ant-oat01-old-{tag}-aaaaaaaaaaaaaaaaaaaaaa"),
            at(-10),
        )
    }

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000 + secs, 0).unwrap()
    }

    fn tokens(refresh: &str, access: &str, expires_at: DateTime<Utc>) -> OAuthTokens {
        OAuthTokens {
            access: AccessToken::new(access),
            refresh: RefreshToken::new(refresh),
            expires_at,
            refresh_expires_at: Some(Utc::now() + Duration::days(20)),
            scopes: vec!["user:inference".into()],
            account: None,
            organization: None,
        }
    }

    fn store_path(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "anthropic-refresh-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("accounts.json")
    }

    fn seeded_store(path: &Path, presented: &OAuthTokens) -> AccountStore {
        let store = AccountStore {
            version: 1,
            accounts: vec![Account::new("shared", Credential::Oauth(presented.clone()))],
            current: Some("shared".into()),
            ..AccountStore::default()
        };
        store.save(path).unwrap();
        store
    }

    /// A token endpoint that answers every request with the same status/body
    /// and counts presentations.
    async fn token_server(status: u16, body: &'static str) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let counter = counter.clone();
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
                            let headers =
                                String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                            let length = headers
                                .lines()
                                .find_map(|l| {
                                    l.strip_prefix("content-length:")
                                        .and_then(|v| v.trim().parse::<usize>().ok())
                                })
                                .unwrap_or(0);
                            if request.len() >= end + 4 + length {
                                break;
                            }
                        }
                    }
                    counter.fetch_add(1, Ordering::SeqCst);
                    let reason = if status == 200 { "OK" } else { "Bad Request" };
                    let response = format!(
                        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        (format!("http://{address}"), hits)
    }

    fn client(token_url: &str) -> OAuthClient {
        let mut endpoints = Endpoints::prod();
        endpoints.token_url = token_url.to_owned();
        OAuthClient::new(endpoints)
    }

    const ROTATED_BODY: &str = r#"{"access_token":"sk-ant-oat01-newnewnewnewnewnewnewnew","refresh_token":"sk-ant-ort01-newnewnewnewnewnewnewnew","expires_in":3600,"scope":"user:inference user:profile"}"#;
    const INVALID_GRANT_BODY: &str =
        r#"{"error":"invalid_grant","error_description":"Refresh token not found or invalid"}"#;

    #[tokio::test]
    async fn unauthorized_recovery_retries_once_on_rotation_and_never_on_unknown_tokens() {
        let (url, hits) = token_server(200, ROTATED_BODY).await;
        const TAG: &str = "recover401";
        let path = store_path(TAG);
        let presented = old_tokens(TAG);
        seeded_store(&path, &presented);
        let client = client(&url);

        let unknown = client
            .recover_unauthorized(
                &path,
                "sk-ant-oat01-not-in-the-store-aaaaaaaa",
                &SharedRefreshOptions::default(),
            )
            .await
            .unwrap();
        assert!(!unknown.decision.retry);
        assert_eq!(
            unknown.decision.reason,
            crate::retry::RetryAfter401Reason::ReauthorizeFailed
        );
        assert_eq!(hits.load(Ordering::SeqCst), 0);

        let recovered = client
            .recover_unauthorized(
                &path,
                presented.access.expose(),
                &SharedRefreshOptions::default(),
            )
            .await
            .unwrap();
        assert!(recovered.decision.retry);
        assert_eq!(
            recovered.decision.reason,
            crate::retry::RetryAfter401Reason::Rotated
        );
        assert_eq!(
            recovered.outcome.unwrap().tokens.access.expose(),
            NEW_ACCESS
        );
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        // The rejected token is gone from the store now: a second 401 on it
        // (a stale in-flight request) cannot trigger another spend.
        let again = client
            .recover_unauthorized(
                &path,
                presented.access.expose(),
                &SharedRefreshOptions::default(),
            )
            .await
            .unwrap();
        assert!(!again.decision.retry);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn unauthorized_recovery_reports_a_revoked_refresh_without_retrying() {
        let (url, _hits) = token_server(400, INVALID_GRANT_BODY).await;
        const TAG: &str = "recover401-dead";
        let path = store_path(TAG);
        let presented = old_tokens(TAG);
        seeded_store(&path, &presented);
        let recovery = client(&url)
            .recover_unauthorized(
                &path,
                presented.access.expose(),
                &SharedRefreshOptions::default(),
            )
            .await
            .unwrap();
        assert!(!recovery.decision.retry);
        assert!(recovery.outcome.is_none());
        assert!(matches!(recovery.failure, Some(Error::RefreshTokenRevoked)));
    }

    #[test]
    fn shared_receipts_carry_only_fingerprints() {
        let tokens = old_tokens("receipt");
        let receipt = shared_credential_receipt("row", &tokens);
        assert_eq!(receipt.credential_id, "row");
        assert_eq!(receipt.account_id, "row");
        assert_eq!(receipt.version, token_fingerprint(tokens.access.expose()));
        assert!(!format!("{receipt:?}").contains("sk-ant"));
    }

    #[tokio::test]
    async fn refresh_persists_rotation_to_the_shared_store_and_releases_the_lease() {
        let (url, hits) = token_server(200, ROTATED_BODY).await;
        const TAG: &str = "persist";
        let path = store_path(TAG);
        let presented = old_tokens(TAG);
        seeded_store(&path, &presented);
        let outcome = client(&url)
            .refresh_shared(&path, &presented, &SharedRefreshOptions::default())
            .await
            .unwrap();
        assert_eq!(outcome.source, RefreshSource::Refreshed);
        assert_eq!(outcome.tokens.refresh.expose(), NEW_REFRESH);
        assert_eq!(outcome.tokens.access.expose(), NEW_ACCESS);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        let stored = AccountStore::load(&path).unwrap();
        let row = stored.get("shared").unwrap();
        // The next pass reads the rotated token, never the spent one.
        assert_eq!(row.oauth().unwrap().refresh.expose(), NEW_REFRESH);
        assert!(row.refresh_lease.is_none());
        assert!(row.dead_refresh_fingerprint.is_none());
        assert_eq!(stored.current.as_deref(), Some("shared"));
        // A second call with the spent token adopts the live rotation without
        // presenting anything: the spent token no longer matches any row, so
        // the store's current credential is adopted.
        let again = client(&url)
            .refresh_shared(&path, &presented, &SharedRefreshOptions::default())
            .await
            .unwrap();
        assert_eq!(again.source, RefreshSource::AdoptedShared);
        assert_eq!(again.tokens.refresh.expose(), NEW_REFRESH);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[tokio::test]
    async fn invalid_grant_is_remembered_and_never_re_presented() {
        let (url, hits) = token_server(400, INVALID_GRANT_BODY).await;
        const TAG: &str = "dead";
        let path = store_path(TAG);
        let presented = old_tokens(TAG);
        seeded_store(&path, &presented);
        let error = client(&url)
            .refresh_shared(&path, &presented, &SharedRefreshOptions::default())
            .await
            .unwrap_err();
        assert!(matches!(error, Error::RefreshTokenRevoked), "{error}");
        assert_eq!(classify_refresh_failure(&error), RefreshFailure::Revoked);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        let row = AccountStore::load(&path).unwrap();
        assert!(row.get("shared").unwrap().refresh_token_is_dead());
        assert!(row.get("shared").unwrap().refresh_lease.is_none());
        // 156 presentations in an hour: every later call short-circuits.
        for _ in 0..3 {
            let error = client(&url)
                .refresh_shared(&path, &presented, &SharedRefreshOptions::default())
                .await
                .unwrap_err();
            assert!(matches!(error, Error::RefreshTokenRevoked));
        }
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        // A credential the store has never seen is guarded process-locally.
        let unknown = tokens(
            "sk-ant-ort01-unknownunknownunknownunk",
            "sk-ant-oat01-unknownunknownunknownunk",
            at(-10),
        );
        let path2 = store_path("dead-unknown");
        seeded_store(&path2, &tokens(NEW_REFRESH, NEW_ACCESS, at(-10)));
        let first = client(&url)
            .refresh_shared(&path2, &unknown, &SharedRefreshOptions::default())
            .await
            .unwrap_err();
        assert!(matches!(first, Error::RefreshTokenRevoked));
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        let second = client(&url)
            .refresh_shared(&path2, &unknown, &SharedRefreshOptions::default())
            .await
            .unwrap_err();
        assert!(matches!(second, Error::RefreshTokenRevoked));
        assert_eq!(
            hits.load(Ordering::SeqCst),
            2,
            "a dead token must not reach the network again"
        );
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
        std::fs::remove_dir_all(path2.parent().unwrap()).ok();
    }

    #[tokio::test]
    async fn held_claim_refuses_without_spending_and_unreadable_store_refuses() {
        let (url, hits) = token_server(200, ROTATED_BODY).await;
        const TAG: &str = "held";
        let path = store_path(TAG);
        let presented = old_tokens(TAG);
        seeded_store(&path, &presented);
        // Another process holds the claim for the whole test.
        let claim = AccountStore::claim_refresh_at(&path, "shared", &presented.refresh, Utc::now())
            .unwrap();
        assert!(matches!(claim, RefreshClaim::Claimed { .. }));
        let options = SharedRefreshOptions {
            claim_max_attempts: 1,
            claim_wait_ms: 1,
            ..Default::default()
        };
        let error = client(&url)
            .refresh_shared(&path, &presented, &options)
            .await
            .unwrap_err();
        assert!(matches!(error, Error::RefreshRefused(_)), "{error}");
        assert_eq!(classify_refresh_failure(&error), RefreshFailure::Refused);
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "never spend after claim contention times out"
        );
        assert!(!error.is_permanent());
        // The foreign claim is untouched.
        assert!(
            AccountStore::load(&path)
                .unwrap()
                .get("shared")
                .unwrap()
                .refresh_lease
                .is_some()
        );
        // No store at all: refuse rather than spend unserialized.
        let missing = store_path("missing").join("nested").join("accounts.json");
        std::fs::create_dir_all(missing.parent().unwrap()).unwrap();
        std::fs::write(&missing, b"{not json").unwrap();
        let error = client(&url)
            .refresh_shared(&missing, &presented, &options)
            .await
            .unwrap_err();
        assert!(matches!(error, Error::RefreshRefused(_)));
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[tokio::test]
    async fn unknown_token_adopts_a_live_rotated_shared_credential() {
        let (url, hits) = token_server(200, ROTATED_BODY).await;
        let path = store_path("adopt");
        let live = tokens(NEW_REFRESH, NEW_ACCESS, Utc::now() + Duration::hours(1));
        seeded_store(&path, &live);
        let mine = old_tokens("adopt");
        let outcome = client(&url)
            .refresh_shared(&path, &mine, &SharedRefreshOptions::default())
            .await
            .unwrap();
        assert_eq!(outcome.source, RefreshSource::AdoptedShared);
        assert_eq!(outcome.tokens.refresh.expose(), NEW_REFRESH);
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        // When the shared credential is also expired, refresh normally.
        let expired = tokens(NEW_REFRESH, NEW_ACCESS, at(-10));
        seeded_store(&path, &expired);
        let outcome = client(&url)
            .refresh_shared(&path, &mine, &SharedRefreshOptions::default())
            .await
            .unwrap();
        assert_eq!(outcome.source, RefreshSource::Refreshed);
        assert_eq!(outcome.account_id, None);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn failure_classification() {
        assert_eq!(
            classify_refresh_failure(&Error::RefreshTokenExpired),
            RefreshFailure::Revoked
        );
        assert_eq!(
            classify_refresh_failure(&Error::Endpoint {
                status: 500,
                permanent: false,
                error_code: None,
                retry_after_ms: None,
                body: String::new()
            }),
            RefreshFailure::Error
        );
        assert_eq!(
            classify_refresh_failure(&Error::RefreshRefused("x".into())),
            RefreshFailure::Refused
        );
        let invalid = Error::Endpoint {
            status: 400,
            permanent: true,
            error_code: Some("invalid_grant".into()),
            retry_after_ms: None,
            body: String::new(),
        };
        assert!(invalid.is_invalid_grant());
        assert!(Error::RefreshTokenRevoked.is_permanent());
        DeadRefreshTokens::remember("sk-ant-ort01-zzzzzzzzzzzzzzzzzzzzzzz");
        assert!(DeadRefreshTokens::is_dead(
            "sk-ant-ort01-zzzzzzzzzzzzzzzzzzzzzzz"
        ));
        assert!(!DeadRefreshTokens::is_dead(
            "sk-ant-ort01-yyyyyyyyyyyyyyyyyyyyyyy"
        ));
    }
}
