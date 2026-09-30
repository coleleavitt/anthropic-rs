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
//! 1. The store is read **under its lock**. If it cannot be read the refresh
//!    is **refused**: without the store there is no way to prove the token is
//!    not being spent elsewhere.
//! 2. Only a refresh token the store holds right now is ever spent. When the
//!    presented token is not in the store:
//!    - a row holding the same login (account uuid + organization) means a
//!      peer rotated it: its live session is adopted, or, when that session
//!      has expired too, *the store's* token is refreshed instead of the
//!      caller's stale one;
//!    - otherwise a live peer-rotated `current` credential is adopted;
//!    - otherwise the refresh is refused. A bare refresh of a token the store
//!      has never held needs [`SharedRefreshOptions::allow_unshared`].
//! 3. The caller claims the account's refresh lease (bounded, jittered
//!    retries). `already-refreshed` adopts the peer's rotation; `dead-token`
//!    refuses; a claim that never comes through refuses — the token is never
//!    presented on an uncertain claim.
//! 4. A process-local dead set short-circuits a token the store cannot
//!    remember (a credential the store has never seen).
//! 5. The token endpoint is called once, bounded by a deadline shorter than
//!    the claim ([`refresh_deadline`]). Only HTTP 400 `invalid_grant` records
//!    the fingerprint as dead (locally, and durably when the store still
//!    holds that token); every other failure is transient and leaves the
//!    row untouched.
//! 6. The rotation is committed with compare-and-swap on the presented token
//!    and the still-live claim; a result obtained under a lapsed claim is
//!    discarded. A lost race adopts the winner's session when it is usable
//!    and refuses otherwise. The lease is released on every path.
//! 7. After a rotation this call performed, Claude Code's credential file is
//!    brought forward when it still holds the spent token
//!    ([`SharedRefreshOptions::native_publish`],
//!    [`crate::credentials::publish_native_rotation`]). The rotation is
//!    already committed; a failed publish never fails the refresh and is
//!    reported on [`SharedRefreshOutcome::native_publish`].

use std::collections::HashSet;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use chrono::{Duration, Utc};

use crate::credentials::{NativePublish, NativePublishOutcome};
use crate::error::{Error, Result, RevocationOrigin};
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
    /// What publishing the rotation to Claude Code's credential file did.
    /// `None` when this call did not rotate the token itself, or the
    /// publish is off or suppressed by OAuth test mode.
    pub native_publish: Option<NativePublishOutcome>,
}

/// Tunables for [`OAuthClient::refresh_shared`].
#[derive(Debug, Clone)]
pub struct SharedRefreshOptions {
    /// Claim attempts before refusing (each waits a jittered 1–2 s).
    pub claim_max_attempts: u32,
    /// Base wait between claim attempts, in milliseconds; a random 0–100%
    /// extra is added.
    pub claim_wait_ms: u64,
    /// Lease TTL for the claim. The token-endpoint call is cut off at
    /// [`refresh_deadline`] of this, so it always ends inside the claim.
    pub lease_ttl_secs: i64,
    /// Permit a bare refresh of a token the store has never held (no row
    /// holds it and no row holds the same login). Off by default: such a
    /// token may be one a peer just rotated, and spending it revokes the
    /// family. Only the process-local dead set guards it.
    pub allow_unshared: bool,
    /// Publish a rotation this call performed to Claude Code's credential
    /// file when that file still holds the spent refresh token. Default:
    /// [`NativePublish::from_env`] (on unless
    /// [`crate::credentials::NATIVE_PUBLISH_ENV`] turns it off);
    /// [`NativePublish::Auto`] is suppressed in OAuth test mode.
    pub native_publish: NativePublish,
}

impl Default for SharedRefreshOptions {
    fn default() -> Self {
        Self {
            claim_max_attempts: REFRESH_CLAIM_MAX_ATTEMPTS,
            claim_wait_ms: 1_000,
            lease_ttl_secs: REFRESH_LEASE_TTL_SECS,
            allow_unshared: false,
            native_publish: NativePublish::from_env(),
        }
    }
}

/// How long the token-endpoint call may take under a claim of
/// `lease_ttl_secs`: the TTL minus a margin of 5 s (a third of the TTL for
/// short test leases), so the claim never lapses while the token is in flight.
pub fn refresh_deadline(lease_ttl_secs: i64) -> std::time::Duration {
    let ttl_ms = lease_ttl_secs.max(1).saturating_mul(1_000);
    let margin_ms = (ttl_ms / 3).min(5_000);
    std::time::Duration::from_millis(u64::try_from(ttl_ms - margin_ms).unwrap_or(1_000))
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
    /// The token is gone: HTTP 400 `invalid_grant`, or the refresh token's
    /// own expiry has passed. Re-login is required.
    Revoked,
    /// Everything else: transport, timeouts, 5xx, other 4xx
    /// (`invalid_client`, `invalid_request`, …), malformed responses. None of
    /// these says the token is dead.
    Error,
}

/// Classify a refresh failure.
pub fn classify_refresh_failure(error: &Error) -> RefreshFailure {
    match error {
        Error::RefreshRefused(_) => RefreshFailure::Refused,
        Error::RefreshTokenRevoked { .. } | Error::RefreshTokenExpired => RefreshFailure::Revoked,
        other if other.is_invalid_grant() => RefreshFailure::Revoked,
        _ => RefreshFailure::Error,
    }
}

/// What the store says about a presented refresh token, read under the lock.
enum Located {
    /// A row holds exactly this token: spend it (the row's copy, with the
    /// store's metadata) under that row's claim.
    Held {
        account_id: String,
        tokens: OAuthTokens,
    },
    /// A row holds the same login with a different (newer) token.
    Rotated {
        account_id: String,
        tokens: OAuthTokens,
        live: bool,
    },
    /// No row knows this login, but the store's `current` credential is a
    /// live peer rotation.
    SharedLive {
        account_id: Option<String>,
        tokens: OAuthTokens,
    },
    /// The store has never held this token or this login.
    Unknown,
}

fn same_login(stored: &OAuthTokens, presented: &OAuthTokens) -> bool {
    let (Some(a), Some(b)) = (&stored.account, &presented.account) else {
        return false;
    };
    !a.uuid.trim().is_empty()
        && a.uuid == b.uuid
        && stored.organization.as_ref().map(|o| &o.uuid)
            == presented.organization.as_ref().map(|o| &o.uuid)
}

fn locate(store: &AccountStore, presented: &OAuthTokens, now: chrono::DateTime<Utc>) -> Located {
    if let Some(account) = store.find_by_refresh_token(&presented.refresh)
        && let Some(tokens) = account.oauth()
    {
        return Located::Held {
            account_id: account.id.clone(),
            tokens: tokens.clone(),
        };
    }
    if let Some((account, tokens)) = store.accounts.iter().find_map(|account| {
        let tokens = account.oauth()?;
        same_login(tokens, presented).then_some((account, tokens))
    }) {
        return Located::Rotated {
            account_id: account.id.clone(),
            tokens: tokens.clone(),
            live: account.oauth_credential_is_live(now)
                && tokens.expires_at
                    > now + Duration::seconds(crate::routing::SHARED_CREDENTIAL_ADOPTION_SKEW_SECS),
        };
    }
    if let Some(tokens) =
        crate::routing::adoptable_shared_credential(store, &presented.refresh, now)
    {
        return Located::SharedLive {
            account_id: crate::routing::current_shared_account(store, now).map(|a| a.id.clone()),
            tokens: tokens.clone(),
        };
    }
    Located::Unknown
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
        let now = Utc::now();
        let located = AccountStore::read_locked(path, |store| Ok(locate(store, presented, now)))
            .map_err(|error| Error::RefreshRefused(format!("shared store unreadable: {error}")))?;

        let (account_id, spend) = match located {
            Located::Held { account_id, tokens } => (account_id, tokens),
            Located::Rotated {
                account_id,
                tokens,
                live: true,
            } => {
                return Ok(SharedRefreshOutcome {
                    tokens,
                    source: RefreshSource::AdoptedPeer,
                    account_id: Some(account_id),
                    native_publish: None,
                });
            }
            // The caller's token is stale and the store's session has expired
            // too: spend the store's token, never the caller's.
            Located::Rotated {
                account_id,
                tokens,
                live: false,
            } => (account_id, tokens),
            Located::SharedLive { account_id, tokens } => {
                return Ok(SharedRefreshOutcome {
                    tokens,
                    source: RefreshSource::AdoptedShared,
                    account_id,
                    native_publish: None,
                });
            }
            Located::Unknown => {
                if !options.allow_unshared {
                    return Err(Error::RefreshRefused(
                        "the presented refresh token is not held by the shared store; \
                         refusing to spend it"
                            .into(),
                    ));
                }
                // Explicitly unshared: only the process-local dead guard can
                // protect it.
                if DeadRefreshTokens::is_dead(presented.refresh.expose()) {
                    return Err(Error::RefreshTokenRevoked {
                        origin: RevocationOrigin::LocalDeadSet,
                    });
                }
                let refreshed = match tokio::time::timeout(
                    refresh_deadline(options.lease_ttl_secs),
                    self.refresh(presented),
                )
                .await
                {
                    Ok(result) => result.map_err(|error| remember_if_revoked(error, presented))?,
                    Err(_) => return Err(Error::Timeout("oauth token refresh".into())),
                };
                let native_publish = self
                    .publish_native(&options.native_publish, &presented.refresh, &refreshed)
                    .await;
                return Ok(SharedRefreshOutcome {
                    tokens: refreshed,
                    source: RefreshSource::Refreshed,
                    account_id: None,
                    native_publish,
                });
            }
        };

        // Claim first and re-read under the claim: the store CAS after the
        // network call is too late, both POSTs have already happened by then.
        let mut attempt = 0u32;
        let lease_id = loop {
            let claim = AccountStore::mutate(path, |store| {
                Ok(store.claim_refresh(
                    &account_id,
                    &spend.refresh,
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
                        account_id: Some(account_id),
                        native_publish: None,
                    });
                }
                RefreshClaim::DeadToken => {
                    return Err(Error::RefreshTokenRevoked {
                        origin: RevocationOrigin::DeadTokenClaim,
                    });
                }
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
            .refresh_claimed(path, &account_id, &lease_id, &spend, options)
            .await;
        if result.is_err() {
            let _ = AccountStore::release_refresh_claim_at(path, &account_id, &lease_id);
        }
        result
    }

    async fn refresh_claimed(
        &self,
        path: &Path,
        account_id: &str,
        lease_id: &str,
        spend: &OAuthTokens,
        options: &SharedRefreshOptions,
    ) -> Result<SharedRefreshOutcome> {
        if DeadRefreshTokens::is_dead(spend.refresh.expose()) {
            return Err(Error::RefreshTokenRevoked {
                origin: RevocationOrigin::LocalDeadSet,
            });
        }
        // Bounded inside the claim even when the caller supplied its own HTTP
        // client (`with_http`) without a timeout.
        let outcome = tokio::time::timeout(
            refresh_deadline(options.lease_ttl_secs),
            self.refresh(spend),
        )
        .await;
        let refreshed = match outcome {
            Ok(Ok(tokens)) => tokens,
            Ok(Err(error)) if error.is_invalid_grant() => {
                DeadRefreshTokens::remember(spend.refresh.expose());
                // Marks only when the store still holds exactly this token:
                // a peer's newer rotation never inherits the verdict.
                let _ = AccountStore::mark_refresh_token_dead_at(path, account_id, &spend.refresh);
                return Err(error.into_revocation().unwrap_or_else(|other| other));
            }
            // Transient: nothing about the token is recorded; the claim is
            // released by the caller.
            Ok(Err(error)) => return Err(error),
            Err(_) => return Err(Error::Timeout("oauth token refresh".into())),
        };
        let committed = AccountStore::commit_refresh_at(
            path,
            account_id,
            &spend.refresh,
            Some(lease_id),
            refreshed.clone(),
        )?;
        if committed {
            let native_publish = self
                .publish_native(&options.native_publish, &spend.refresh, &refreshed)
                .await;
            return Ok(SharedRefreshOutcome {
                tokens: refreshed,
                source: RefreshSource::Refreshed,
                account_id: Some(account_id.to_owned()),
                native_publish,
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
        if winner.refresh == spend.refresh {
            // Nobody rotated the row, so the commit failed on the claim: it
            // lapsed or was taken over while the token was in flight. The
            // result is discarded rather than committed outside the claim.
            return Err(Error::RefreshRefused(
                "refresh claim lapsed before the result could be committed; the result was discarded"
                    .into(),
            ));
        }
        Ok(SharedRefreshOutcome {
            tokens: winner,
            source: RefreshSource::AdoptedWinner,
            account_id: Some(account_id.to_owned()),
            native_publish: None,
        })
    }

    /// Bring Claude Code's credential file forward after a rotation this
    /// process committed (module docs, step 7). Blocking file work (Claude
    /// Code's write lock may be waited on for a few seconds) runs off the
    /// async worker.
    async fn publish_native(
        &self,
        policy: &NativePublish,
        spent: &crate::token::RefreshToken,
        rotated: &OAuthTokens,
    ) -> Option<NativePublishOutcome> {
        let path = policy.target(self.is_test_mode())?;
        let spent = spent.clone();
        let rotated = rotated.clone();
        let work = move || crate::credentials::publish_native_rotation(&path, &spent, &rotated);
        Some(match tokio::runtime::Handle::try_current() {
            Ok(handle) => handle.spawn_blocking(work).await.unwrap_or_else(|e| {
                NativePublishOutcome::Failed(format!("publish worker failed: {e}"))
            }),
            Err(_) => work(),
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
    match error.into_revocation() {
        Ok(revoked) => {
            DeadRefreshTokens::remember(presented.refresh.expose());
            revoked
        }
        Err(other) => other,
    }
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
        assert!(matches!(
            recovery.failure,
            Some(Error::RefreshTokenRevoked { .. })
        ));
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

    /// Claude Code's credential file beside the test store, holding
    /// `refresh` (0600, the shape Claude Code writes).
    fn native_beside(path: &Path, refresh: &str) -> std::path::PathBuf {
        let native = path.parent().unwrap().join(".credentials.json");
        let doc = serde_json::json!({
            "claudeAiOauth": {
                "accessToken": "sk-ant-oat01-nativenativenativenative",
                "refreshToken": refresh,
                "expiresAt": 1_700_000_000_000_i64,
                "scopes": ["user:inference"],
                "subscriptionType": "max"
            },
            "mcpOAuth": { "keep": true }
        });
        std::fs::write(&native, serde_json::to_vec(&doc).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&native, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        native
    }

    fn publishing_to(native: &Path) -> SharedRefreshOptions {
        SharedRefreshOptions {
            native_publish: NativePublish::At(native.to_path_buf()),
            ..SharedRefreshOptions::default()
        }
    }

    #[tokio::test]
    async fn a_rotation_is_published_to_claude_code_when_it_held_the_spent_token() {
        let (url, hits) = token_server(200, ROTATED_BODY).await;
        const TAG: &str = "native-publish";
        let path = store_path(TAG);
        let presented = old_tokens(TAG);
        seeded_store(&path, &presented);
        let native = native_beside(&path, presented.refresh.expose());
        let outcome = client(&url)
            .refresh_shared(&path, &presented, &publishing_to(&native))
            .await
            .unwrap();
        assert_eq!(outcome.source, RefreshSource::Refreshed);
        assert_eq!(outcome.native_publish, Some(NativePublishOutcome::Written));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        let doc: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&native).unwrap()).unwrap();
        assert_eq!(doc["claudeAiOauth"]["refreshToken"], NEW_REFRESH);
        assert_eq!(doc["claudeAiOauth"]["accessToken"], NEW_ACCESS);
        assert_eq!(doc["claudeAiOauth"]["subscriptionType"], "max");
        assert_eq!(doc["mcpOAuth"]["keep"], true);
        // The store and Claude Code now agree; the next pass adopts, spends
        // nothing and publishes nothing.
        let again = client(&url)
            .refresh_shared(&path, &presented, &publishing_to(&native))
            .await
            .unwrap();
        assert_eq!(again.source, RefreshSource::AdoptedShared);
        assert_eq!(again.native_publish, None);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[tokio::test]
    async fn a_native_file_holding_another_token_is_never_rewritten() {
        let (url, _hits) = token_server(200, ROTATED_BODY).await;
        const TAG: &str = "native-foreign";
        let path = store_path(TAG);
        let presented = old_tokens(TAG);
        seeded_store(&path, &presented);
        let native = native_beside(&path, "sk-ant-ort01-claudecoderotatedonitsown00");
        let before = std::fs::read(&native).unwrap();
        let outcome = client(&url)
            .refresh_shared(&path, &presented, &publishing_to(&native))
            .await
            .unwrap();
        assert_eq!(outcome.native_publish, Some(NativePublishOutcome::NotHeld));
        assert_eq!(std::fs::read(&native).unwrap(), before);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[tokio::test]
    async fn a_failed_refresh_publishes_nothing() {
        let (url, _hits) = token_server(400, INVALID_GRANT_BODY).await;
        const TAG: &str = "native-dead";
        let path = store_path(TAG);
        let presented = old_tokens(TAG);
        seeded_store(&path, &presented);
        let native = native_beside(&path, presented.refresh.expose());
        let before = std::fs::read(&native).unwrap();
        let error = client(&url)
            .refresh_shared(&path, &presented, &publishing_to(&native))
            .await
            .unwrap_err();
        assert!(
            matches!(error, Error::RefreshTokenRevoked { .. }),
            "{error}"
        );
        assert_eq!(std::fs::read(&native).unwrap(), before);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[tokio::test]
    async fn the_publish_is_off_by_policy_and_auto_is_suppressed_in_test_mode() {
        for (tag, policy) in [
            ("native-off", NativePublish::Off),
            // `cfg(test)` is OAuth test mode: `Auto` never resolves (or
            // reads) the real `~/.claude/.credentials.json`.
            ("native-auto", NativePublish::Auto),
        ] {
            let (url, _hits) = token_server(200, ROTATED_BODY).await;
            let path = store_path(tag);
            let presented = old_tokens(tag);
            seeded_store(&path, &presented);
            let native = native_beside(&path, presented.refresh.expose());
            let before = std::fs::read(&native).unwrap();
            let options = SharedRefreshOptions {
                native_publish: policy.clone(),
                ..SharedRefreshOptions::default()
            };
            let outcome = client(&url)
                .refresh_shared(&path, &presented, &options)
                .await
                .unwrap();
            assert_eq!(outcome.source, RefreshSource::Refreshed, "{policy:?}");
            assert_eq!(outcome.native_publish, None, "{policy:?}");
            assert_eq!(std::fs::read(&native).unwrap(), before, "{policy:?}");
            std::fs::remove_dir_all(path.parent().unwrap()).ok();
        }
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
        assert!(
            matches!(error, Error::RefreshTokenRevoked { .. }),
            "{error}"
        );
        // The verdict says it came from the endpoint, not a local record.
        assert_eq!(
            error.revocation_origin(),
            Some(&RevocationOrigin::Endpoint {
                status: 400,
                error_code: Some("invalid_grant".into())
            })
        );
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
            assert_eq!(
                error.revocation_origin(),
                Some(&RevocationOrigin::DeadTokenClaim)
            );
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
        let unshared = SharedRefreshOptions {
            allow_unshared: true,
            ..Default::default()
        };
        let first = client(&url)
            .refresh_shared(&path2, &unknown, &unshared)
            .await
            .unwrap_err();
        assert!(matches!(first, Error::RefreshTokenRevoked { .. }));
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        let second = client(&url)
            .refresh_shared(&path2, &unknown, &unshared)
            .await
            .unwrap_err();
        assert_eq!(
            second.revocation_origin(),
            Some(&RevocationOrigin::LocalDeadSet)
        );
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
        // When the shared credential is also expired, a token the store has
        // never held is not spent: it may be one a peer just rotated.
        let expired = tokens(NEW_REFRESH, NEW_ACCESS, at(-10));
        seeded_store(&path, &expired);
        let refused = client(&url)
            .refresh_shared(&path, &mine, &SharedRefreshOptions::default())
            .await
            .unwrap_err();
        assert!(matches!(refused, Error::RefreshRefused(_)), "{refused}");
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        // Only an explicit opt-in spends an unshared token.
        let outcome = client(&url)
            .refresh_shared(
                &path,
                &mine,
                &SharedRefreshOptions {
                    allow_unshared: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(outcome.source, RefreshSource::Refreshed);
        assert_eq!(outcome.account_id, None);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    /// A token endpoint that records every presented refresh token, answers
    /// with `status`/`body` after `delay`, and runs `before_answer` (a peer's
    /// store write) before answering.
    async fn recording_server(
        status: u16,
        body: &'static str,
        delay: std::time::Duration,
        before_answer: Option<Arc<dyn Fn() + Send + Sync>>,
    ) -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let log = log.clone();
                let before_answer = before_answer.clone();
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut chunk = [0u8; 4096];
                    let body_start = loop {
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
                                break end + 4;
                            }
                        }
                    };
                    let json: serde_json::Value =
                        serde_json::from_slice(&request[body_start..]).unwrap_or_default();
                    if let Some(refresh) = json["refresh_token"].as_str() {
                        log.lock().unwrap().push(refresh.to_owned());
                    }
                    tokio::time::sleep(delay).await;
                    if let Some(hook) = before_answer {
                        tokio::task::spawn_blocking(move || hook()).await.unwrap();
                    }
                    let response = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        (format!("http://{address}"), seen)
    }

    fn with_identity(mut tokens: OAuthTokens) -> OAuthTokens {
        tokens.account = Some(crate::token::TokenAccount {
            uuid: "acct-uuid".into(),
            email_address: Some("me@example.com".into()),
        });
        tokens.organization = Some(crate::token::TokenOrganization {
            uuid: "org-uuid".into(),
        });
        tokens
    }

    #[tokio::test]
    async fn a_stale_caller_token_is_never_spent_the_stores_token_is() {
        let (url, seen) =
            recording_server(200, ROTATED_BODY, std::time::Duration::ZERO, None).await;
        let path = store_path("stale-caller");
        // The store already holds a newer rotation of the same login.
        let store_row = with_identity(tokens(
            "sk-ant-ort01-store-newer-aaaaaaaaaaaaaaaaaa",
            "sk-ant-oat01-store-newer-aaaaaaaaaaaaaaaaaa",
            Utc::now() + Duration::hours(2),
        ));
        seeded_store(&path, &store_row);
        let stale = with_identity(old_tokens("stale-caller"));

        // Live store session: adopted, nothing presented.
        let adopted = client(&url)
            .refresh_shared(&path, &stale, &SharedRefreshOptions::default())
            .await
            .unwrap();
        assert_eq!(adopted.source, RefreshSource::AdoptedPeer);
        assert_eq!(adopted.tokens.refresh, store_row.refresh);
        assert!(seen.lock().unwrap().is_empty());

        // Expired store session: the store's token is refreshed, the
        // caller's stale one never reaches the endpoint.
        let mut expired = store_row.clone();
        expired.expires_at = at(-10);
        seeded_store(&path, &expired);
        let refreshed = client(&url)
            .refresh_shared(&path, &stale, &SharedRefreshOptions::default())
            .await
            .unwrap();
        assert_eq!(refreshed.source, RefreshSource::Refreshed);
        assert_eq!(refreshed.account_id.as_deref(), Some("shared"));
        assert_eq!(
            *seen.lock().unwrap(),
            vec![store_row.refresh.expose().to_owned()],
            "only the store's refresh token may be spent"
        );
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[tokio::test]
    async fn a_stalled_token_call_is_cut_off_inside_the_claim_and_never_committed() {
        let (url, seen) =
            recording_server(200, ROTATED_BODY, std::time::Duration::from_secs(40), None).await;
        const TAG: &str = "stall";
        let path = store_path(TAG);
        let presented = old_tokens(TAG);
        seeded_store(&path, &presented);
        // A caller-supplied client with no timeout at all.
        let mut endpoints = Endpoints::prod();
        endpoints.token_url = url;
        let client = OAuthClient::with_http(reqwest::Client::new(), endpoints);
        let options = SharedRefreshOptions {
            lease_ttl_secs: 3,
            ..Default::default()
        };
        let started = std::time::Instant::now();
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client.refresh_shared(&path, &presented, &options),
        )
        .await
        .expect("the refresh must give up inside the claim")
        .unwrap_err();
        assert!(matches!(error, Error::Timeout(_)), "{error}");
        assert!(started.elapsed() < std::time::Duration::from_secs(3));
        assert_eq!(classify_refresh_failure(&error), RefreshFailure::Error);
        assert_eq!(seen.lock().unwrap().len(), 1);
        let row = AccountStore::load(&path).unwrap();
        let row = row.get("shared").unwrap();
        // Nothing committed, nothing marked dead, no error recorded, and the
        // claim released rather than left to lapse.
        assert_eq!(row.oauth().unwrap().refresh, presented.refresh);
        assert!(!row.refresh_token_is_dead());
        assert!(row.refresh_lease.is_none());
        assert!(row.last_error.is_none());
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[tokio::test]
    async fn only_a_400_invalid_grant_marks_the_token_dead() {
        for (status, body) in [
            (400u16, r#"{"error":"invalid_client"}"#),
            (
                400,
                r#"{"error":"invalid_request","error_description":"not invalid_grant"}"#,
            ),
            (401, r#"{"error":"invalid_grant"}"#),
            (500, r#"{"error":"invalid_grant"}"#),
        ] {
            let (url, hits) = token_server(status, body).await;
            let tag = format!("transient-{status}-{}", body.len());
            let path = store_path(&tag);
            let presented = old_tokens(&tag);
            seeded_store(&path, &presented);
            let error = client(&url)
                .refresh_shared(&path, &presented, &SharedRefreshOptions::default())
                .await
                .unwrap_err();
            assert!(
                !matches!(error, Error::RefreshTokenRevoked { .. }),
                "{status} {body}"
            );
            assert_eq!(
                classify_refresh_failure(&error),
                RefreshFailure::Error,
                "{status} {body}"
            );
            let row = AccountStore::load(&path).unwrap();
            let row = row.get("shared").unwrap();
            assert!(!row.refresh_token_is_dead(), "{status} {body}");
            assert!(row.dead_refresh_fingerprint.is_none());
            assert!(!DeadRefreshTokens::is_dead(presented.refresh.expose()));
            // Still refreshable: a transient failure never strands the login.
            let again = client(&url)
                .refresh_shared(&path, &presented, &SharedRefreshOptions::default())
                .await
                .unwrap_err();
            assert!(!matches!(again, Error::RefreshTokenRevoked { .. }));
            assert_eq!(hits.load(Ordering::SeqCst), 2);
            std::fs::remove_dir_all(path.parent().unwrap()).ok();
        }
    }

    #[tokio::test]
    async fn invalid_grant_on_a_token_the_store_no_longer_holds_marks_nothing() {
        const TAG: &str = "dead-rotated";
        let path = store_path(TAG);
        let presented = old_tokens(TAG);
        seeded_store(&path, &presented);
        // While our POST is in flight, a peer (which never claims, like a
        // fail-open host) rotates the row.
        let peer_path = path.clone();
        let peer_expected = presented.refresh.clone();
        let hook: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            let rotated = tokens(
                "sk-ant-ort01-peer-rotated-aaaaaaaaaaaaaaaaa",
                "sk-ant-oat01-peer-rotated-aaaaaaaaaaaaaaaaa",
                Utc::now() + Duration::hours(8),
            );
            assert!(
                AccountStore::replace_oauth_after_refresh(
                    &peer_path,
                    "shared",
                    &peer_expected,
                    rotated
                )
                .unwrap()
            );
        });
        let (url, _seen) = recording_server(
            400,
            INVALID_GRANT_BODY,
            std::time::Duration::ZERO,
            Some(hook),
        )
        .await;
        let error = client(&url)
            .refresh_shared(&path, &presented, &SharedRefreshOptions::default())
            .await
            .unwrap_err();
        assert!(matches!(error, Error::RefreshTokenRevoked { .. }));
        let stored = AccountStore::load(&path).unwrap();
        let row = stored.get("shared").unwrap();
        assert_eq!(
            row.oauth().unwrap().refresh.expose(),
            "sk-ant-ort01-peer-rotated-aaaaaaaaaaaaaaaaa"
        );
        assert!(row.dead_refresh_fingerprint.is_none());
        assert!(!row.refresh_token_is_dead());
        assert!(row.current_error().is_none());
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn the_refresh_deadline_always_ends_inside_the_claim() {
        for ttl in [1, 3, 10, 30, 120] {
            let deadline = refresh_deadline(ttl);
            assert!(
                deadline < std::time::Duration::from_secs(ttl as u64),
                "{ttl}"
            );
            assert!(!deadline.is_zero());
        }
        assert_eq!(
            refresh_deadline(REFRESH_LEASE_TTL_SECS),
            std::time::Duration::from_secs(25)
        );
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
        // A permanent 4xx that is not invalid_grant says nothing about the
        // token: it is not reported as revoked.
        assert_eq!(
            classify_refresh_failure(&Error::Endpoint {
                status: 400,
                permanent: true,
                error_code: Some("invalid_client".into()),
                retry_after_ms: None,
                body: String::new()
            }),
            RefreshFailure::Error
        );
        let invalid = Error::Endpoint {
            status: 400,
            permanent: true,
            error_code: Some("invalid_grant".into()),
            retry_after_ms: None,
            body: String::new(),
        };
        assert!(invalid.is_invalid_grant());
        assert!(
            Error::RefreshTokenRevoked {
                origin: RevocationOrigin::LocalDeadSet
            }
            .is_permanent()
        );
        DeadRefreshTokens::remember("sk-ant-ort01-zzzzzzzzzzzzzzzzzzzzzzz");
        assert!(DeadRefreshTokens::is_dead(
            "sk-ant-ort01-zzzzzzzzzzzzzzzzzzzzzzz"
        ));
        assert!(!DeadRefreshTokens::is_dead(
            "sk-ant-ort01-yyyyyyyyyyyyyyyyyyyyyyy"
        ));
    }
}
