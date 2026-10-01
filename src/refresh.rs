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
//!    brought forward when it still holds the spent token or Claude Code is
//!    logged into the same account ([`OAuthClient::native_publish`],
//!    [`crate::credentials::publish_native_login`]). The rotation is
//!    already committed; a failed publish never fails the refresh and is
//!    reported on [`SharedRefreshOutcome::native_publish`].
//! 8. One login per account ([`crate::credentials::reconcile_claude_code_link`]):
//!    a row linked to Claude Code's login (same account and organization)
//!    is first brought into step with it, newest copy winning. While Claude
//!    Code's access token is live it is borrowed and nothing is spent
//!    ([`RefreshSource::ClaudeCode`]). Otherwise the shared token is
//!    refreshed once, under Claude Code's own refresh lock
//!    ([`crate::credentials::ClaudeCodeRefreshLock`]), and published back.
//!    An `invalid_grant` on a linked row first re-reads Claude Code's
//!    login: a newer one (the operator logged in there, revoking the
//!    store's) is adopted, which clears the error and the dead verdict,
//!    instead of the account being declared dead.

use std::collections::HashSet;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use chrono::{Duration, Utc};

use crate::credentials::{ClaudeCodeFiles, LinkReconcile, NativePublishOutcome, Reconciled};
use crate::error::{Error, Result, RevocationOrigin};
use crate::oauth::OAuthClient;
use crate::refresh_claim::{REFRESH_LEASE_TTL_SECS, RefreshClaim};
use crate::store::AccountStore;
use crate::token::{OAuthTokens, RefreshToken, token_fingerprint};

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
    /// The row is linked to Claude Code's login and Claude Code's live
    /// access token was borrowed: nothing was spent.
    ClaudeCode,
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
#[derive(Debug, Clone, Copy)]
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
}

impl Default for SharedRefreshOptions {
    fn default() -> Self {
        Self {
            claim_max_attempts: REFRESH_CLAIM_MAX_ATTEMPTS,
            claim_wait_ms: 1_000,
            lease_ttl_secs: REFRESH_LEASE_TTL_SECS,
            allow_unshared: false,
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

        // One login per account: a row linked to Claude Code's login borrows,
        // adopts or refreshes under Claude Code's refresh lock.
        if let (Some(files), Located::Held { account_id, .. } | Located::Rotated { account_id, .. }) =
            (self.claude_code_files(), &located)
            && let Some(outcome) = self
                .refresh_linked(path, &files, account_id, presented, options)
                .await?
        {
            return Ok(outcome);
        }

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
                    .publish_native(&presented.refresh, &refreshed, None)
                    .await;
                return Ok(SharedRefreshOutcome {
                    tokens: refreshed,
                    source: RefreshSource::Refreshed,
                    account_id: None,
                    native_publish,
                });
            }
        };

        self.claim_and_refresh(path, &account_id, &spend, options, None)
            .await
    }

    /// Claim `account_id`'s refresh lease for `spend`, spend it once and
    /// commit the rotation (steps 3–7 of the module docs). `link` is set on
    /// the linked path (step 8): an `invalid_grant` is then not recorded
    /// durably here (the caller does, only after reading Claude Code's
    /// credentials), and the publish replaces only the copy Claude Code held
    /// when the row was judged.
    async fn claim_and_refresh(
        &self,
        path: &Path,
        account_id: &str,
        spend: &OAuthTokens,
        options: &SharedRefreshOptions,
        link: Option<&LinkGuard>,
    ) -> Result<SharedRefreshOutcome> {
        // Claim first and re-read under the claim: the store CAS after the
        // network call is too late, both POSTs have already happened by then.
        let mut attempt = 0u32;
        let lease_id = loop {
            let claim = AccountStore::mutate(path, |store| {
                Ok(store.claim_refresh(
                    account_id,
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
                        account_id: Some(account_id.to_owned()),
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
            .refresh_claimed(path, account_id, &lease_id, spend, options, link)
            .await;
        if result.is_err() {
            let _ = AccountStore::release_refresh_claim_at(path, account_id, &lease_id);
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
        link: Option<&LinkGuard>,
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
                // a peer's newer rotation never inherits the verdict. A
                // linked row is marked by the caller, and only after Claude
                // Code's credentials were read (a newer login there heals it).
                if link.is_none() {
                    let _ =
                        AccountStore::mark_refresh_token_dead_at(path, account_id, &spend.refresh);
                }
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
            let native_before = link.and_then(|l| l.native_before.as_ref());
            let native_publish = self
                .publish_native(&spend.refresh, &refreshed, native_before)
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

    /// Claude Code's files for the link and the by-account publish (the
    /// native-publish policy; `Auto` is suppressed in OAuth test mode).
    pub fn claude_code_files(&self) -> Option<ClaudeCodeFiles> {
        let files = self.native_publish_policy().files(self.is_test_mode())?;
        Some(match self.claude_code_backend_override() {
            Some(backend) => files.with_backend(backend.clone()),
            None => files,
        })
    }

    /// Bring Claude Code's credential file forward after a rotation this
    /// process committed (module docs, step 7): when it holds the spent
    /// token, or Claude Code is logged into the same account. Blocking file
    /// work (Claude Code's write lock may be waited on for a few seconds)
    /// runs off the async worker.
    async fn publish_native(
        &self,
        spent: &RefreshToken,
        rotated: &OAuthTokens,
        native_before: Option<&RefreshToken>,
    ) -> Option<NativePublishOutcome> {
        let files = self.claude_code_files()?;
        let spent = spent.clone();
        let rotated = rotated.clone();
        let native_before = native_before.cloned();
        Some(
            off_thread(move || {
                crate::credentials::publish_native_login_guarded(
                    &files,
                    Some(&spent),
                    native_before.as_ref(),
                    &rotated,
                )
            })
            .await
            .unwrap_or_else(|e| {
                NativePublishOutcome::Failed(format!("publish worker failed: {e}"))
            }),
        )
    }

    /// Module docs, step 8. `Ok(None)`: the row is not linked to Claude
    /// Code's login; the ordinary path continues. [`Error::LinkBusy`]:
    /// Claude Code's credentials could not be read, so the row was neither
    /// spent nor marked dead.
    async fn refresh_linked(
        &self,
        path: &Path,
        files: &ClaudeCodeFiles,
        account_id: &str,
        presented: &OAuthTokens,
        options: &SharedRefreshOptions,
    ) -> Result<Option<SharedRefreshOutcome>> {
        let first = reconcile(path, files, account_id).await?;
        if matches!(first.outcome, LinkReconcile::NotLinked) {
            return Ok(None);
        }
        if let Some(outcome) = borrowed(&first.outcome, presented, account_id) {
            return Ok(Some(outcome));
        }
        // Expired (or the caller's own copy was rejected): refresh once,
        // under Claude Code's refresh lock, so no Claude Code process spends
        // the same token meanwhile. A Claude Code that was refreshing when
        // the lock was asked for has published its rotation by the time it
        // is granted; the re-read below adopts it.
        let lock_files = files.clone();
        let lock =
            off_thread(move || crate::credentials::ClaudeCodeRefreshLock::acquire(&lock_files))
                .await
                .ok()
                .flatten();
        let Some(_lock) = lock else {
            return Err(Error::RefreshRefused(
                "Claude Code is refreshing this login (its refresh lock is held); \
                 refresh was not attempted"
                    .into(),
            ));
        };
        // Each pass that does not return adopted a login Claude Code wrote
        // meanwhile (a `/login`); a login that keeps changing is retried
        // later rather than chased.
        for _ in 0..3 {
            let current = reconcile(path, files, account_id).await?;
            if let Some(outcome) = borrowed(&current.outcome, presented, account_id) {
                return Ok(Some(outcome));
            }
            let spend = match current.outcome {
                LinkReconcile::NotLinked => return Ok(None),
                LinkReconcile::Native { tokens, .. } | LinkReconcile::Store { tokens, .. } => {
                    tokens
                }
            };
            let guard = LinkGuard {
                native_before: current.native_refresh,
            };
            match self
                .claim_and_refresh(path, account_id, &spend, options, Some(&guard))
                .await
            {
                Ok(outcome) if outcome.source == RefreshSource::Refreshed => {
                    // A Claude Code `/login` while the token was in flight
                    // revoked the rotation just committed: adopt that login
                    // and hand out its token, never the revoked one.
                    let (job_path, job_files, job_id) =
                        (path.to_path_buf(), files.clone(), account_id.to_owned());
                    let (spent, rotated) = (spend.refresh.clone(), outcome.tokens.clone());
                    let before = guard.native_before.clone();
                    let adopted = off_thread(move || {
                        recheck_after_refresh(
                            &job_path,
                            &job_files,
                            &job_id,
                            &spent,
                            &rotated,
                            before.as_ref(),
                        )
                    })
                    .await
                    .map_err(|e| {
                        Error::RefreshRefused(format!("claude code link worker failed: {e}"))
                    })?;
                    match adopted {
                        None => return Ok(Some(outcome)),
                        Some(tokens) if !tokens.needs_refresh(Utc::now()) => {
                            return Ok(Some(SharedRefreshOutcome {
                                tokens,
                                source: RefreshSource::ClaudeCode,
                                account_id: Some(account_id.to_owned()),
                                native_publish: outcome.native_publish,
                            }));
                        }
                        // Adopted but already inside the leeway: spend it
                        // on the next pass, still under the refresh lock.
                        Some(_) => {}
                    }
                }
                Ok(outcome) => return Ok(Some(outcome)),
                Err(error)
                    if matches!(classify_refresh_failure(&error), RefreshFailure::Revoked) =>
                {
                    // The operator may have logged into Claude Code, which
                    // revoked the store's login: adopt Claude Code's rather
                    // than declare the account dead. Dead only once Claude
                    // Code's credentials were read and hold nothing newer.
                    let (job_path, job_files, job_id) =
                        (path.to_path_buf(), files.clone(), account_id.to_owned());
                    let spent = spend.refresh.clone();
                    let verdict =
                        off_thread(move || verify_revoked(&job_path, &job_files, &job_id, &spent))
                            .await
                            .map_err(|e| {
                                Error::RefreshRefused(format!(
                                    "claude code link worker failed: {e}"
                                ))
                            })??;
                    if verdict == RevokedVerdict::Dead {
                        return Err(error);
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Err(crate::credentials::link_busy(
            "Claude Code's login changed repeatedly during the refresh",
        ))
    }
}

/// The linked path's context for one spend (module docs, step 8).
#[derive(Debug, Clone)]
struct LinkGuard {
    /// The refresh token Claude Code held when the row was judged: the only
    /// copy a publish may replace besides the spent token.
    native_before: Option<RefreshToken>,
}

/// After a refresh of a linked row was committed: Claude Code's credentials
/// re-read under its write lock. When they hold a login the store never
/// wrote (not the spent token, not the rotation, not the copy judged before
/// the spend) Claude Code logged in during the refresh window, which
/// revoked the rotation: that login is adopted (compare-and-swap on the row
/// still holding the rotation) and returned. `None`: keep the rotation
/// (including when Claude Code cannot be read right now).
fn recheck_after_refresh(
    path: &Path,
    files: &ClaudeCodeFiles,
    account_id: &str,
    spent: &RefreshToken,
    rotated: &OAuthTokens,
    native_before: Option<&RefreshToken>,
) -> Option<OAuthTokens> {
    let store = AccountStore::read_locked(path, |store| Ok(store.clone())).ok()?;
    let login = crate::credentials::try_read_claude_code_login_locked(files, Some(&store))
        .ok()
        .flatten()?;
    if !store
        .get(account_id)
        .is_some_and(|a| crate::credentials::is_linked(a, &login.identity))
    {
        return None;
    }
    let held = &login.tokens.refresh;
    if held == &rotated.refresh || held == spent || Some(held) == native_before {
        return None;
    }
    AccountStore::mutate(path, |store| {
        Ok(store.adopt_claude_code_login(account_id, &rotated.refresh, login.tokens.clone()))
    })
    .ok()
    .flatten()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RevokedVerdict {
    /// Claude Code held a different login of the account; the row adopted
    /// it (or a peer moved the row on): re-judge and retry.
    Adopted,
    /// Claude Code's credentials were read and hold nothing newer: the row
    /// is now recorded dead.
    Dead,
}

/// After an `invalid_grant` (or a recorded dead verdict) on a linked row:
/// the row is declared dead only once Claude Code's credentials were read
/// under its write lock and hold no other login of the account. A read that
/// cannot be made is [`Error::LinkBusy`] and nothing is recorded.
fn verify_revoked(
    path: &Path,
    files: &ClaudeCodeFiles,
    account_id: &str,
    spent: &RefreshToken,
) -> Result<RevokedVerdict> {
    let store = AccountStore::read_locked(path, |store| Ok(store.clone()))
        .map_err(|error| Error::RefreshRefused(format!("shared store unreadable: {error}")))?;
    let login = crate::credentials::try_read_claude_code_login_locked(files, Some(&store))?;
    if let Some(login) = login
        && store
            .get(account_id)
            .is_some_and(|a| crate::credentials::is_linked(a, &login.identity))
        && &login.tokens.refresh != spent
    {
        AccountStore::mutate(path, |store| {
            Ok(store.adopt_claude_code_login(account_id, spent, login.tokens.clone()))
        })
        .map_err(|error| Error::RefreshRefused(format!("shared store unwritable: {error}")))?;
        return Ok(RevokedVerdict::Adopted);
    }
    let _ = AccountStore::mark_refresh_token_dead_at(path, account_id, spent);
    Ok(RevokedVerdict::Dead)
}

/// [`crate::credentials::reconcile_claude_code_link`] off the async worker.
/// [`Error::LinkBusy`] passes through (nothing is spent or marked); an
/// unreadable store refuses.
async fn reconcile(path: &Path, files: &ClaudeCodeFiles, account_id: &str) -> Result<Reconciled> {
    let (path, files, account_id) = (path.to_path_buf(), files.clone(), account_id.to_owned());
    off_thread(move || crate::credentials::reconcile_link(&path, &files, &account_id))
        .await
        .map_err(|e| Error::RefreshRefused(format!("claude code link worker failed: {e}")))?
        .map_err(|error| match error {
            busy @ Error::LinkBusy { .. } => busy,
            other => Error::RefreshRefused(format!("shared store unreadable: {other}")),
        })
}

/// The linked login's session when it can be handed out without a spend:
/// live (outside the refresh leeway) and not the copy the caller already
/// holds (a caller re-presenting its own live token wants a new one).
fn borrowed(
    reconciled: &LinkReconcile,
    presented: &OAuthTokens,
    account_id: &str,
) -> Option<SharedRefreshOutcome> {
    let (tokens, source, native_publish) = match reconciled {
        LinkReconcile::NotLinked => return None,
        LinkReconcile::Native { tokens, .. } => (tokens, RefreshSource::ClaudeCode, None),
        LinkReconcile::Store { tokens, publish } => {
            (tokens, RefreshSource::AdoptedPeer, Some(publish.clone()))
        }
    };
    if tokens.needs_refresh(Utc::now()) || tokens.access == presented.access {
        return None;
    }
    Some(SharedRefreshOutcome {
        tokens: tokens.clone(),
        source,
        account_id: Some(account_id.to_owned()),
        native_publish,
    })
}

/// Run blocking file work off the async worker (inline without a runtime).
async fn off_thread<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> std::result::Result<T, String> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => handle.spawn_blocking(work).await.map_err(|e| e.to_string()),
        Err(_) => Ok(work()),
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

    fn publishing_to(url: &str, native: &Path) -> OAuthClient {
        client(url).native_publish(crate::credentials::NativePublish::At(native.to_path_buf()))
    }

    #[tokio::test]
    async fn a_rotation_is_published_to_claude_code_when_it_held_the_spent_token() {
        let (url, hits) = token_server(200, ROTATED_BODY).await;
        const TAG: &str = "native-publish";
        let path = store_path(TAG);
        let presented = old_tokens(TAG);
        seeded_store(&path, &presented);
        let native = native_beside(&path, presented.refresh.expose());
        let outcome = publishing_to(&url, &native)
            .refresh_shared(&path, &presented, &SharedRefreshOptions::default())
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
        let again = publishing_to(&url, &native)
            .refresh_shared(&path, &presented, &SharedRefreshOptions::default())
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
        let outcome = publishing_to(&url, &native)
            .refresh_shared(&path, &presented, &SharedRefreshOptions::default())
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
        let error = publishing_to(&url, &native)
            .refresh_shared(&path, &presented, &SharedRefreshOptions::default())
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
        use crate::credentials::NativePublish;
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
            let outcome = client(&url)
                .native_publish(policy.clone())
                .refresh_shared(&path, &presented, &SharedRefreshOptions::default())
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

    /// One login per account (module docs, step 8). Temp dirs, a mock token
    /// server, OAuth test mode (`cfg(test)`), and an explicit native path:
    /// the real `~/.claude` is never resolved.
    mod claude_code_link {
        use super::*;
        use crate::credentials::{NATIVE_CONFIG_FILE_NAME, NATIVE_WRITE_LOCK_NAME, NativePublish};

        const ACCOUNT: &str = "acct-cc-link";
        const ORG: &str = "org-cc-link";

        fn identified(mut tokens: OAuthTokens) -> OAuthTokens {
            tokens.account = Some(crate::token::TokenAccount {
                uuid: ACCOUNT.into(),
                email_address: Some("me@example.com".into()),
            });
            tokens.organization = Some(crate::token::TokenOrganization { uuid: ORG.into() });
            tokens
        }

        fn pair(tag: &str, expires_at: DateTime<Utc>) -> OAuthTokens {
            tokens(
                &format!("sk-ant-ort01-{tag}-aaaaaaaaaaaaaaaaaaaaaa"),
                &format!("sk-ant-oat01-{tag}-aaaaaaaaaaaaaaaaaaaaaa"),
                expires_at,
            )
        }

        fn private(path: &Path, value: &serde_json::Value) {
            std::fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
        }

        /// Claude Code's two files beside the test store: the credential
        /// file holding `native`, and `.claude.json` naming `account`/`org`.
        fn claude_code(
            path: &Path,
            native: &OAuthTokens,
            account: &str,
            org: &str,
        ) -> std::path::PathBuf {
            let dir = path.parent().unwrap();
            let credentials = dir.join(".credentials.json");
            write_native(&credentials, native);
            private(
                &dir.join(NATIVE_CONFIG_FILE_NAME),
                &serde_json::json!({
                    "projects": {},
                    "oauthAccount": {
                        "accountUuid": account,
                        "organizationUuid": org,
                        "emailAddress": "me@example.com"
                    }
                }),
            );
            credentials
        }

        fn write_native(credentials: &Path, native: &OAuthTokens) {
            private(
                credentials,
                &serde_json::json!({
                    "claudeAiOauth": {
                        "accessToken": native.access.expose(),
                        "refreshToken": native.refresh.expose(),
                        "expiresAt": native.expires_at.timestamp_millis(),
                        "scopes": ["user:inference", "user:profile"],
                        "subscriptionType": "max",
                        "rateLimitTier": "default_claude_max_20x"
                    },
                    "mcpOAuth": { "keep": true }
                }),
            );
        }

        fn native_doc(credentials: &Path) -> serde_json::Value {
            serde_json::from_slice(&std::fs::read(credentials).unwrap()).unwrap()
        }

        fn linked_client(url: &str, credentials: &Path) -> OAuthClient {
            client(url).native_publish(NativePublish::At(credentials.to_path_buf()))
        }

        fn row(path: &Path) -> crate::account::Account {
            AccountStore::load(path)
                .unwrap()
                .get("shared")
                .unwrap()
                .clone()
        }

        #[tokio::test]
        async fn a_live_claude_code_token_is_borrowed_and_nothing_is_refreshed() {
            let (url, hits) = token_server(200, ROTATED_BODY).await;
            let path = store_path("cc-borrow");
            // The store's copy expired; Claude Code holds the same login,
            // live (the operator uses Claude Code right now).
            let stored = identified(pair("cc-borrow-store", at(-10)));
            seeded_store(&path, &stored);
            let native = pair("cc-borrow-native", Utc::now() + Duration::hours(6));
            let credentials = claude_code(&path, &native, ACCOUNT, ORG);
            let before = std::fs::read(&credentials).unwrap();
            let client = linked_client(&url, &credentials);

            let outcome = client
                .refresh_shared(&path, &stored, &SharedRefreshOptions::default())
                .await
                .unwrap();
            assert_eq!(outcome.source, RefreshSource::ClaudeCode);
            assert_eq!(outcome.tokens.access, native.access);
            assert_eq!(outcome.account_id.as_deref(), Some("shared"));
            assert_eq!(hits.load(Ordering::SeqCst), 0, "nothing is spent");
            // The store now holds the shared login (synced both ways), and
            // Claude Code's file is untouched.
            assert_eq!(row(&path).oauth().unwrap().refresh, native.refresh);
            assert_eq!(std::fs::read(&credentials).unwrap(), before);

            // The coarse entry point borrows it too.
            let grant = crate::access::get_access_token(
                &client,
                &path,
                &crate::access::AccessRequest::default(),
                &SharedRefreshOptions::default(),
            )
            .await
            .unwrap();
            assert_eq!(grant.source, crate::access::AccessSource::ClaudeCode);
            assert_eq!(grant.access_token, native.access.expose());
            assert_eq!(hits.load(Ordering::SeqCst), 0);
            std::fs::remove_dir_all(path.parent().unwrap()).ok();
        }

        #[tokio::test]
        async fn a_store_login_revoked_by_a_newer_claude_code_login_is_healed_not_dead() {
            let (url, hits) = token_server(400, INVALID_GRANT_BODY).await;
            let path = store_path("cc-heal");
            // The store row was flagged by an earlier invalid_grant on its
            // (revoked) token. The operator then logged into Claude Code.
            let stored = identified(pair("cc-heal-store", at(-10)));
            seeded_store(&path, &stored);
            AccountStore::mutate(&path, |store| {
                Ok(store.mark_refresh_token_dead("shared", &stored.refresh))
            })
            .unwrap();
            assert!(row(&path).refresh_token_is_dead());
            let native = pair("cc-heal-native", Utc::now() + Duration::hours(8));
            let credentials = claude_code(&path, &native, ACCOUNT, ORG);
            let client = linked_client(&url, &credentials);

            let grant = crate::access::get_access_token(
                &client,
                &path,
                &crate::access::AccessRequest::default(),
                &SharedRefreshOptions::default(),
            )
            .await
            .unwrap();
            assert_eq!(grant.source, crate::access::AccessSource::ClaudeCode);
            assert_eq!(grant.access_token, native.access.expose());
            assert_eq!(
                hits.load(Ordering::SeqCst),
                0,
                "the revoked token is never spent"
            );
            let healed = row(&path);
            assert_eq!(healed.oauth().unwrap().refresh, native.refresh);
            assert!(!healed.refresh_token_is_dead());
            assert!(healed.dead_refresh_fingerprint.is_none());
            assert!(healed.last_error.is_none());
            assert!(healed.enabled);
            std::fs::remove_dir_all(path.parent().unwrap()).ok();
        }

        #[tokio::test]
        async fn an_invalid_grant_while_claude_code_logs_in_adopts_its_login() {
            // Store and Claude Code share one expired token. While the
            // store's refresh is in flight the operator logs into Claude
            // Code (a new login: it revokes the shared one, so the endpoint
            // answers invalid_grant).
            let path = store_path("cc-race-login");
            let shared = identified(pair("cc-race-shared", at(-10)));
            seeded_store(&path, &shared);
            let credentials = claude_code(&path, &shared, ACCOUNT, ORG);
            let fresh = pair("cc-race-fresh", Utc::now() + Duration::hours(8));
            let hook: Arc<dyn Fn() + Send + Sync> = {
                let (credentials, fresh) = (credentials.clone(), fresh.clone());
                Arc::new(move || write_native(&credentials, &fresh))
            };
            let (url, seen) = recording_server(
                400,
                INVALID_GRANT_BODY,
                std::time::Duration::ZERO,
                Some(hook),
            )
            .await;
            let outcome = linked_client(&url, &credentials)
                .refresh_shared(&path, &shared, &SharedRefreshOptions::default())
                .await
                .unwrap();
            assert_eq!(outcome.source, RefreshSource::ClaudeCode);
            assert_eq!(outcome.tokens.access, fresh.access);
            assert_eq!(seen.lock().unwrap().len(), 1, "one spend, then adopt");
            let healed = row(&path);
            assert_eq!(healed.oauth().unwrap().refresh, fresh.refresh);
            assert!(!healed.refresh_token_is_dead(), "not marked dead");
            assert!(healed.current_error().is_none());
            assert!(!path.parent().unwrap().join(".oauth_refresh.lock").exists());
            std::fs::remove_dir_all(path.parent().unwrap()).ok();
        }

        #[tokio::test]
        async fn an_expired_login_is_refreshed_once_and_published_to_claude_code() {
            let (url, seen) =
                recording_server(200, ROTATED_BODY, std::time::Duration::ZERO, None).await;
            let path = store_path("cc-expired");
            // The store holds the newer copy (it rotated last); Claude Code
            // holds an older, different token of the same account. Both
            // access tokens have expired.
            let stored = identified(pair("cc-expired-store", at(-10)));
            seeded_store(&path, &stored);
            let older = pair("cc-expired-native", at(-3_600));
            let credentials = claude_code(&path, &older, ACCOUNT, ORG);
            let outcome = linked_client(&url, &credentials)
                .refresh_shared(&path, &stored, &SharedRefreshOptions::default())
                .await
                .unwrap();
            assert_eq!(outcome.source, RefreshSource::Refreshed);
            assert_eq!(outcome.native_publish, Some(NativePublishOutcome::Written));
            assert_eq!(
                *seen.lock().unwrap(),
                vec![stored.refresh.expose().to_owned()],
                "exactly one spend, of the store's token"
            );
            let doc = native_doc(&credentials);
            assert_eq!(doc["claudeAiOauth"]["refreshToken"], NEW_REFRESH);
            assert_eq!(doc["claudeAiOauth"]["accessToken"], NEW_ACCESS);
            assert_eq!(doc["claudeAiOauth"]["subscriptionType"], "max");
            assert_eq!(doc["mcpOAuth"]["keep"], true);
            assert_eq!(row(&path).oauth().unwrap().refresh.expose(), NEW_REFRESH);
            // Claude Code's refresh lock was taken and released.
            let dir = path.parent().unwrap();
            assert!(!dir.join(".oauth_refresh.lock").exists());
            assert!(!dir.join(NATIVE_WRITE_LOCK_NAME).exists());

            // Same token on both sides, expired: one spend, published.
            let path = store_path("cc-expired-same");
            let shared = identified(pair("cc-expired-same", at(-10)));
            seeded_store(&path, &shared);
            let credentials = claude_code(&path, &shared, ACCOUNT, ORG);
            let (url, seen) =
                recording_server(200, ROTATED_BODY, std::time::Duration::ZERO, None).await;
            let outcome = linked_client(&url, &credentials)
                .refresh_shared(&path, &shared, &SharedRefreshOptions::default())
                .await
                .unwrap();
            assert_eq!(outcome.source, RefreshSource::Refreshed);
            assert_eq!(outcome.native_publish, Some(NativePublishOutcome::Written));
            assert_eq!(seen.lock().unwrap().len(), 1);
            assert_eq!(
                native_doc(&credentials)["claudeAiOauth"]["refreshToken"],
                NEW_REFRESH
            );
            std::fs::remove_dir_all(dir).ok();
            std::fs::remove_dir_all(path.parent().unwrap()).ok();
        }

        #[tokio::test]
        async fn claude_code_on_another_account_is_never_touched() {
            let (url, hits) = token_server(200, ROTATED_BODY).await;
            let path = store_path("cc-other");
            let stored = identified(pair("cc-other-store", at(-10)));
            seeded_store(&path, &stored);
            // Claude Code is logged into someone else, with a live token.
            let theirs = pair("cc-other-native", Utc::now() + Duration::hours(6));
            let credentials = claude_code(&path, &theirs, "acct-someone-else", ORG);
            let before = std::fs::read(&credentials).unwrap();
            let client = linked_client(&url, &credentials);
            let outcome = client
                .refresh_shared(&path, &stored, &SharedRefreshOptions::default())
                .await
                .unwrap();
            assert_eq!(outcome.source, RefreshSource::Refreshed, "not borrowed");
            assert_eq!(
                outcome.native_publish,
                Some(NativePublishOutcome::OtherAccount)
            );
            assert_eq!(hits.load(Ordering::SeqCst), 1);
            assert_eq!(std::fs::read(&credentials).unwrap(), before);
            let grant = crate::access::get_access_token(
                &client,
                &path,
                &crate::access::AccessRequest::default(),
                &SharedRefreshOptions::default(),
            )
            .await
            .unwrap();
            assert_ne!(grant.access_token, theirs.access.expose());
            assert_eq!(std::fs::read(&credentials).unwrap(), before);
            std::fs::remove_dir_all(path.parent().unwrap()).ok();
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn an_adopt_waits_for_claude_codes_write_in_flight() {
            let (url, hits) = token_server(200, ROTATED_BODY).await;
            let path = store_path("cc-concurrent");
            let stored = identified(pair("cc-concurrent-store", at(-10)));
            seeded_store(&path, &stored);
            // Claude Code's file still says the old login; Claude Code is
            // mid-write of a new one under its write lock.
            let old = pair("cc-concurrent-old", at(-7_200));
            let credentials = claude_code(&path, &old, ACCOUNT, ORG);
            let lock = path.parent().unwrap().join(NATIVE_WRITE_LOCK_NAME);
            std::fs::create_dir(&lock).unwrap();
            let fresh = pair("cc-concurrent-fresh", Utc::now() + Duration::hours(8));
            let writer = {
                let (credentials, fresh, lock) = (credentials.clone(), fresh.clone(), lock.clone());
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_millis(400));
                    write_native(&credentials, &fresh);
                    std::fs::remove_dir(&lock).unwrap();
                })
            };
            let outcome = linked_client(&url, &credentials)
                .refresh_shared(&path, &stored, &SharedRefreshOptions::default())
                .await
                .unwrap();
            writer.join().unwrap();
            // The snapshot was taken after Claude Code's write, never during
            // it: the new login is adopted and borrowed, nothing spent.
            assert_eq!(outcome.source, RefreshSource::ClaudeCode);
            assert_eq!(outcome.tokens.access, fresh.access);
            assert_eq!(row(&path).oauth().unwrap().refresh, fresh.refresh);
            assert_eq!(hits.load(Ordering::SeqCst), 0);
            assert_eq!(
                native_doc(&credentials)["claudeAiOauth"]["refreshToken"],
                fresh.refresh.expose()
            );
            std::fs::remove_dir_all(path.parent().unwrap()).ok();
        }

        #[tokio::test]
        async fn claude_codes_refresh_in_progress_is_waited_for_and_adopted() {
            // Claude Code holds its refresh lock and publishes a rotation
            // before releasing it: the store waits, re-reads, adopts.
            let (url, hits) = token_server(200, ROTATED_BODY).await;
            let path = store_path("cc-cc-refreshing");
            let shared = identified(pair("cc-cc-refreshing", at(-10)));
            seeded_store(&path, &shared);
            let credentials = claude_code(&path, &shared, ACCOUNT, ORG);
            let lock = path.parent().unwrap().join(".oauth_refresh.lock");
            std::fs::create_dir(&lock).unwrap();
            let rotated = pair("cc-cc-rotated", Utc::now() + Duration::hours(8));
            let cc = {
                let (credentials, rotated, lock) =
                    (credentials.clone(), rotated.clone(), lock.clone());
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_millis(400));
                    write_native(&credentials, &rotated);
                    std::fs::remove_dir(&lock).unwrap();
                })
            };
            let outcome = linked_client(&url, &credentials)
                .refresh_shared(&path, &shared, &SharedRefreshOptions::default())
                .await
                .unwrap();
            cc.join().unwrap();
            assert_eq!(outcome.source, RefreshSource::ClaudeCode);
            assert_eq!(outcome.tokens.access, rotated.access);
            assert_eq!(
                hits.load(Ordering::SeqCst),
                0,
                "the shared token is never spent twice"
            );
            std::fs::remove_dir_all(path.parent().unwrap()).ok();
        }

        /// Hold Claude Code's `.storage-write.lock` the way a live
        /// `proper-lockfile` holder does (fresh mtime) until the returned
        /// flag is set; the lock dir is removed then.
        fn hold_write_lock(
            dir: &Path,
        ) -> (
            Arc<std::sync::atomic::AtomicBool>,
            std::thread::JoinHandle<()>,
        ) {
            let lock = dir.join(NATIVE_WRITE_LOCK_NAME);
            std::fs::create_dir(&lock).unwrap();
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let keeper = {
                let stop = stop.clone();
                std::thread::spawn(move || {
                    while !stop.load(Ordering::SeqCst) {
                        if let Ok(dir) = std::fs::File::open(&lock) {
                            let _ = dir.set_modified(std::time::SystemTime::now());
                        }
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    std::fs::remove_dir(&lock).unwrap();
                })
            };
            (stop, keeper)
        }

        fn assert_not_dead(path: &Path) {
            let row = row(path);
            assert!(!row.refresh_token_is_dead(), "never marked dead");
            assert!(row.dead_refresh_fingerprint.is_none());
            assert!(row.current_error().is_none(), "{:?}", row.last_error);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_held_claude_code_lock_and_invalid_grant_is_transient_never_dead() {
            // Store and Claude Code share one expired token. While the token
            // is in flight Claude Code takes its write lock (it is writing a
            // new login) and keeps it past the bounded wait; the endpoint
            // answers invalid_grant.
            let path = store_path("cc-busy-grant");
            let dir = path.parent().unwrap().to_path_buf();
            let shared = identified(pair("cc-busy-grant", at(-10)));
            seeded_store(&path, &shared);
            let credentials = claude_code(&path, &shared, ACCOUNT, ORG);
            let holder: Arc<std::sync::Mutex<Option<_>>> = Arc::new(std::sync::Mutex::new(None));
            let hook: Arc<dyn Fn() + Send + Sync> = {
                let (dir, holder) = (dir.clone(), holder.clone());
                Arc::new(move || *holder.lock().unwrap() = Some(hold_write_lock(&dir)))
            };
            let (url, seen) = recording_server(
                400,
                INVALID_GRANT_BODY,
                std::time::Duration::ZERO,
                Some(hook),
            )
            .await;
            let client = linked_client(&url, &credentials);
            let error = client
                .refresh_shared(&path, &shared, &SharedRefreshOptions::default())
                .await
                .unwrap_err();
            assert!(matches!(error, Error::LinkBusy { .. }), "{error:?}");
            assert_eq!(
                classify_refresh_failure(&error),
                RefreshFailure::Error,
                "transient, not revoked"
            );
            let access = crate::access::AccessError::from_error(&error);
            assert_eq!(access.kind, crate::access::AccessErrorKind::Transient);
            assert_eq!(
                access.retry_after_ms,
                Some(crate::credentials::LINK_BUSY_RETRY_AFTER_MS)
            );
            assert_eq!(seen.lock().unwrap().len(), 1);
            assert_not_dead(&path);

            // Claude Code finishes its `/login` and releases the lock: the
            // next call adopts that login, spending nothing.
            let fresh = pair("cc-busy-fresh", Utc::now() + Duration::hours(8));
            write_native(&credentials, &fresh);
            let (stop, keeper) = holder.lock().unwrap().take().unwrap();
            stop.store(true, Ordering::SeqCst);
            keeper.join().unwrap();
            let outcome = client
                .refresh_shared(&path, &shared, &SharedRefreshOptions::default())
                .await
                .unwrap();
            assert_eq!(outcome.source, RefreshSource::ClaudeCode);
            assert_eq!(outcome.tokens.access, fresh.access);
            assert_eq!(seen.lock().unwrap().len(), 1, "nothing more spent");
            assert_eq!(row(&path).oauth().unwrap().refresh, fresh.refresh);
            assert_not_dead(&path);
            std::fs::remove_dir_all(dir).ok();
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_busy_claude_code_lock_never_spends_or_kills_the_linked_row() {
            // Claude Code's write lock is held for the whole call. The row is
            // Claude Code's account (`.claude.json`) and its own copy may be
            // the revoked one: nothing is spent, nothing is marked, and the
            // coarse entry point answers `transient`.
            let (url, hits) = token_server(400, INVALID_GRANT_BODY).await;
            let path = store_path("cc-busy-before");
            let dir = path.parent().unwrap().to_path_buf();
            let stored = identified(pair("cc-busy-before-store", at(-10)));
            seeded_store(&path, &stored);
            let native = pair("cc-busy-before-native", Utc::now() + Duration::hours(8));
            let credentials = claude_code(&path, &native, ACCOUNT, ORG);
            let client = linked_client(&url, &credentials);
            let (stop, keeper) = hold_write_lock(&dir);
            let error = crate::access::get_access_token(
                &client,
                &path,
                &crate::access::AccessRequest::default(),
                &SharedRefreshOptions::default(),
            )
            .await
            .unwrap_err();
            assert_eq!(
                error.kind,
                crate::access::AccessErrorKind::Transient,
                "{error}"
            );
            assert!(error.retry_after_ms.is_some());
            let error = client
                .refresh_shared(&path, &stored, &SharedRefreshOptions::default())
                .await
                .unwrap_err();
            assert!(matches!(error, Error::LinkBusy { .. }), "{error:?}");
            stop.store(true, Ordering::SeqCst);
            keeper.join().unwrap();
            assert_eq!(hits.load(Ordering::SeqCst), 0, "nothing spent");
            assert_not_dead(&path);
            assert_eq!(row(&path).oauth().unwrap().refresh, stored.refresh);
            // Released: Claude Code's newer login is adopted.
            let outcome = client
                .refresh_shared(&path, &stored, &SharedRefreshOptions::default())
                .await
                .unwrap();
            assert_eq!(outcome.source, RefreshSource::ClaudeCode);
            assert_eq!(outcome.tokens.access, native.access);
            assert_eq!(hits.load(Ordering::SeqCst), 0);
            std::fs::remove_dir_all(dir).ok();
        }

        #[tokio::test]
        async fn a_lock_held_for_another_account_does_not_block_the_store() {
            // Claude Code is logged into someone else: a busy lock says
            // nothing about this row, which refreshes as usual.
            let (url, hits) = token_server(200, ROTATED_BODY).await;
            let path = store_path("cc-busy-other");
            let dir = path.parent().unwrap().to_path_buf();
            let stored = identified(pair("cc-busy-other-store", at(-10)));
            seeded_store(&path, &stored);
            let theirs = pair("cc-busy-other-native", Utc::now() + Duration::hours(6));
            let credentials = claude_code(&path, &theirs, "acct-someone-else", ORG);
            let (stop, keeper) = hold_write_lock(&dir);
            let outcome = linked_client(&url, &credentials)
                .refresh_shared(&path, &stored, &SharedRefreshOptions::default())
                .await
                .unwrap();
            stop.store(true, Ordering::SeqCst);
            keeper.join().unwrap();
            assert_eq!(outcome.source, RefreshSource::Refreshed);
            assert_eq!(hits.load(Ordering::SeqCst), 1);
            std::fs::remove_dir_all(dir).ok();
        }

        /// `/login` in Claude Code between the token POST and the commit:
        /// the hook writes Claude Code's new login before the endpoint
        /// answers. `native_minutes` is that login's access lifetime; the
        /// rotation's is 60 min.
        async fn login_during_refresh(tag: &str, native_minutes: i64) {
            let path = store_path(tag);
            let dir = path.parent().unwrap().to_path_buf();
            let shared = identified(pair(&format!("{tag}-shared"), at(-10)));
            seeded_store(&path, &shared);
            let credentials = claude_code(&path, &shared, ACCOUNT, ORG);
            let fresh = pair(
                &format!("{tag}-login"),
                Utc::now() + Duration::minutes(native_minutes),
            );
            let written: Arc<std::sync::Mutex<Vec<u8>>> = Arc::default();
            let hook: Arc<dyn Fn() + Send + Sync> = {
                let (credentials, fresh, written) =
                    (credentials.clone(), fresh.clone(), written.clone());
                Arc::new(move || {
                    write_native(&credentials, &fresh);
                    *written.lock().unwrap() = std::fs::read(&credentials).unwrap();
                })
            };
            let (url, seen) =
                recording_server(200, ROTATED_BODY, std::time::Duration::ZERO, Some(hook)).await;
            let outcome = linked_client(&url, &credentials)
                .refresh_shared(&path, &shared, &SharedRefreshOptions::default())
                .await
                .unwrap();
            assert_eq!(outcome.source, RefreshSource::ClaudeCode, "{tag}");
            assert_eq!(
                outcome.tokens.access, fresh.access,
                "{tag}: Claude Code's login, never the revoked rotation"
            );
            assert_eq!(
                outcome.native_publish,
                Some(NativePublishOutcome::NotHeld),
                "{tag}"
            );
            assert_eq!(
                *seen.lock().unwrap(),
                vec![shared.refresh.expose().to_owned()],
                "{tag}: one request, and it succeeded"
            );
            assert_eq!(
                std::fs::read(&credentials).unwrap(),
                *written.lock().unwrap(),
                "{tag}: the new login is never overwritten"
            );
            assert_eq!(row(&path).oauth().unwrap().refresh, fresh.refresh, "{tag}");
            assert_not_dead(&path);
            std::fs::remove_dir_all(dir).ok();
        }

        #[tokio::test]
        async fn a_claude_code_login_during_the_refresh_is_adopted_not_overwritten() {
            // Shorter-lived than the rotation (the expiry rule alone would
            // have overwritten it) and longer-lived (it would have returned
            // the revoked rotation).
            login_during_refresh("cc-login-short", 30).await;
            login_during_refresh("cc-login-long", 8 * 60).await;
        }

        fn keychain_client(
            url: &str,
            dir: &Path,
            item: &crate::credentials::KeychainItem,
        ) -> OAuthClient {
            linked_client(url, &dir.join(".credentials.json")).claude_code_backend(
                crate::credentials::CredentialBackend::Keychain(item.clone()),
            )
        }

        fn keychain_document(native: &OAuthTokens) -> String {
            serde_json::json!({
                "claudeAiOauth": {
                    "accessToken": native.access.expose(),
                    "refreshToken": native.refresh.expose(),
                    "expiresAt": native.expires_at.timestamp_millis(),
                    "scopes": ["user:inference", "user:profile"],
                    "subscriptionType": "max"
                },
                "mcpOAuth": { "keep": true }
            })
            .to_string()
        }

        fn claude_json(dir: &Path, account: &str) {
            private(
                &dir.join(NATIVE_CONFIG_FILE_NAME),
                &serde_json::json!({
                    "oauthAccount": {
                        "accountUuid": account,
                        "organizationUuid": ORG,
                        "emailAddress": "me@example.com"
                    }
                }),
            );
        }

        #[tokio::test]
        async fn the_keychain_backend_borrows_adopts_and_publishes() {
            use crate::credentials::source::tests::{item, seed, stored};

            // Borrow + adopt: Claude Code's Keychain holds a newer live login.
            let (url, hits) = token_server(200, ROTATED_BODY).await;
            let path = store_path("kc-borrow");
            let dir = path.parent().unwrap().to_path_buf();
            let item = item(&dir);
            let row_tokens = identified(pair("kc-borrow-store", at(-10)));
            seeded_store(&path, &row_tokens);
            claude_json(&dir, ACCOUNT);
            let native = pair("kc-borrow-native", Utc::now() + Duration::hours(6));
            seed(&dir, &item, &keychain_document(&native));
            let before = stored(&dir, &item);
            let client = keychain_client(&url, &dir, &item);
            let outcome = client
                .refresh_shared(&path, &row_tokens, &SharedRefreshOptions::default())
                .await
                .unwrap();
            assert_eq!(outcome.source, RefreshSource::ClaudeCode);
            assert_eq!(outcome.tokens.access, native.access);
            assert_eq!(hits.load(Ordering::SeqCst), 0);
            assert_eq!(row(&path).oauth().unwrap().refresh, native.refresh);
            assert_eq!(stored(&dir, &item), before, "an adopt never writes");
            assert!(
                !dir.join(".credentials.json").exists(),
                "no file is created"
            );

            // Publish: both expired, the row's copy newer; one spend, the
            // rotation written into the Keychain item, unknown keys kept,
            // and the secret never on argv.
            let (url, seen) =
                recording_server(200, ROTATED_BODY, std::time::Duration::ZERO, None).await;
            let path = store_path("kc-publish");
            let dir = path.parent().unwrap().to_path_buf();
            let item = crate::credentials::source::tests::item(&dir);
            let row_tokens = identified(pair("kc-publish-store", at(-10)));
            seeded_store(&path, &row_tokens);
            claude_json(&dir, ACCOUNT);
            seed(
                &dir,
                &item,
                &keychain_document(&pair("kc-publish-native", at(-3_600))),
            );
            let outcome = keychain_client(&url, &dir, &item)
                .refresh_shared(&path, &row_tokens, &SharedRefreshOptions::default())
                .await
                .unwrap();
            assert_eq!(outcome.source, RefreshSource::Refreshed);
            assert_eq!(outcome.native_publish, Some(NativePublishOutcome::Written));
            assert_eq!(seen.lock().unwrap().len(), 1);
            let doc: serde_json::Value =
                serde_json::from_str(&stored(&dir, &item).unwrap()).unwrap();
            assert_eq!(doc["claudeAiOauth"]["refreshToken"], NEW_REFRESH);
            assert_eq!(doc["claudeAiOauth"]["subscriptionType"], "max");
            assert_eq!(doc["mcpOAuth"]["keep"], true);
            let argv = std::fs::read_to_string(dir.join("argv.log")).unwrap();
            assert!(!argv.contains("sk-ant"), "{argv}");
            assert!(argv.lines().any(|l| l == r#"["-i"]"#));
            std::fs::remove_dir_all(dir).ok();
        }

        #[tokio::test]
        async fn the_keychain_backend_never_writes_another_account_or_creates_an_item() {
            use crate::credentials::source::tests::{item, seed, stored};

            // Another account: not linked, not borrowed, never written.
            let (url, hits) = token_server(200, ROTATED_BODY).await;
            let path = store_path("kc-other");
            let dir = path.parent().unwrap().to_path_buf();
            let item = item(&dir);
            let row_tokens = identified(pair("kc-other-store", at(-10)));
            seeded_store(&path, &row_tokens);
            claude_json(&dir, "acct-someone-else");
            let theirs = pair("kc-other-native", Utc::now() + Duration::hours(6));
            seed(&dir, &item, &keychain_document(&theirs));
            let before = stored(&dir, &item);
            let outcome = keychain_client(&url, &dir, &item)
                .refresh_shared(&path, &row_tokens, &SharedRefreshOptions::default())
                .await
                .unwrap();
            assert_eq!(outcome.source, RefreshSource::Refreshed);
            assert_eq!(
                outcome.native_publish,
                Some(NativePublishOutcome::OtherAccount)
            );
            assert_eq!(hits.load(Ordering::SeqCst), 1);
            assert_eq!(stored(&dir, &item), before);
            std::fs::remove_dir_all(&dir).ok();

            // No item: nothing to link, and none is created.
            let (url, _) = token_server(200, ROTATED_BODY).await;
            let path = store_path("kc-absent");
            let dir = path.parent().unwrap().to_path_buf();
            let item = crate::credentials::source::tests::item(&dir);
            let row_tokens = identified(pair("kc-absent-store", at(-10)));
            seeded_store(&path, &row_tokens);
            claude_json(&dir, ACCOUNT);
            let outcome = keychain_client(&url, &dir, &item)
                .refresh_shared(&path, &row_tokens, &SharedRefreshOptions::default())
                .await
                .unwrap();
            assert_eq!(outcome.source, RefreshSource::Refreshed);
            assert_eq!(outcome.native_publish, Some(NativePublishOutcome::Absent));
            assert_eq!(stored(&dir, &item), None, "never created");
            std::fs::remove_dir_all(dir).ok();
        }

        #[tokio::test]
        async fn a_locked_keychain_is_transient_for_a_linked_row() {
            use crate::credentials::source::tests::{item, seed};

            let (url, hits) = token_server(400, INVALID_GRANT_BODY).await;
            let path = store_path("kc-locked");
            let dir = path.parent().unwrap().to_path_buf();
            let item = item(&dir);
            let row_tokens = identified(pair("kc-locked-store", at(-10)));
            seeded_store(&path, &row_tokens);
            claude_json(&dir, ACCOUNT);
            let native = pair("kc-locked-native", Utc::now() + Duration::hours(6));
            seed(&dir, &item, &keychain_document(&native));
            std::fs::write(dir.join("mode"), "locked").unwrap();
            let client = keychain_client(&url, &dir, &item);
            let error = client
                .refresh_shared(&path, &row_tokens, &SharedRefreshOptions::default())
                .await
                .unwrap_err();
            assert!(matches!(error, Error::LinkBusy { .. }), "{error:?}");
            assert_eq!(hits.load(Ordering::SeqCst), 0);
            assert_not_dead(&path);
            // Unlocked: adopted.
            std::fs::remove_file(dir.join("mode")).unwrap();
            let outcome = client
                .refresh_shared(&path, &row_tokens, &SharedRefreshOptions::default())
                .await
                .unwrap();
            assert_eq!(outcome.source, RefreshSource::ClaudeCode);
            assert_eq!(outcome.tokens.access, native.access);
            assert_eq!(hits.load(Ordering::SeqCst), 0);
            std::fs::remove_dir_all(dir).ok();
        }
    }
}
