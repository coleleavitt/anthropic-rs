//! One login per account, shared between Claude Code and the store.
//!
//! Logging into an Anthropic account through the shared OAuth client
//! **revokes that account's older login**: two independent logins to the
//! same account cannot coexist. Logging into Claude Code kills the store's
//! login for that account, and a store (or plugin) login kills Claude
//! Code's. Before this module that was the dominant cause of
//! `invalid_grant` (doc 23 §8): the store kept presenting a refresh token
//! that a later Claude Code login had already revoked.
//!
//! So a store row and Claude Code that hold the same account share **one**
//! login, kept in step both ways:
//!
//! - **Link by identity.** A row is *linked* when its account uuid and
//!   organization uuid equal Claude Code's `oauthAccount.{accountUuid,
//!   organizationUuid}` in `.claude.json` (`~/.claude.json` by default and
//!   for `CLAUDE_CONFIG_DIR=~/.claude`; a custom `CLAUDE_CONFIG_DIR`'s own
//!   `.claude.json`; see [`ClaudeCodeFiles::from_lookup`]). When `.claude.json` names no identity, the
//!   identity of a store row that already holds Claude Code's exact token is
//!   used. Linking never calls the network.
//! - **Newest copy wins** ([`reconcile_claude_code_link`]). When the two
//!   copies differ, the one whose access token expires later is the newer
//!   login (or rotation): Claude Code's is adopted into the row (keeping its
//!   id, label, quota and unknown fields, and clearing the error and the
//!   dead-token verdict, which belonged to the revoked token), or the row's
//!   is published to Claude Code by account
//!   ([`super::publish_native_login`]). A row whose own token is recorded
//!   dead always yields to Claude Code's.
//! - **Borrow, don't rotate.** While Claude Code's access token is live the
//!   store hands it out and refreshes nothing (`OAuthClient::refresh_shared`,
//!   `access::get_access_token`). Only when it has expired does the store
//!   refresh, once, under Claude Code's own refresh lock
//!   ([`ClaudeCodeRefreshLock`]), and publish the rotation back.
//!
//! The link is part of the native-publish policy: it is active wherever
//! [`super::NativePublish`] resolves Claude Code's files
//! ([`super::NativePublish::files`]): off with `ANTHROPIC_NATIVE_PUBLISH=0`,
//! and `Auto` is suppressed in OAuth test mode, so a test never reads or
//! writes a developer's real `~/.claude`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::Deserialize;

use super::publish::{LockFailure, NativeWriteLock, ProperLock};
use super::source::{CredentialBackend, NativeRaw};
use super::{
    NativeClaudeCredentialSource,
    NativeClaudeImport,
    NativePublish,
    NativePublishOutcome,
};
use crate::account::Account;
use crate::error::{Error, Result};
use crate::store::AccountStore;
use crate::token::{OAuthTokens, RefreshToken, TokenAccount, TokenOrganization};

/// Claude Code's global config file name (holds `oauthAccount`).
pub const NATIVE_CONFIG_FILE_NAME: &str = ".claude.json";

/// Claude Code's OAuth refresh lock directory, inside its config dir
/// (`proper-lockfile`, `lockfilePath: <dir>/.oauth_refresh.lock`).
pub const NATIVE_REFRESH_LOCK_NAME: &str = ".oauth_refresh.lock";

/// Claude Code treats a refresh lock older than this as abandoned
/// (`stale: 60000`).
pub const NATIVE_REFRESH_LOCK_STALE: Duration = Duration::from_secs(60);

/// `.claude.json` can hold a long project history; it is read only for its
/// `oauthAccount` block, and refused above this size.
const MAX_CONFIG_BYTES: u64 = 32 * 1024 * 1024;

/// How long a caller should wait after [`Error::LinkBusy`] (Claude Code's
/// write lock is normally held for milliseconds; a crashed holder goes stale
/// after 15 s).
pub const LINK_BUSY_RETRY_AFTER_MS: u64 = 2_000;

/// Claude Code's credential source and the global config that names the
/// logged-in account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaudeCodeFiles {
    /// `.credentials.json` (the tokens, for [`CredentialBackend::File`]). Its
    /// directory is Claude Code's config directory, where its locks live,
    /// for every backend.
    pub credentials: PathBuf,
    /// `.claude.json` (`oauthAccount`: who is logged in).
    pub config: PathBuf,
    /// Where the tokens are kept: the file above, or the macOS Keychain.
    pub backend: CredentialBackend,
}

impl ClaudeCodeFiles {
    /// Claude Code's own files from an environment lookup: the credential
    /// file as [`super::native_claude_credentials_path_from_lookup`], the
    /// backend as [`CredentialBackend::from_lookup`] (the Keychain on macOS
    /// when there is no `.credentials.json`), and `.claude.json`:
    ///
    /// - no (or an empty) `CLAUDE_CONFIG_DIR`: `$HOME/.claude.json`;
    /// - a `CLAUDE_CONFIG_DIR`: the same rule as
    ///   [`ClaudeCodeFiles::for_credentials`] applies to that directory, so
    ///   `CLAUDE_CONFIG_DIR=~/.claude` without its own `.claude.json` still
    ///   finds `~/.claude.json`, and any directory holding a `.claude.json`
    ///   keeps it.
    ///
    /// `CLAUDE_SECURESTORAGE_CONFIG_DIR` moves only the credential file,
    /// never `.claude.json`.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let credentials = super::native_claude_credentials_path_from_lookup(&lookup);
        let config = match lookup("CLAUDE_CONFIG_DIR").filter(|v| !v.is_empty()) {
            Some(directory) => config_for_directory(Path::new(&directory)),
            None => {
                let home = lookup("HOME")
                    .filter(|v| !v.is_empty())
                    .or_else(|| lookup("USERPROFILE").filter(|v| !v.is_empty()))
                    .unwrap_or_else(|| ".".into());
                PathBuf::from(home).join(NATIVE_CONFIG_FILE_NAME)
            }
        };
        let backend = CredentialBackend::from_lookup(&lookup, &credentials);
        Self {
            credentials,
            config,
            backend,
        }
    }

    /// Claude Code's own files from the process environment.
    pub fn from_env() -> Self {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// The files that go with an explicit credential file: `.claude.json`
    /// beside it when there is one (a `CLAUDE_CONFIG_DIR` layout), else,
    /// for a `.claude` directory, `.claude.json` beside that directory (the
    /// default `~/.claude` + `~/.claude.json` layout).
    pub fn for_credentials(credentials: &Path) -> Self {
        let directory = credentials.parent().unwrap_or_else(|| Path::new("."));
        Self {
            credentials: credentials.to_path_buf(),
            config: config_for_directory(directory),
            backend: CredentialBackend::File,
        }
    }

    /// The same files with another credential backend.
    #[must_use]
    pub fn with_backend(mut self, backend: CredentialBackend) -> Self {
        self.backend = backend;
        self
    }

    /// Claude Code's config directory (where its locks live).
    pub fn config_directory(&self) -> &Path {
        self.credentials.parent().unwrap_or_else(|| Path::new("."))
    }
}

/// `.claude.json` for a Claude Code config directory: the one inside it when
/// there is one, else, for a `.claude` directory, the one beside it (the
/// default `~/.claude` + `~/.claude.json` layout).
fn config_for_directory(directory: &Path) -> PathBuf {
    let inside = directory.join(NATIVE_CONFIG_FILE_NAME);
    if std::fs::symlink_metadata(&inside).is_err()
        && directory.file_name().is_some_and(|n| n == ".claude")
    {
        directory
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(NATIVE_CONFIG_FILE_NAME)
    } else {
        inside
    }
}

impl NativePublish {
    /// Claude Code's files for the link and the by-account publish, or
    /// `None` when the policy is off or (for `Auto`) OAuth test mode
    /// suppresses it. `At(path)` names the credential file; its
    /// `.claude.json` is found by [`ClaudeCodeFiles::for_credentials`], and
    /// its backend is the file unless
    /// [`super::CREDENTIALS_BACKEND_ENV`] explicitly says `keychain` (how
    /// the Keychain backend is exercised against a fake `security`).
    pub fn files(&self, test_mode: bool) -> Option<ClaudeCodeFiles> {
        match self {
            Self::Off => None,
            Self::Auto if test_mode => None,
            Self::Auto => Some(ClaudeCodeFiles::from_env()),
            Self::At(path) => {
                let files = ClaudeCodeFiles::for_credentials(path);
                Some(
                    match CredentialBackend::explicit_from_lookup(|k| std::env::var(k).ok()) {
                        Some(backend) => files.with_backend(backend),
                        None => files,
                    },
                )
            }
        }
    }
}

/// The account Claude Code is logged into. Not a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaudeCodeIdentity {
    /// `oauthAccount.accountUuid`.
    pub account_uuid: String,
    /// `oauthAccount.organizationUuid`.
    pub organization_uuid: String,
    /// `oauthAccount.emailAddress` (display only).
    pub email: Option<String>,
}

impl ClaudeCodeIdentity {
    /// The identity a token set carries, when it names both an account and
    /// an organization.
    pub fn of_tokens(tokens: &OAuthTokens) -> Option<Self> {
        let account = tokens.account.as_ref()?;
        let organization = tokens.organization.as_ref()?;
        if account.uuid.trim().is_empty() || organization.uuid.trim().is_empty() {
            return None;
        }
        Some(Self {
            account_uuid: account.uuid.clone(),
            organization_uuid: organization.uuid.clone(),
            email: account.email_address.clone(),
        })
    }

    /// Same account and organization (the email is display only).
    pub fn same_account(&self, other: &Self) -> bool {
        self.account_uuid == other.account_uuid && self.organization_uuid == other.organization_uuid
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConfigDocument {
    #[serde(default)]
    oauth_account: Option<ConfigOauthAccount>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConfigOauthAccount {
    #[serde(default)]
    account_uuid: Option<String>,
    #[serde(default)]
    organization_uuid: Option<String>,
    #[serde(default)]
    email_address: Option<String>,
}

/// The account `.claude.json` says Claude Code is logged into, or `None`
/// (no file, a symlink, unreadable, oversized, malformed, or no complete
/// `oauthAccount`). Read-only; never an error.
pub fn read_claude_code_identity(config: &Path) -> Option<ClaudeCodeIdentity> {
    let raw = crate::file_security::read_bounded_regular(
        config,
        MAX_CONFIG_BYTES,
        false,
        "claude config",
    )
    .ok()?;
    let document: ConfigDocument = serde_json::from_slice(&raw).ok()?;
    let account = document.oauth_account?;
    let account_uuid = account.account_uuid.filter(|v| !v.trim().is_empty())?;
    let organization_uuid = account.organization_uuid.filter(|v| !v.trim().is_empty())?;
    Some(ClaudeCodeIdentity {
        account_uuid,
        organization_uuid,
        email: account.email_address.filter(|v| !v.trim().is_empty()),
    })
}

/// Where a [`ClaudeCodeLogin`]'s identity came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentitySource {
    /// `.claude.json` `oauthAccount`.
    Config,
    /// A store row that already holds Claude Code's exact token.
    Store,
}

/// Claude Code's login: its tokens (with the identity filled in) and the
/// account it belongs to. `Debug` never shows a token.
#[derive(Debug, Clone)]
pub struct ClaudeCodeLogin {
    /// The tokens in `.credentials.json`, with `account` / `organization`
    /// set from the identity.
    pub tokens: OAuthTokens,
    /// Who is logged in.
    pub identity: ClaudeCodeIdentity,
    /// Where the identity came from.
    pub identity_source: IdentitySource,
}

/// The error for a Claude Code credential read that could not be made right
/// now (secret-free reason).
pub(crate) fn link_busy(reason: impl Into<String>) -> Error {
    Error::LinkBusy {
        reason: crate::token::redact_secrets(&reason.into()),
        retry_after_ms: LINK_BUSY_RETRY_AFTER_MS,
    }
}

/// Claude Code's credential document through its backend: `Ok(None)` when
/// there is none or it is unusable (absent, a symlink, group/world
/// readable, malformed: Claude Code treats a corrupt document as no login
/// too), `Err(reason)` when it could not be read right now.
fn load_native(files: &ClaudeCodeFiles) -> std::result::Result<Option<NativeClaudeImport>, String> {
    let raw = match super::source::read_raw(files, true) {
        NativeRaw::Present(raw) => raw,
        NativeRaw::Absent | NativeRaw::Refused(_) => return Ok(None),
        NativeRaw::Unavailable(reason) => return Err(reason),
    };
    let source = match &files.backend {
        CredentialBackend::File => {
            NativeClaudeCredentialSource::CredentialsFile(files.credentials.clone())
        }
        CredentialBackend::Keychain(item) => NativeClaudeCredentialSource::SecureStorage {
            service: item.service.clone(),
            account: item.account.clone(),
        },
    };
    Ok(super::parse_native_document(&raw, source).ok())
}

/// Read Claude Code's login from `files`, or `None` when there is no usable
/// credential, no identity, or it cannot be read right now. `store` supplies
/// the local fallback identity (a row holding Claude Code's exact refresh or
/// access token). Never calls the network and never writes.
pub fn read_claude_code_login(
    files: &ClaudeCodeFiles,
    store: Option<&AccountStore>,
) -> Option<ClaudeCodeLogin> {
    try_read_claude_code_login(files, store).ok().flatten()
}

/// [`read_claude_code_login`] that tells "no login" (`Ok(None)`) from "could
/// not read it right now" ([`Error::LinkBusy`]: an I/O error, a locked
/// Keychain, a failed or timed-out `security`).
pub fn try_read_claude_code_login(
    files: &ClaudeCodeFiles,
    store: Option<&AccountStore>,
) -> Result<Option<ClaudeCodeLogin>> {
    let mut tokens = match load_native(files) {
        Ok(Some(import)) => import.tokens,
        Ok(None) => return Ok(None),
        Err(reason) => return Err(link_busy(reason)),
    };
    let (identity, identity_source) = match read_claude_code_identity(&files.config) {
        Some(identity) => (identity, IdentitySource::Config),
        None => {
            let found = store.and_then(|store| {
                let row = store.accounts.iter().find(|a| {
                    a.oauth().is_some_and(|t| {
                        t.refresh == tokens.refresh || t.access.expose() == tokens.access.expose()
                    })
                })?;
                ClaudeCodeIdentity::of_tokens(row.oauth()?)
            });
            match found {
                Some(identity) => (identity, IdentitySource::Store),
                None => return Ok(None),
            }
        }
    };
    tokens.account = Some(TokenAccount {
        uuid: identity.account_uuid.clone(),
        email_address: identity.email.clone(),
    });
    tokens.organization = Some(TokenOrganization {
        uuid: identity.organization_uuid.clone(),
    });
    Ok(Some(ClaudeCodeLogin {
        tokens,
        identity,
        identity_source,
    }))
}

/// [`read_claude_code_login`] under Claude Code's `.storage-write.lock`, so
/// the snapshot is never one of its half-done writes. `None` also when the
/// lock stays held by a live writer.
pub fn read_claude_code_login_locked(
    files: &ClaudeCodeFiles,
    store: Option<&AccountStore>,
) -> Option<ClaudeCodeLogin> {
    try_read_claude_code_login_locked(files, store)
        .ok()
        .flatten()
}

/// [`read_claude_code_login_locked`] that reports a lock held past its
/// bounded wait (about 7 s), or a read that failed transiently, as
/// [`Error::LinkBusy`] instead of "no login". A missing config directory
/// means no Claude Code write can be in flight; it is read unlocked.
pub fn try_read_claude_code_login_locked(
    files: &ClaudeCodeFiles,
    store: Option<&AccountStore>,
) -> Result<Option<ClaudeCodeLogin>> {
    if matches!(files.backend, CredentialBackend::File)
        && std::fs::symlink_metadata(&files.credentials)
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
    {
        return Ok(None);
    }
    let _lock = match NativeWriteLock::try_acquire(files.config_directory()) {
        Ok(lock) => Some(lock),
        Err(LockFailure::Io(std::io::ErrorKind::NotFound)) => None,
        Err(LockFailure::Busy) => {
            return Err(link_busy(
                "Claude Code's credential write lock (.storage-write.lock) stayed held",
            ));
        }
        Err(LockFailure::Io(kind)) => {
            return Err(link_busy(format!(
                "Claude Code's credential write lock could not be taken: {kind}"
            )));
        }
    };
    try_read_claude_code_login(files, store)
}

/// Whether `account` is linked to Claude Code's login (same account uuid and
/// organization uuid).
pub fn is_linked(account: &Account, identity: &ClaudeCodeIdentity) -> bool {
    account
        .oauth()
        .and_then(ClaudeCodeIdentity::of_tokens)
        .is_some_and(|row| row.same_account(identity))
}

/// The link state of one row. Booleans only; never a token or fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClaudeCodeLinkStatus {
    /// The row is the account Claude Code is logged into.
    pub linked: bool,
    /// Claude Code's access token is live (outside the refresh leeway).
    pub native_live: bool,
    /// The row's access token is live (outside the refresh leeway).
    pub store_live: bool,
    /// The row and Claude Code hold the same refresh token.
    pub same_refresh: bool,
    /// The copies differ and Claude Code's is the newer login (its access
    /// token expires later, or the row's token is recorded dead): the row's
    /// token is most likely revoked and will be healed by adopting.
    pub native_newer: bool,
}

/// The link state of `account` against Claude Code's `login`.
pub fn link_status(
    account: &Account,
    login: Option<&ClaudeCodeLogin>,
    now: DateTime<Utc>,
) -> ClaudeCodeLinkStatus {
    let (Some(login), Some(row)) = (login, account.oauth()) else {
        return ClaudeCodeLinkStatus::default();
    };
    if !is_linked(account, &login.identity) {
        return ClaudeCodeLinkStatus::default();
    }
    let same_refresh = row.refresh == login.tokens.refresh;
    ClaudeCodeLinkStatus {
        linked: true,
        native_live: !login.tokens.needs_refresh(now),
        store_live: !row.access.expose().is_empty() && !row.needs_refresh(now),
        same_refresh,
        native_newer: !same_refresh && native_wins(account, row, &login.tokens),
    }
}

/// Claude Code's copy wins when it expires no earlier than the row's, or
/// when the row's own token is recorded dead.
fn native_wins(account: &Account, row: &OAuthTokens, native: &OAuthTokens) -> bool {
    account.refresh_token_is_dead() || native.expires_at >= row.expires_at
}

/// What [`reconcile_claude_code_link`] did.
#[derive(Debug, Clone)]
pub enum LinkReconcile {
    /// The row is not linked (no Claude Code login, no identity, another
    /// account, or the row is not OAuth).
    NotLinked,
    /// Claude Code's copy is the current one, and the row now holds it.
    Native {
        /// The shared login (the row's metadata, Claude Code's tokens).
        tokens: OAuthTokens,
        /// Whether the row had to adopt it (it held an older, revoked token).
        adopted: bool,
    },
    /// The row's copy is newer; it was published to Claude Code by account.
    Store {
        /// The row's tokens.
        tokens: OAuthTokens,
        /// What the publish did.
        publish: NativePublishOutcome,
    },
}

/// Bring a linked row and Claude Code's login into agreement, newest copy
/// winning (module docs). Store writes go through [`AccountStore::mutate`]
/// with compare-and-swap on the row's refresh token; Claude Code's
/// credentials are read under its write lock and written only by
/// [`super::publish_native_login`]. No network.
///
/// A row whose identity is Claude Code's account is never judged without
/// that read: when Claude Code's write lock stays held or the read fails
/// transiently this returns [`Error::LinkBusy`] (retry later) instead of
/// [`LinkReconcile::NotLinked`], so no caller goes on to spend or mark dead
/// a token that a newer Claude Code login may have replaced.
pub fn reconcile_claude_code_link(
    path: &Path,
    files: &ClaudeCodeFiles,
    account_id: &str,
) -> Result<LinkReconcile> {
    reconcile_link(path, files, account_id).map(|r| r.outcome)
}

/// [`reconcile_claude_code_link`] and the refresh token Claude Code held when
/// it was judged (the snapshot a later publish may replace, and nothing
/// else).
#[derive(Debug, Clone)]
pub(crate) struct Reconciled {
    pub(crate) outcome: LinkReconcile,
    pub(crate) native_refresh: Option<RefreshToken>,
}

pub(crate) fn reconcile_link(
    path: &Path,
    files: &ClaudeCodeFiles,
    account_id: &str,
) -> Result<Reconciled> {
    let not_linked = Reconciled {
        outcome: LinkReconcile::NotLinked,
        native_refresh: None,
    };
    // Set when Claude Code's copy changed under a publish: whatever it holds
    // now was written after this judged the row newer (a `/login`), so it is
    // adopted, never overwritten.
    let mut native_changed = false;
    // A row rotated by a peer between the read and the CAS is re-judged.
    for _ in 0..3 {
        let store = AccountStore::read_locked(path, |store| Ok(store.clone()))?;
        let login = match try_read_claude_code_login_locked(files, Some(&store)) {
            Ok(Some(login)) => login,
            Ok(None) => return Ok(not_linked),
            Err(busy) => {
                return if row_may_be_linked(files, &store, account_id) {
                    Err(busy)
                } else {
                    Ok(not_linked)
                };
            }
        };
        let Some(account) = store.get(account_id) else {
            return Ok(not_linked);
        };
        let Some(row) = account.oauth() else {
            return Ok(not_linked);
        };
        if !is_linked(account, &login.identity) {
            return Ok(not_linked);
        }
        let native_refresh = Some(login.tokens.refresh.clone());
        if row.refresh == login.tokens.refresh {
            return Ok(Reconciled {
                outcome: LinkReconcile::Native {
                    tokens: merged(row, login.tokens),
                    adopted: false,
                },
                native_refresh,
            });
        }
        if native_changed || native_wins(account, row, &login.tokens) {
            let expected = row.refresh.clone();
            let adopted = AccountStore::mutate(path, |store| {
                Ok(store.adopt_claude_code_login(account_id, &expected, login.tokens.clone()))
            })?;
            if let Some(tokens) = adopted {
                return Ok(Reconciled {
                    outcome: LinkReconcile::Native {
                        tokens,
                        adopted: true,
                    },
                    native_refresh,
                });
            }
            continue;
        }
        // The row is newer: replace exactly the copy judged older, never one
        // Claude Code wrote since.
        let publish =
            super::publish_native_login_guarded(files, None, Some(&login.tokens.refresh), row);
        if publish == NativePublishOutcome::NotHeld {
            native_changed = true;
            continue;
        }
        return Ok(Reconciled {
            outcome: LinkReconcile::Store {
                tokens: row.clone(),
                publish,
            },
            native_refresh,
        });
    }
    Ok(not_linked)
}

/// Whether `account_id` may be Claude Code's account although its
/// credentials could not be read: `.claude.json` names the row's account, or
/// (without one) an unlocked read finds a login linked to it.
fn row_may_be_linked(files: &ClaudeCodeFiles, store: &AccountStore, account_id: &str) -> bool {
    let Some(account) = store.get(account_id) else {
        return false;
    };
    if let Some(identity) = read_claude_code_identity(&files.config) {
        return is_linked(account, &identity);
    }
    try_read_claude_code_login(files, Some(store))
        .ok()
        .flatten()
        .is_some_and(|login| is_linked(account, &login.identity))
}

/// `native` with the row's metadata where Claude Code's file has none.
fn merged(row: &OAuthTokens, mut native: OAuthTokens) -> OAuthTokens {
    if native.refresh_expires_at.is_none() {
        native.refresh_expires_at = row.refresh_expires_at;
    }
    if native.scopes.is_empty() {
        native.scopes = row.scopes.clone();
    }
    if native.account.is_none() {
        native.account = row.account.clone();
    }
    if native.organization.is_none() {
        native.organization = row.organization.clone();
    }
    native
}

impl AccountStore {
    /// Adopt Claude Code's login into `account_id` (in-memory form; persist
    /// with [`AccountStore::mutate`]): compare-and-swap on the row still
    /// holding `expected_refresh`, then the [`AccountStore::merge_login`]
    /// semantics for a re-login of the same account: the credential is
    /// replaced, the error, dead-token verdict, refresh claim and cooldown
    /// that belonged to the revoked token are cleared, and the id, label,
    /// quota, pin, `enabled` and unknown fields are kept. Returns the row's
    /// new tokens, or `None` when the row is gone or holds another token.
    pub fn adopt_claude_code_login(
        &mut self,
        account_id: &str,
        expected_refresh: &RefreshToken,
        native: OAuthTokens,
    ) -> Option<OAuthTokens> {
        let account = self.accounts.iter_mut().find(|a| a.id == account_id)?;
        let row = account.oauth()?;
        if &row.refresh != expected_refresh {
            return None;
        }
        let next = merged(row, native);
        account.replace_oauth_tokens(next).ok()?;
        account.clear_error();
        account.dead_refresh_fingerprint = None;
        account.refresh_lease = None;
        account.rate_limited_until = None;
        account.oauth().cloned()
    }
}

/// Claude Code's OAuth refresh lock: `<config dir>/.oauth_refresh.lock`
/// plus the legacy `<config dir>.lock` that older Claude Code versions use
/// (Claude Code 2.1.286 takes both). While the store holds it, no Claude
/// Code process refreshes this login; one that was waiting re-reads the
/// file afterwards and finds the published rotation. Released on drop.
pub struct ClaudeCodeRefreshLock {
    _primary: ProperLock,
    _legacy: Option<ProperLock>,
}

impl ClaudeCodeRefreshLock {
    /// Take both locks for the config directory of `files` (about 7 s of
    /// bounded retries each; an abandoned lock older than
    /// [`NATIVE_REFRESH_LOCK_STALE`] is taken over). `None` when a live
    /// holder keeps either: Claude Code is refreshing right now.
    pub fn acquire(files: &ClaudeCodeFiles) -> Option<Self> {
        let directory = files.config_directory();
        let primary = ProperLock::acquire(
            &directory.join(NATIVE_REFRESH_LOCK_NAME),
            NATIVE_REFRESH_LOCK_STALE,
        )?;
        let legacy_path = {
            let resolved = std::fs::canonicalize(directory).unwrap_or_else(|_| directory.into());
            let mut name = resolved.as_os_str().to_owned();
            name.push(".lock");
            PathBuf::from(name)
        };
        // Claude Code tolerates a legacy lock it cannot create for any
        // reason but contention; so does this.
        let legacy = match ProperLock::acquire(&legacy_path, NATIVE_REFRESH_LOCK_STALE) {
            Some(lock) => Some(lock),
            None if legacy_path.exists() => return None,
            None => None,
        };
        Some(Self {
            _primary: primary,
            _legacy: legacy,
        })
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};

    use super::*;
    use crate::token::{AccessToken, Credential};

    pub(crate) const ACCOUNT: &str = "acct-1111";
    pub(crate) const ORG: &str = "org-2222";

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "anthropic-link-{tag}-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_private(path: &Path, value: &serde_json::Value) {
        std::fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn tokens(tag: &str, expires_at: DateTime<Utc>, identity: bool) -> OAuthTokens {
        OAuthTokens {
            access: AccessToken::new(format!("sk-ant-oat01-{tag}-aaaaaaaaaaaaaaaaaaaa")),
            refresh: RefreshToken::new(format!("sk-ant-ort01-{tag}-aaaaaaaaaaaaaaaaaaaa")),
            expires_at,
            refresh_expires_at: None,
            scopes: vec!["user:inference".into()],
            account: identity.then(|| TokenAccount {
                uuid: ACCOUNT.into(),
                email_address: Some("me@example.com".into()),
            }),
            organization: identity.then(|| TokenOrganization { uuid: ORG.into() }),
        }
    }

    fn native(dir: &Path, tokens: &OAuthTokens, config: Option<(&str, &str)>) -> ClaudeCodeFiles {
        let credentials = dir.join(".credentials.json");
        write_private(
            &credentials,
            &serde_json::json!({
                "claudeAiOauth": {
                    "accessToken": tokens.access.expose(),
                    "refreshToken": tokens.refresh.expose(),
                    "expiresAt": tokens.expires_at.timestamp_millis(),
                    "scopes": ["user:inference", "user:profile"],
                    "subscriptionType": "max"
                }
            }),
        );
        if let Some((account, org)) = config {
            write_private(
                &dir.join(NATIVE_CONFIG_FILE_NAME),
                &serde_json::json!({
                    "numStartups": 3,
                    "projects": { "/x": { "history": [] } },
                    "oauthAccount": {
                        "accountUuid": account,
                        "organizationUuid": org,
                        "emailAddress": "me@example.com"
                    }
                }),
            );
        }
        ClaudeCodeFiles::for_credentials(&credentials)
    }

    fn store_with(dir: &Path, row: OAuthTokens) -> PathBuf {
        let path = dir.join("accounts.json");
        let mut account = Account::new("me", Credential::Oauth(row)).with_label("Mine");
        account.quota = Some(crate::account::QuotaObservation {
            five_hour_percent: Some(12.0),
            seven_day_percent: Some(30.0),
            checked_at: Some(Utc::now()),
        });
        AccountStore {
            accounts: vec![account],
            ..AccountStore::default()
        }
        .save(&path)
        .unwrap();
        path
    }

    #[test]
    fn files_resolve_like_claude_code() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |key: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == key)
                    .map(|(_, v)| (*v).to_owned())
            }
        };
        let default = ClaudeCodeFiles::from_lookup(env(&[("HOME", "/h")]));
        assert_eq!(
            default.credentials,
            PathBuf::from("/h/.claude/.credentials.json")
        );
        assert_eq!(default.config, PathBuf::from("/h/.claude.json"));
        let custom =
            ClaudeCodeFiles::from_lookup(env(&[("HOME", "/h"), ("CLAUDE_CONFIG_DIR", "/c")]));
        assert_eq!(custom.credentials, PathBuf::from("/c/.credentials.json"));
        assert_eq!(custom.config, PathBuf::from("/c/.claude.json"));
        // An explicit credential file in a `.claude` dir pairs with the
        // sibling `.claude.json`; any other dir with the one inside it.
        let dir = temp_dir("files");
        let dot_claude = dir.join(".claude");
        std::fs::create_dir_all(&dot_claude).unwrap();
        let files = ClaudeCodeFiles::for_credentials(&dot_claude.join(".credentials.json"));
        assert_eq!(files.config, dir.join(".claude.json"));
        let files = ClaudeCodeFiles::for_credentials(&dir.join(".credentials.json"));
        assert_eq!(files.config, dir.join(".claude.json"));
        assert_eq!(NativePublish::Auto.files(true), None, "test mode");
        assert_eq!(NativePublish::Off.files(false), None);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A lookup over a temp `HOME` plus extra variables (never the real
    /// environment).
    fn lookup_in(
        home: &Path,
        extra: &[(&'static str, PathBuf)],
    ) -> impl Fn(&str) -> Option<String> {
        let mut vars = vec![("HOME", home.to_string_lossy().into_owned())];
        vars.extend(
            extra
                .iter()
                .map(|(k, v)| (*k, v.to_string_lossy().into_owned())),
        );
        move |key: &str| vars.iter().find(|(k, _)| *k == key).map(|(_, v)| v.clone())
    }

    /// Lay out the default `~/.claude/.credentials.json` + `~/.claude.json`.
    fn default_layout(home: &Path) -> PathBuf {
        let dot_claude = home.join(".claude");
        std::fs::create_dir_all(&dot_claude).unwrap();
        std::fs::write(dot_claude.join(".credentials.json"), b"{}").unwrap();
        std::fs::write(home.join(NATIVE_CONFIG_FILE_NAME), b"{}").unwrap();
        dot_claude
    }

    #[test]
    fn claude_json_is_in_home_by_default() {
        let home = temp_dir("cj-default");
        default_layout(&home);
        let files = ClaudeCodeFiles::from_lookup(lookup_in(&home, &[]));
        assert_eq!(
            files.credentials,
            home.join(".claude").join(".credentials.json")
        );
        assert_eq!(files.config, home.join(NATIVE_CONFIG_FILE_NAME));
        assert_eq!(
            files.config,
            ClaudeCodeFiles::for_credentials(&files.credentials).config
        );
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn claude_config_dir_naming_the_default_keeps_claude_json_in_home() {
        let home = temp_dir("cj-default-dir");
        let dot_claude = default_layout(&home);
        let files =
            ClaudeCodeFiles::from_lookup(lookup_in(&home, &[("CLAUDE_CONFIG_DIR", dot_claude)]));
        assert_eq!(files.config, home.join(NATIVE_CONFIG_FILE_NAME));
        assert_eq!(
            files.config,
            ClaudeCodeFiles::for_credentials(&files.credentials).config
        );
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn a_custom_claude_config_dir_keeps_its_own_claude_json() {
        let home = temp_dir("cj-custom");
        default_layout(&home);
        // A custom dir that is also named `.claude` (the case the sibling
        // fallback must not hijack) and holds its own `.claude.json`.
        let custom = home.join("profiles").join(".claude");
        std::fs::create_dir_all(&custom).unwrap();
        std::fs::write(custom.join(".credentials.json"), b"{}").unwrap();
        std::fs::write(custom.join(NATIVE_CONFIG_FILE_NAME), b"{}").unwrap();
        let files = ClaudeCodeFiles::from_lookup(lookup_in(
            &home,
            &[("CLAUDE_CONFIG_DIR", custom.clone())],
        ));
        assert_eq!(files.credentials, custom.join(".credentials.json"));
        assert_eq!(files.config, custom.join(NATIVE_CONFIG_FILE_NAME));
        // A secure-storage dir moves only the credential file, never
        // `.claude.json`.
        let secure = home.join("secure");
        std::fs::create_dir_all(&secure).unwrap();
        let files = ClaudeCodeFiles::from_lookup(lookup_in(
            &home,
            &[
                ("CLAUDE_CONFIG_DIR", custom.clone()),
                ("CLAUDE_SECURESTORAGE_CONFIG_DIR", secure.clone()),
            ],
        ));
        assert_eq!(files.credentials, secure.join(".credentials.json"));
        assert_eq!(files.config, custom.join(NATIVE_CONFIG_FILE_NAME));
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn identity_comes_from_claude_json_else_from_a_row_holding_the_exact_token() {
        let dir = temp_dir("identity");
        let live = tokens("native", Utc::now() + Duration::hours(4), false);
        let files = native(&dir, &live, Some((ACCOUNT, ORG)));
        let login = read_claude_code_login(&files, None).unwrap();
        assert_eq!(login.identity_source, IdentitySource::Config);
        assert_eq!(login.identity.account_uuid, ACCOUNT);
        assert_eq!(login.tokens.organization.as_ref().unwrap().uuid, ORG);
        assert!(!format!("{login:?}").contains("sk-ant"));

        // No `.claude.json`: only a row holding the exact token supplies it.
        std::fs::remove_file(&files.config).unwrap();
        assert!(read_claude_code_login(&files, None).is_none());
        let other = AccountStore {
            accounts: vec![Account::new(
                "x",
                Credential::Oauth(tokens("other", Utc::now(), true)),
            )],
            ..AccountStore::default()
        };
        assert!(read_claude_code_login(&files, Some(&other)).is_none());
        let mut holding = live.clone();
        holding.account = Some(TokenAccount {
            uuid: ACCOUNT.into(),
            email_address: None,
        });
        holding.organization = Some(TokenOrganization { uuid: ORG.into() });
        let store = AccountStore {
            accounts: vec![Account::new("x", Credential::Oauth(holding))],
            ..AccountStore::default()
        };
        let login = read_claude_code_login(&files, Some(&store)).unwrap();
        assert_eq!(login.identity_source, IdentitySource::Store);
        assert_eq!(login.identity.organization_uuid, ORG);
        // A config without a complete identity is no identity.
        write_private(
            &files.config,
            &serde_json::json!({ "oauthAccount": { "accountUuid": ACCOUNT } }),
        );
        assert!(read_claude_code_identity(&files.config).is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_newer_claude_code_login_is_adopted_keeping_the_rows_metadata() {
        let dir = temp_dir("adopt");
        let stale = tokens(
            "store-old",
            Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            true,
        );
        let path = store_with(&dir, stale.clone());
        AccountStore::mutate(&path, |store| {
            let row = store.get_mut("me")?;
            row.record_error("invalid_grant");
            row.dead_refresh_fingerprint =
                Some(crate::token::token_fingerprint(stale.refresh.expose()));
            Ok(())
        })
        .unwrap();
        let fresh = tokens("native", Utc::now() + Duration::hours(8), false);
        let files = native(&dir, &fresh, Some((ACCOUNT, ORG)));
        let before = std::fs::read(&files.credentials).unwrap();
        match reconcile_claude_code_link(&path, &files, "me").unwrap() {
            LinkReconcile::Native { tokens, adopted } => {
                assert!(adopted);
                assert_eq!(tokens.refresh, fresh.refresh);
            }
            other => panic!("{other:?}"),
        }
        let store = AccountStore::load(&path).unwrap();
        let row = store.get("me").unwrap();
        assert_eq!(row.oauth().unwrap().refresh, fresh.refresh);
        assert_eq!(row.label.as_deref(), Some("Mine"));
        assert!(row.quota.is_some(), "quota kept");
        assert!(row.last_error.is_none(), "error cleared");
        assert!(row.dead_refresh_fingerprint.is_none(), "not dead");
        assert!(!row.refresh_token_is_dead());
        assert_eq!(
            row.oauth().unwrap().account.as_ref().unwrap().uuid,
            ACCOUNT,
            "identity kept"
        );
        // Claude Code's file is never written by an adopt.
        assert_eq!(std::fs::read(&files.credentials).unwrap(), before);
        // Now in step: nothing more to do.
        assert!(matches!(
            reconcile_claude_code_link(&path, &files, "me").unwrap(),
            LinkReconcile::Native { adopted: false, .. }
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_newer_store_login_is_published_and_another_account_is_never_touched() {
        let dir = temp_dir("publish");
        let newer = tokens("store-new", Utc::now() + Duration::hours(8), true);
        let path = store_with(&dir, newer.clone());
        let older = tokens("native-old", Utc::now() + Duration::hours(1), false);
        let files = native(&dir, &older, Some((ACCOUNT, ORG)));
        match reconcile_claude_code_link(&path, &files, "me").unwrap() {
            LinkReconcile::Store { publish, .. } => {
                assert_eq!(publish, NativePublishOutcome::Written);
            }
            other => panic!("{other:?}"),
        }
        let written: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&files.credentials).unwrap()).unwrap();
        assert_eq!(
            written["claudeAiOauth"]["refreshToken"],
            newer.refresh.expose()
        );
        assert_eq!(written["claudeAiOauth"]["subscriptionType"], "max");

        // Claude Code logged into another account: not linked, untouched.
        let files = native(&dir, &older, Some(("acct-someone-else", ORG)));
        let before = std::fs::read(&files.credentials).unwrap();
        assert!(matches!(
            reconcile_claude_code_link(&path, &files, "me").unwrap(),
            LinkReconcile::NotLinked
        ));
        assert_eq!(
            super::super::publish_native_login(&files, None, &newer),
            NativePublishOutcome::OtherAccount
        );
        // Same account, another organization: also another login.
        let files = native(&dir, &older, Some((ACCOUNT, "org-other")));
        assert_eq!(
            super::super::publish_native_login(&files, None, &newer),
            NativePublishOutcome::OtherAccount
        );
        assert_eq!(std::fs::read(&files.credentials).unwrap(), before);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_publish_never_overwrites_a_newer_claude_code_login_of_the_account() {
        let dir = temp_dir("publish-newer");
        let rotated = tokens("store", Utc::now() + Duration::hours(2), true);
        let newer = tokens("native-newer", Utc::now() + Duration::hours(7), false);
        let files = native(&dir, &newer, Some((ACCOUNT, ORG)));
        let before = std::fs::read(&files.credentials).unwrap();
        assert_eq!(
            super::super::publish_native_login(&files, None, &rotated),
            NativePublishOutcome::NotHeld
        );
        assert_eq!(std::fs::read(&files.credentials).unwrap(), before);
        // ...but the exact spent token is always brought forward.
        let spent = newer.refresh.clone();
        assert_eq!(
            super::super::publish_native_login(&files, Some(&spent), &rotated),
            NativePublishOutcome::Written
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_locked_snapshot_waits_for_claude_codes_write_in_flight() {
        let dir = temp_dir("locked-read");
        let old = tokens("old", Utc::now() - Duration::hours(2), false);
        let files = native(&dir, &old, Some((ACCOUNT, ORG)));
        let lock = dir.join(super::super::NATIVE_WRITE_LOCK_NAME);
        std::fs::create_dir(&lock).unwrap();
        let fresh = tokens("fresh", Utc::now() + Duration::hours(8), false);
        let writer = {
            let (dir, fresh, lock) = (dir.clone(), fresh.clone(), lock.clone());
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(400));
                native(&dir, &fresh, None);
                std::fs::remove_dir(&lock).unwrap();
            })
        };
        let login = read_claude_code_login_locked(&files, None).unwrap();
        writer.join().unwrap();
        assert_eq!(
            login.tokens.refresh, fresh.refresh,
            "never the pre-write copy"
        );
        assert!(!lock.exists(), "the reader releases its own lock");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn status_reports_booleans_only() {
        let now = Utc::now();
        let row = Account::new(
            "me",
            Credential::Oauth(tokens("store", now - Duration::hours(1), true)),
        );
        let login = ClaudeCodeLogin {
            tokens: {
                let mut t = tokens("native", now + Duration::hours(3), true);
                t.account.as_mut().unwrap().email_address = None;
                t
            },
            identity: ClaudeCodeIdentity {
                account_uuid: ACCOUNT.into(),
                organization_uuid: ORG.into(),
                email: None,
            },
            identity_source: IdentitySource::Config,
        };
        let status = link_status(&row, Some(&login), now);
        assert_eq!(
            status,
            ClaudeCodeLinkStatus {
                linked: true,
                native_live: true,
                store_live: false,
                same_refresh: false,
                native_newer: true,
            }
        );
        assert_eq!(
            link_status(&row, None, now),
            ClaudeCodeLinkStatus::default()
        );
        let stranger = Account::new(
            "x",
            Credential::Oauth(tokens("x", now + Duration::hours(3), false)),
        );
        assert!(!link_status(&stranger, Some(&login), now).linked);
    }

    #[test]
    fn the_refresh_lock_excludes_claude_code_and_takes_over_a_dead_holder() {
        let dir = temp_dir("refresh-lock");
        let files = ClaudeCodeFiles::for_credentials(&dir.join(".credentials.json"));
        let held = ClaudeCodeRefreshLock::acquire(&files).unwrap();
        assert!(dir.join(NATIVE_REFRESH_LOCK_NAME).is_dir());
        let mut legacy = dir.clone().into_os_string();
        legacy.push(".lock");
        assert!(PathBuf::from(&legacy).is_dir());
        drop(held);
        assert!(!dir.join(NATIVE_REFRESH_LOCK_NAME).exists());
        assert!(!PathBuf::from(&legacy).exists());
        // An abandoned holder (mtime older than 60 s) is taken over.
        std::fs::create_dir(dir.join(NATIVE_REFRESH_LOCK_NAME)).unwrap();
        std::fs::File::open(dir.join(NATIVE_REFRESH_LOCK_NAME))
            .unwrap()
            .set_modified(std::time::SystemTime::now() - Duration::minutes(5).to_std().unwrap())
            .unwrap();
        assert!(ClaudeCodeRefreshLock::acquire(&files).is_some());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_guarded_publish_replaces_only_the_copy_it_judged() {
        let dir = temp_dir("guarded");
        let rotated = tokens("store", Utc::now() + Duration::hours(2), true);
        // Claude Code's copy is older than the rotation, but it is not the
        // one judged moments ago: a `/login` wrote it since. Left alone.
        let relogin = tokens("native-relogin", Utc::now() + Duration::minutes(30), false);
        let files = native(&dir, &relogin, Some((ACCOUNT, ORG)));
        let before = std::fs::read(&files.credentials).unwrap();
        let judged = RefreshToken::new("sk-ant-ort01-judged-aaaaaaaaaaaaaaaaaaaa");
        assert_eq!(
            super::super::publish_native_login_guarded(&files, None, Some(&judged), &rotated),
            NativePublishOutcome::NotHeld
        );
        assert_eq!(std::fs::read(&files.credentials).unwrap(), before);
        // The judged copy itself is replaced, whatever its expiry.
        let longer = tokens("native-judged", Utc::now() + Duration::hours(9), false);
        let files = native(&dir, &longer, Some((ACCOUNT, ORG)));
        assert_eq!(
            super::super::publish_native_login_guarded(
                &files,
                None,
                Some(&longer.refresh),
                &rotated
            ),
            NativePublishOutcome::Written
        );
        // Never for another account.
        let files = native(&dir, &longer, Some(("acct-someone-else", ORG)));
        assert_eq!(
            super::super::publish_native_login_guarded(
                &files,
                None,
                Some(&longer.refresh),
                &rotated
            ),
            NativePublishOutcome::OtherAccount
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_busy_lock_is_link_busy_for_the_linked_row_only() {
        let dir = temp_dir("busy");
        let row = tokens("store-busy", Utc::now() - Duration::hours(1), true);
        let path = store_with(&dir, row);
        let native_tokens = tokens("native-busy", Utc::now() + Duration::hours(4), false);
        let files = native(&dir, &native_tokens, Some((ACCOUNT, ORG)));
        let lock = dir.join(super::super::NATIVE_WRITE_LOCK_NAME);
        std::fs::create_dir(&lock).unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let keeper = {
            let (lock, stop) = (lock.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                    if let Ok(dir) = std::fs::File::open(&lock) {
                        let _ = dir.set_modified(std::time::SystemTime::now());
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            })
        };
        match reconcile_claude_code_link(&path, &files, "me") {
            Err(Error::LinkBusy {
                reason,
                retry_after_ms,
            }) => {
                assert!(reason.contains("storage-write"), "{reason}");
                assert_eq!(retry_after_ms, LINK_BUSY_RETRY_AFTER_MS);
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            try_read_claude_code_login_locked(&files, None),
            Err(Error::LinkBusy { .. })
        ));
        assert!(read_claude_code_login_locked(&files, None).is_none());
        // Claude Code logged into another account: not this row's business.
        let other = native(&dir, &native_tokens, Some(("acct-someone-else", ORG)));
        assert!(matches!(
            reconcile_claude_code_link(&path, &other, "me").unwrap(),
            LinkReconcile::NotLinked
        ));
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        keeper.join().unwrap();
        std::fs::remove_dir(&lock).unwrap();
        // No config dir at all: nothing can be mid-write; an unlocked read.
        let missing = ClaudeCodeFiles::for_credentials(&dir.join("nope").join(".credentials.json"));
        assert!(matches!(
            try_read_claude_code_login_locked(&missing, None),
            Ok(None)
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_keychain_backend_reads_a_login_and_keeps_unknown_keys_on_publish() {
        use crate::credentials::source::tests::{item, seed, stored};
        let dir = temp_dir("keychain-link");
        let item = item(&dir);
        let files = ClaudeCodeFiles::for_credentials(&dir.join(".credentials.json"))
            .with_backend(CredentialBackend::Keychain(item.clone()));
        write_private(
            &files.config,
            &serde_json::json!({
                "oauthAccount": { "accountUuid": ACCOUNT, "organizationUuid": ORG }
            }),
        );
        // No item: no login, and a publish never creates one.
        assert!(try_read_claude_code_login(&files, None).unwrap().is_none());
        let rotated = tokens("kc-rotated", Utc::now() + Duration::hours(8), true);
        assert_eq!(
            super::super::publish_native_login(&files, None, &rotated),
            NativePublishOutcome::Absent
        );
        assert!(stored(&dir, &item).is_none());
        let old = tokens("kc-old", Utc::now() + Duration::hours(1), false);
        seed(
            &dir,
            &item,
            &serde_json::json!({
                "claudeAiOauth": {
                    "accessToken": old.access.expose(),
                    "refreshToken": old.refresh.expose(),
                    "expiresAt": old.expires_at.timestamp_millis(),
                    "scopes": ["user:inference"],
                    "rateLimitTier": "tier"
                },
                "trustedDeviceToken": "keep-me"
            })
            .to_string(),
        );
        let login = try_read_claude_code_login_locked(&files, None)
            .unwrap()
            .unwrap();
        assert_eq!(login.tokens.refresh, old.refresh);
        assert_eq!(login.identity.account_uuid, ACCOUNT);
        assert_eq!(
            super::super::publish_native_login(&files, None, &rotated),
            NativePublishOutcome::Written
        );
        let doc: serde_json::Value = serde_json::from_str(&stored(&dir, &item).unwrap()).unwrap();
        assert_eq!(
            doc["claudeAiOauth"]["refreshToken"],
            rotated.refresh.expose()
        );
        assert_eq!(doc["claudeAiOauth"]["rateLimitTier"], "tier");
        assert_eq!(doc["trustedDeviceToken"], "keep-me");
        assert!(!files.credentials.exists(), "never falls back to a file");
        assert!(!dir.join(super::super::NATIVE_WRITE_LOCK_NAME).exists());
        // `security` failing: transient, never "no login".
        std::fs::write(dir.join("mode"), "fail").unwrap();
        assert!(matches!(
            try_read_claude_code_login(&files, None),
            Err(Error::LinkBusy { .. })
        ));
        assert!(matches!(
            super::super::publish_native_login(&files, None, &rotated),
            NativePublishOutcome::Failed(_)
        ));
        let _ = std::fs::remove_dir_all(dir);
    }
}
