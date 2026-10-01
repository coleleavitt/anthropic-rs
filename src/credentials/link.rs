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
//!   organizationUuid}` in `.claude.json` (`$CLAUDE_CONFIG_DIR/.claude.json`,
//!   else `~/.claude.json`). When `.claude.json` names no identity, the
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

use super::publish::{NativeWriteLock, ProperLock};
use super::{NativePublish, NativePublishOutcome, import_native_claude_file};
use crate::account::Account;
use crate::error::Result;
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

/// Claude Code's two files: the credential file and the global config that
/// names the logged-in account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaudeCodeFiles {
    /// `.credentials.json` (the tokens).
    pub credentials: PathBuf,
    /// `.claude.json` (`oauthAccount`: who is logged in).
    pub config: PathBuf,
}

impl ClaudeCodeFiles {
    /// Claude Code's own files from an environment lookup: the credential
    /// file as [`super::native_claude_credentials_path_from_lookup`], and
    /// `$CLAUDE_CONFIG_DIR/.claude.json`, else `$HOME/.claude.json`.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let credentials = super::native_claude_credentials_path_from_lookup(&lookup);
        let config = match lookup("CLAUDE_CONFIG_DIR").filter(|v| !v.is_empty()) {
            Some(directory) => PathBuf::from(directory).join(NATIVE_CONFIG_FILE_NAME),
            None => {
                let home = lookup("HOME")
                    .filter(|v| !v.is_empty())
                    .or_else(|| lookup("USERPROFILE").filter(|v| !v.is_empty()))
                    .unwrap_or_else(|| ".".into());
                PathBuf::from(home).join(NATIVE_CONFIG_FILE_NAME)
            }
        };
        Self {
            credentials,
            config,
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
        let inside = directory.join(NATIVE_CONFIG_FILE_NAME);
        let config = if std::fs::symlink_metadata(&inside).is_err()
            && directory.file_name().is_some_and(|n| n == ".claude")
        {
            directory
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(NATIVE_CONFIG_FILE_NAME)
        } else {
            inside
        };
        Self {
            credentials: credentials.to_path_buf(),
            config,
        }
    }

    /// Claude Code's config directory (where its locks live).
    pub fn config_directory(&self) -> &Path {
        self.credentials.parent().unwrap_or_else(|| Path::new("."))
    }
}

impl NativePublish {
    /// Claude Code's files for the link and the by-account publish, or
    /// `None` when the policy is off or (for `Auto`) OAuth test mode
    /// suppresses it. `At(path)` names the credential file; its
    /// `.claude.json` is found by [`ClaudeCodeFiles::for_credentials`].
    pub fn files(&self, test_mode: bool) -> Option<ClaudeCodeFiles> {
        match self {
            Self::Off => None,
            Self::Auto if test_mode => None,
            Self::Auto => Some(ClaudeCodeFiles::from_env()),
            Self::At(path) => Some(ClaudeCodeFiles::for_credentials(path)),
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

/// Read Claude Code's login from `files`, or `None` when there is no usable
/// credential file or no identity. `store` supplies the local fallback
/// identity (a row holding Claude Code's exact refresh or access token).
/// Never calls the network and never writes.
pub fn read_claude_code_login(
    files: &ClaudeCodeFiles,
    store: Option<&AccountStore>,
) -> Option<ClaudeCodeLogin> {
    if std::fs::symlink_metadata(&files.credentials).is_err() {
        return None;
    }
    let mut tokens = import_native_claude_file(Some(&files.credentials))
        .ok()?
        .tokens;
    let (identity, identity_source) = match read_claude_code_identity(&files.config) {
        Some(identity) => (identity, IdentitySource::Config),
        None => {
            let row = store?.accounts.iter().find(|a| {
                a.oauth().is_some_and(|t| {
                    t.refresh == tokens.refresh || t.access.expose() == tokens.access.expose()
                })
            })?;
            (
                ClaudeCodeIdentity::of_tokens(row.oauth()?)?,
                IdentitySource::Store,
            )
        }
    };
    tokens.account = Some(TokenAccount {
        uuid: identity.account_uuid.clone(),
        email_address: identity.email.clone(),
    });
    tokens.organization = Some(TokenOrganization {
        uuid: identity.organization_uuid.clone(),
    });
    Some(ClaudeCodeLogin {
        tokens,
        identity,
        identity_source,
    })
}

/// [`read_claude_code_login`] under Claude Code's `.storage-write.lock`, so
/// the snapshot is never one of its half-done writes. `None` also when the
/// lock stays held by a live writer.
pub fn read_claude_code_login_locked(
    files: &ClaudeCodeFiles,
    store: Option<&AccountStore>,
) -> Option<ClaudeCodeLogin> {
    if std::fs::symlink_metadata(&files.credentials).is_err() {
        return None;
    }
    let _lock = NativeWriteLock::acquire(files.config_directory())?;
    read_claude_code_login(files, store)
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
/// with compare-and-swap on the row's refresh token; Claude Code's file is
/// read under its write lock and written only by
/// [`super::publish_native_login`]. No network.
pub fn reconcile_claude_code_link(
    path: &Path,
    files: &ClaudeCodeFiles,
    account_id: &str,
) -> Result<LinkReconcile> {
    // A row rotated by a peer between the read and the CAS is re-judged.
    for _ in 0..3 {
        let store = AccountStore::read_locked(path, |store| Ok(store.clone()))?;
        let Some(login) = read_claude_code_login_locked(files, Some(&store)) else {
            return Ok(LinkReconcile::NotLinked);
        };
        let Some(account) = store.get(account_id) else {
            return Ok(LinkReconcile::NotLinked);
        };
        let Some(row) = account.oauth() else {
            return Ok(LinkReconcile::NotLinked);
        };
        if !is_linked(account, &login.identity) {
            return Ok(LinkReconcile::NotLinked);
        }
        if row.refresh == login.tokens.refresh {
            return Ok(LinkReconcile::Native {
                tokens: merged(row, login.tokens),
                adopted: false,
            });
        }
        if native_wins(account, row, &login.tokens) {
            let expected = row.refresh.clone();
            let adopted = AccountStore::mutate(path, |store| {
                Ok(store.adopt_claude_code_login(account_id, &expected, login.tokens.clone()))
            })?;
            if let Some(tokens) = adopted {
                return Ok(LinkReconcile::Native {
                    tokens,
                    adopted: true,
                });
            }
            continue;
        }
        let publish = super::publish_native_login(files, None, row);
        return Ok(LinkReconcile::Store {
            tokens: row.clone(),
            publish,
        });
    }
    Ok(LinkReconcile::NotLinked)
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
}
