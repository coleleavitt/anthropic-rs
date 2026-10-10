//! The shared, project-neutral multi-account credential store.
//!
//! Canonical location is `~/.anthropic-accounts/accounts.json` so that every
//! consumer — a coding agent, a build tool, a one-off request client — reads the
//! same credentials instead of each keeping a private copy under its own config
//! directory.
//!
//! Resolution order for the store path:
//!   1. an explicit path passed by the caller,
//!   2. `$ANTHROPIC_ACCOUNTS_FILE` (full path),
//!   3. `$ANTHROPIC_ACCOUNTS_DIR/accounts.json`,
//!   4. `$HOME/.anthropic-accounts/accounts.json`.
//!
//! [`AccountStore::load_or_migrate`] additionally folds in any known legacy
//! per-application store that has not been adopted yet — including the flat
//! pre-shared-store schema — so existing logins are merged rather than lost
//! behind whichever file happened to be found first.

use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::account::Account;
use crate::error::{Error, Result};
use crate::token::{ApiKey, Credential, OAuthTokens, RefreshToken};

/// Environment variable naming the store file outright.
pub const STORE_FILE_ENV: &str = "ANTHROPIC_ACCOUNTS_FILE";

/// Environment variable naming the directory that holds `accounts.json`.
pub const STORE_DIR_ENV: &str = "ANTHROPIC_ACCOUNTS_DIR";

/// Directory name under `$HOME` for the shared store.
pub const STORE_DIR_NAME: &str = ".anthropic-accounts";

/// File name within the store directory.
pub const STORE_FILE_NAME: &str = "accounts.json";

/// Orphaned temp files older than this are swept on write.
const ORPHAN_TMP_MAX_AGE_SECS: u64 = 60 * 60;
const STORE_MAX_BYTES: u64 = 4 * 1024 * 1024;
const STORE_LOCK_WAIT: Duration = Duration::from_secs(12);

/// The persisted document.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccountStore {
    /// Schema version, for future migrations.
    #[serde(default = "default_version")]
    pub version: u32,
    /// All known accounts, in routing order.
    #[serde(default)]
    pub accounts: Vec<Account>,
    /// Id of the preferred account, when the user pinned one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<String>,
    /// Legacy store paths whose accounts have already been folded in.
    ///
    /// Re-reading one would resurrect accounts the user has since removed, so
    /// adoption is recorded rather than repeated.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub migrated_from: Vec<String>,
    /// The machine-wide keep-alive lease: at most one process runs
    /// [`crate::keepalive`] at a time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive: Option<crate::keepalive::KeepAliveLease>,
    /// Top-level fields this crate does not model, preserved verbatim so a
    /// write never drops another writer's data.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

fn default_version() -> u32 {
    1
}

/// Every key under which an account may already be known.
///
/// One key is not enough. The same login rotates its refresh token, so copies
/// left in different tools' stores carry different tokens, while the Anthropic
/// account UUID and the store id stay put. Matching on any key keeps a merge
/// from admitting the same login twice — which would put duplicate ids in the
/// store and make every id-keyed update ambiguous.
pub fn account_identities(account: &Account) -> Vec<String> {
    let mut keys = vec![format!("id:{}", account.id)];
    match &account.credential {
        Credential::ApiKey { key } => keys.push(format!("api_key:{}", key.expose())),
        Credential::Oauth(tokens) => {
            let refresh = tokens.refresh.expose();
            if !refresh.is_empty() {
                keys.push(format!("refresh:{refresh}"));
            }
            // Identity is the (account, organization) pair, not the account
            // alone. One person can hold a grant in several organizations, and
            // those are separate routable credentials sharing an account uuid
            // and an email. Keying on either alone would collapse them and
            // silently drop a working login.
            //
            // A row that never captured its organization emits the unqualified
            // form, which therefore matches nothing qualified. That direction
            // is deliberate: an unmerged duplicate is a tidy-up, a wrongly
            // merged pair is data loss.
            let org_scope = tokens
                .organization
                .as_ref()
                .map(|o| format!("@{}", o.uuid))
                .unwrap_or_default();
            if let Some(uuid) = tokens.account.as_ref().map(|a| a.uuid.as_str()) {
                keys.push(format!("uuid:{uuid}{org_scope}"));
            }
            if let Some(email) = tokens
                .account
                .as_ref()
                .and_then(|a| a.email_address.as_deref())
                .filter(|e| !e.trim().is_empty())
            {
                keys.push(format!("email:{}{org_scope}", email.trim().to_lowercase()));
            }
        }
    }
    keys
}

/// Home directory without pulling in a platform-dirs dependency.
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("USERPROFILE")
                .filter(|h| !h.is_empty())
                .map(PathBuf::from)
        })
}

fn non_empty_env_path(key: &str) -> Option<PathBuf> {
    std::env::var_os(key)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// The shared store directory (`~/.anthropic-accounts`, or the env override).
pub fn store_dir() -> PathBuf {
    if let Some(dir) = non_empty_env_path(STORE_DIR_ENV) {
        return dir;
    }
    home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(STORE_DIR_NAME)
}

/// The canonical store file path.
pub fn default_store_path() -> PathBuf {
    if let Some(file) = non_empty_env_path(STORE_FILE_ENV) {
        return file;
    }
    store_dir().join(STORE_FILE_NAME)
}

/// Legacy per-application store locations, newest convention first. These are
/// read-only fallbacks used to adopt an existing login into the shared store.
pub fn legacy_store_paths() -> Vec<PathBuf> {
    legacy_store_paths_from_lookup(|key| std::env::var(key).ok())
}

/// [`legacy_store_paths`] over an arbitrary variable lookup (`HOME`,
/// `USERPROFILE`, `GROK_HOME`, [`STORE_DIR_ENV`]); a JS host passes its own
/// environment snapshot.
pub fn legacy_store_paths_from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Vec<PathBuf> {
    let get = |key: &str| lookup(key).filter(|v| !v.is_empty()).map(PathBuf::from);
    let home = get("HOME").or_else(|| get("USERPROFILE"));
    let store_dir = get(STORE_DIR_ENV).unwrap_or_else(|| {
        home.clone()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(STORE_DIR_NAME)
    });
    // Predecessors wrote this name into the shared directory itself, so it sits
    // beside the canonical file and is the most likely place to find accounts
    // that were never migrated.
    let mut paths = vec![store_dir.join("anthropic-accounts.json")];
    if let Some(grok_home) = get("GROK_HOME") {
        paths.push(grok_home.join("anthropic-accounts.json"));
    }
    if let Some(home) = home {
        paths.push(home.join(".config/jfc/anthropic-accounts.json"));
        paths.push(home.join(".grok/anthropic-accounts.json"));
        paths.push(home.join(".config/opencode/anthropic-accounts.json"));
    }
    paths
}

/// Where a loaded store came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadSource {
    /// Read from the canonical shared path.
    Canonical(PathBuf),
    /// Adopted from a legacy per-application path; the caller should persist it
    /// to the canonical path to complete the migration.
    Legacy(PathBuf),
    /// No store existed anywhere; an empty document was returned.
    Empty,
}

/// A loaded store plus its provenance.
#[derive(Debug, Clone)]
pub struct Loaded {
    /// The store document.
    pub store: AccountStore,
    /// Where it came from.
    pub source: LoadSource,
}

impl AccountStore {
    /// Read a store from an explicit path.
    ///
    /// Refuses to follow a symlink: a store path that became a symlink is a
    /// tampering signal, not something to silently read through.
    ///
    /// A rotation a refresh could not save (see [`crate::unsaved`]) is
    /// applied: a row still holding the spent refresh token holds the
    /// rotation in the returned store.
    pub fn load(path: &Path) -> Result<Self> {
        let mut store = Self::load_file(path)?;
        crate::unsaved::apply(path, &mut store);
        Ok(store)
    }

    /// The store file as written, without unsaved rotations applied.
    pub(crate) fn load_file(path: &Path) -> Result<Self> {
        let raw = crate::file_security::read_bounded_regular(
            path,
            STORE_MAX_BYTES,
            false,
            "credential store",
        )?;
        crate::file_security::parse_json_redacted(&raw, "credential store")
    }

    /// Read the canonical store, folding in any legacy per-application store
    /// that has not been adopted yet.
    ///
    /// Adoption used to stop at the first file that existed, so once the
    /// canonical store held a single account every other login on the machine
    /// became invisible — leaving a router with nothing to fall back to.
    pub fn load_or_migrate() -> Result<Loaded> {
        Self::load_or_migrate_from(&default_store_path(), &legacy_store_paths())
    }

    /// [`Self::load_or_migrate`] with the paths injected, so tests never touch
    /// the real store.
    pub fn load_or_migrate_from(canonical: &Path, legacy: &[PathBuf]) -> Result<Loaded> {
        let canonical_exists = canonical.exists();
        let base = if canonical_exists {
            Some(Self::load(canonical)?)
        } else {
            None
        };

        let mut store = base.unwrap_or_default();
        let already: HashSet<String> = store.migrated_from.iter().cloned().collect();
        let mut seen: HashSet<String> =
            store.accounts.iter().flat_map(account_identities).collect();
        let mut adopted: Vec<PathBuf> = Vec::new();
        let mut scanned: Vec<PathBuf> = Vec::new();

        for candidate in legacy {
            if candidate == canonical || already.contains(&candidate.to_string_lossy().to_string())
            {
                continue;
            }
            if !candidate.exists() {
                continue;
            }
            // A legacy file is a best-effort source: an unreadable one must not
            // block a valid canonical credential or stop the remaining
            // candidates from being checked.
            let Ok(accounts) = Self::read_legacy(candidate) else {
                continue;
            };
            // Recorded even when every row was skipped (duplicates, or rows
            // dead by definition), so the file is not re-scanned on every
            // load and a later identity drift cannot re-import its rows.
            scanned.push(candidate.clone());
            if accounts.is_empty() {
                continue;
            }
            adopted.push(candidate.clone());
            for account in accounts {
                let identities = account_identities(&account);
                if identities.iter().any(|key| seen.contains(key)) {
                    continue;
                }
                seen.extend(identities);
                store.accounts.push(account);
            }
        }

        if !canonical_exists && store.accounts.is_empty() {
            return Ok(Loaded {
                store: Self::default(),
                source: LoadSource::Empty,
            });
        }

        store.migrated_from.extend(
            scanned
                .iter()
                .map(|path| path.to_string_lossy().to_string()),
        );

        let source = match adopted.first() {
            Some(first) if !canonical_exists => LoadSource::Legacy(first.clone()),
            _ => LoadSource::Canonical(canonical.to_path_buf()),
        };
        Ok(Loaded { store, source })
    }

    /// Read one legacy store, accepting either the shared schema or the flat
    /// per-application schema that predates it.
    fn read_legacy(path: &Path) -> Result<Vec<Account>> {
        let raw = crate::file_security::read_bounded_regular(
            path,
            STORE_MAX_BYTES,
            false,
            "credential store",
        )?;
        if let Ok(shared) = serde_json::from_slice::<Self>(&raw) {
            if !shared.accounts.is_empty() {
                return Ok(shared.accounts);
            }
        }
        let legacy: crate::legacy::LegacyStore =
            crate::file_security::parse_json_redacted(&raw, "legacy credential store")?;
        Ok(legacy.into_accounts())
    }

    /// Persist to `path` atomically.
    ///
    /// This is a **snapshot overwrite**: whatever another process wrote since
    /// `self` was loaded is lost, including token rotations. Prefer
    /// [`Self::mutate`] (re-read under the lock) for every update, and
    /// [`Self::merge_adopted`] to persist rows found by
    /// [`Self::load_or_migrate`].
    ///
    /// Refuses to write an empty account list: an empty store is nearly always
    /// a bug upstream, and committing it would wipe the user's credentials.
    pub fn save(&self, path: &Path) -> Result<()> {
        let _lock = StoreLock::acquire(path, STORE_LOCK_WAIT)?;
        self.save_unlocked(path, false)
    }

    /// Persist to `path` atomically while explicitly allowing an empty account
    /// list. Use only for an intentional user-approved final-account removal or
    /// post-revocation cleanup; ordinary reconciliation should call [`Self::save`].
    pub fn save_allow_empty(&self, path: &Path) -> Result<()> {
        let _lock = StoreLock::acquire(path, STORE_LOCK_WAIT)?;
        self.save_unlocked(path, true)
    }

    /// Reload and mutate a store while holding its inter-process lock, then
    /// atomically persist the result. This prevents read-modify-write updates
    /// from dropping another process's token rotation or account changes.
    pub fn mutate<R>(path: &Path, update: impl FnOnce(&mut Self) -> Result<R>) -> Result<R> {
        Self::mutate_with_empty_policy(path, false, update)
    }

    /// Locked mutation that explicitly permits removing the final account.
    /// Use only for an intentional disconnect/revocation flow.
    pub fn mutate_allow_empty<R>(
        path: &Path,
        update: impl FnOnce(&mut Self) -> Result<R>,
    ) -> Result<R> {
        Self::mutate_with_empty_policy(path, true, update)
    }

    fn mutate_with_empty_policy<R>(
        path: &Path,
        allow_empty: bool,
        update: impl FnOnce(&mut Self) -> Result<R>,
    ) -> Result<R> {
        let _lock = StoreLock::acquire(path, STORE_LOCK_WAIT)?;
        let (mut store, unsaved) = Self::load_if_present(path)?;
        // Stale errors (bound to a token the row no longer holds, or an
        // unbound `invalid_grant` with no dead-token record) clear themselves
        // on the next locked write, whoever makes it.
        for account in &mut store.accounts {
            account.clear_stale_error();
        }
        let output = update(&mut store)?;
        store.save_unlocked(path, allow_empty)?;
        // The unsaved rotations applied on load are in the file now.
        crate::unsaved::settle(path, &unsaved, &store);
        Ok(output)
    }

    /// The store at `path` (empty when there is none) with the unsaved
    /// rotations applied, and the records seen.
    fn load_if_present(path: &Path) -> Result<(Self, Vec<crate::unsaved::Seen>)> {
        match std::fs::symlink_metadata(path) {
            Ok(_) => {
                let mut store = Self::load_file(path)?;
                let unsaved = crate::unsaved::apply(path, &mut store);
                Ok((store, unsaved))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok((Self::default(), Vec::new()))
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Read the store under its inter-process lock without writing it back.
    /// Use it when a decision must see the latest committed state (for
    /// example, which refresh token the store holds right now) but nothing
    /// needs to change.
    pub fn read_locked<R>(path: &Path, read: impl FnOnce(&Self) -> Result<R>) -> Result<R> {
        let _lock = StoreLock::acquire(path, STORE_LOCK_WAIT)?;
        let (store, _) = Self::load_if_present(path)?;
        read(&store)
    }

    /// Persist accounts adopted from legacy stores (see
    /// [`Self::load_or_migrate_from`]) without overwriting anything. Under the
    /// store lock, the file is re-read and each of `rows` is appended only
    /// when none of its [`account_identities`] is already present; existing
    /// rows, their fields (known and unknown) and the pin are untouched.
    /// `migrated_from` paths not yet recorded are added. Returns how many rows
    /// were appended.
    ///
    /// This is the locked replacement for persisting a
    /// [`Self::load_or_migrate`] result with [`Self::save`], which overwrites
    /// every rotation made since the load.
    pub fn merge_adopted(path: &Path, rows: &[Account], migrated_from: &[String]) -> Result<usize> {
        Self::mutate(path, |store| {
            let mut seen: HashSet<String> =
                store.accounts.iter().flat_map(account_identities).collect();
            let mut added = 0;
            for account in rows {
                let identities = account_identities(account);
                if identities.iter().any(|key| seen.contains(key)) {
                    continue;
                }
                seen.extend(identities);
                store.accounts.push(account.clone());
                added += 1;
            }
            for path in migrated_from {
                if !store.migrated_from.contains(path) {
                    store.migrated_from.push(path.clone());
                }
            }
            Ok(added)
        })
    }

    /// Fold `legacy` stores into the canonical store at `canonical` and
    /// persist what they add: [`Self::load_or_migrate_from`] followed by a
    /// locked, append-only [`Self::merge_adopted`]. Rows dead by definition
    /// (disabled with `invalid_grant`, no refresh token) are skipped by the
    /// legacy reader; a scanned file is recorded in `migrated_from` so it is
    /// never re-read and a removed account is never resurrected. Nothing is
    /// written when there is nothing new, and an empty canonical store is
    /// never created. Returns how many rows were added.
    pub fn adopt_legacy(canonical: &Path, legacy: &[PathBuf]) -> Result<usize> {
        if legacy.is_empty() {
            return Ok(0);
        }
        let before = if canonical.exists() {
            Some(Self::load(canonical)?)
        } else {
            None
        };
        let loaded = Self::load_or_migrate_from(canonical, legacy)?;
        let known: HashSet<String> = before
            .iter()
            .flat_map(|store| store.accounts.iter().flat_map(account_identities))
            .collect();
        let rows: Vec<Account> = loaded
            .store
            .accounts
            .iter()
            .filter(|a| !account_identities(a).iter().any(|k| known.contains(k)))
            .cloned()
            .collect();
        let recorded: HashSet<&String> = before
            .iter()
            .flat_map(|store| store.migrated_from.iter())
            .collect();
        let scanned: Vec<String> = loaded
            .store
            .migrated_from
            .iter()
            .filter(|p| !recorded.contains(p))
            .cloned()
            .collect();
        let has_rows = before.as_ref().is_some_and(|b| !b.accounts.is_empty());
        if rows.is_empty() && (scanned.is_empty() || !has_rows) {
            return Ok(0);
        }
        Self::merge_adopted(canonical, &rows, &scanned)
    }

    /// Install a freshly logged-in credential. When a row already holds the
    /// same login (any shared identity: id, account uuid + organization,
    /// email + organization, token), that row is updated **in place**: its
    /// credential is replaced, it is re-enabled, and records bound to the old
    /// token (error, dead-token verdict, refresh claim, cooldown) are cleared,
    /// while its id, label, quota, pin and unknown fields are kept. Otherwise
    /// `account` is appended. Returns the id of the row that now holds the
    /// login.
    pub fn merge_login(&mut self, account: Account) -> Result<String> {
        let incoming: HashSet<String> = account_identities(&account).into_iter().collect();
        let Some(existing) = self.accounts.iter_mut().find(|candidate| {
            account_identities(candidate)
                .iter()
                .any(|key| incoming.contains(key))
        }) else {
            let id = account.id.clone();
            self.accounts.push(account);
            return Ok(id);
        };
        match (&mut existing.credential, account.credential) {
            (Credential::Oauth(_), Credential::Oauth(tokens)) => {
                existing.replace_oauth_tokens(tokens)?;
            }
            (_, credential) => {
                existing.credential = credential;
                existing.credential_extra = serde_json::Map::new();
            }
        }
        if account.label.is_some() {
            existing.label = account.label;
        }
        if account.email.is_some() {
            existing.email = account.email;
        }
        existing.enabled = true;
        existing.rate_limited_until = None;
        existing.clear_error();
        existing.dead_refresh_fingerprint = None;
        existing.refresh_lease = None;
        Ok(existing.id.clone())
    }

    /// Add a static API key (in-memory form; persist with
    /// [`AccountStore::mutate`]). A row that already holds this exact key is
    /// kept as it is (`added == false`). A new row is keyed by `label` (else
    /// `api-key-<last 4>`), suffixed `-2`, `-3`, … when that id is taken, so
    /// an API key never lands on another row. Returns `(id, added)`.
    pub fn add_api_key(&mut self, label: Option<&str>, key: ApiKey) -> (String, bool) {
        let identity = format!("api_key:{}", key.expose());
        if let Some(existing) = self
            .accounts
            .iter()
            .find(|a| account_identities(a).contains(&identity))
        {
            return (existing.id.clone(), false);
        }
        let label = label.map(str::trim).filter(|l| !l.is_empty());
        let base = label
            .map(str::to_owned)
            .unwrap_or_else(|| format!("api-key-{}", crate::token::key_suffix(key.expose())));
        let mut id = base.clone();
        let mut n = 2;
        while self.accounts.iter().any(|a| a.id == id) {
            id = format!("{base}-{n}");
            n += 1;
        }
        let mut account = Account::new(id.clone(), Credential::ApiKey { key });
        account.label = label.map(str::to_owned);
        self.accounts.push(account);
        if self.current.is_none() {
            self.current = Some(id.clone());
        }
        (id, true)
    }

    /// Compare-and-swap an OAuth refresh result into the latest store. Returns
    /// `false` when another process already rotated the refresh token; in that
    /// case the newer stored session is left untouched.
    ///
    /// On success the row changes the way [`AccountStore::commit_refresh`]
    /// changes it, without pinning `current`: the credential is replaced and
    /// the last error, dead-token verdict and refresh claim are cleared.
    /// Prefer [`crate::OAuthClient::refresh_shared`], which also claims the
    /// token before spending it.
    pub fn replace_oauth_after_refresh(
        path: &Path,
        account_id: &str,
        expected_refresh: &RefreshToken,
        refreshed: OAuthTokens,
    ) -> Result<bool> {
        Self::mutate(path, |store| {
            let account = store.get_mut(account_id)?;
            let Credential::Oauth(current) = &account.credential else {
                return Err(Error::Protocol(format!(
                    "account {account_id} is not an OAuth account"
                )));
            };
            if &current.refresh != expected_refresh {
                return Ok(false);
            }
            account.replace_oauth_tokens(refreshed)?;
            account.clear_error();
            account.dead_refresh_fingerprint = None;
            account.refresh_lease = None;
            account.last_refreshed_at = Some(Utc::now());
            Ok(true)
        })
    }

    fn save_unlocked(&self, path: &Path, allow_empty: bool) -> Result<()> {
        if self.accounts.is_empty() && !allow_empty {
            return Err(Error::WouldDeleteAllAccounts);
        }
        if let Ok(meta) = std::fs::symlink_metadata(path)
            && meta.file_type().is_symlink()
        {
            return Err(Error::StoreIsSymlink);
        }
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)?;
        restrict_dir_permissions(parent);
        sweep_orphan_temp_files(parent, path);

        let body = serde_json::to_vec_pretty(self)?;
        let tmp = parent.join(format!(
            "{}.tmp-{}-{}",
            path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(STORE_FILE_NAME),
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default(),
        ));

        // Write-then-rename: a crash mid-write leaves the previous store intact
        // rather than a truncated file.
        let write_result = (|| -> Result<()> {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)?;
            restrict_file_permissions(&file);
            file.write_all(&body)?;
            file.sync_all()?;
            Ok(())
        })();
        if let Err(error) = write_result {
            let _ = std::fs::remove_file(&tmp);
            return Err(error);
        }
        if let Ok(metadata) = std::fs::symlink_metadata(path)
            && metadata.file_type().is_symlink()
        {
            let _ = std::fs::remove_file(&tmp);
            return Err(Error::StoreIsSymlink);
        }
        match std::fs::rename(&tmp, path) {
            Ok(()) => {
                if let Ok(directory) = std::fs::File::open(parent) {
                    let _ = directory.sync_all();
                }
                Ok(())
            }
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                Err(e.into())
            }
        }
    }

    /// Persist to the canonical shared path.
    pub fn save_default(&self) -> Result<PathBuf> {
        let path = default_store_path();
        self.save(&path)?;
        Ok(path)
    }

    /// All accounts able to serve a request at `now`, in routing order with the
    /// pinned `current` account first.
    pub fn available(&self, now: DateTime<Utc>) -> Vec<&Account> {
        let mut out: Vec<&Account> = self
            .accounts
            .iter()
            .filter(|a| a.is_available(now))
            .collect();
        if let Some(current) = self.current.as_deref()
            && let Some(pos) = out.iter().position(|a| a.id == current)
        {
            out.swap(0, pos);
        }
        out
    }

    /// The account a request should use at `now`.
    pub fn pick(&self, now: DateTime<Utc>) -> Result<&Account> {
        self.available(now).into_iter().next().ok_or_else(|| {
            Error::NoUsableAccount(format!(
                "{} account(s) known, none available (disabled or rate-limited)",
                self.accounts.len()
            ))
        })
    }

    /// Mutable access to an account by id.
    pub fn get_mut(&mut self, id: &str) -> Result<&mut Account> {
        self.accounts
            .iter_mut()
            .find(|a| a.id == id)
            .ok_or_else(|| Error::UnknownAccount(id.to_owned()))
    }

    /// Look up an account by id.
    pub fn get(&self, id: &str) -> Option<&Account> {
        self.accounts.iter().find(|a| a.id == id)
    }

    /// Insert an account, replacing any existing entry with the same id.
    pub fn upsert(&mut self, account: Account) {
        match self.accounts.iter_mut().find(|a| a.id == account.id) {
            Some(slot) => *slot = account,
            None => self.accounts.push(account),
        }
    }

    /// Remove an account by id, returning whether it existed.
    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.accounts.len();
        self.accounts.retain(|a| a.id != id);
        if self.current.as_deref() == Some(id) {
            self.current = None;
        }
        self.accounts.len() != before
    }

    /// Pin the preferred account.
    pub fn set_current(&mut self, id: &str) -> Result<()> {
        if self.get(id).is_none() {
            return Err(Error::UnknownAccount(id.to_owned()));
        }
        self.current = Some(id.to_owned());
        Ok(())
    }

    /// Rotate away from `id`: pin the next available account, if any.
    pub fn rotate_from(&mut self, id: &str, now: DateTime<Utc>) -> Option<String> {
        let next = self
            .accounts
            .iter()
            .find(|a| a.id != id && a.is_available(now))
            .map(|a| a.id.clone())?;
        self.current = Some(next.clone());
        Some(next)
    }
}

struct StoreLock {
    advisory_file: std::fs::File,
    lease_path: PathBuf,
    owner_id: String,
    heartbeat_stop: Option<std::sync::mpsc::Sender<()>>,
    heartbeat: Option<std::thread::JoinHandle<()>>,
}

impl StoreLock {
    fn acquire(target: &Path, wait: Duration) -> Result<Self> {
        const LEASE_MS: u128 = 30_000;
        const STALE_HEARTBEAT_MS: u128 = 10_000;

        let parent = target.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)?;
        restrict_dir_permissions(parent);
        let name = target
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(STORE_FILE_NAME);
        let lease_path = parent.join(format!("{name}.lock"));
        let advisory_path = parent.join(format!("{name}.flock"));
        for path in [&lease_path, &advisory_path] {
            if std::fs::symlink_metadata(path)
                .is_ok_and(|metadata| metadata.file_type().is_symlink())
            {
                return Err(Error::StoreIsSymlink);
            }
        }
        let advisory_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(advisory_path)?;
        restrict_file_permissions(&advisory_file);
        let deadline = Instant::now() + wait;
        loop {
            match fs2::FileExt::try_lock_exclusive(&advisory_file) {
                Ok(()) => break,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(Error::Protocol(
                            "timed out waiting for credential store lock".into(),
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(error) => return Err(error.into()),
            }
        }

        let owner_id = uuid::Uuid::new_v4().to_string();
        loop {
            let now = unix_time_millis();
            let body = format!(
                "{{\"ownerId\":\"{owner_id}\",\"pid\":{},\"expiresAt\":{}}}\n",
                std::process::id(),
                now.saturating_add(LEASE_MS)
            );
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lease_path)
            {
                Ok(mut lease) => {
                    restrict_file_permissions(&lease);
                    lease.write_all(body.as_bytes())?;
                    lease.sync_all()?;
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if lease_is_stale(&lease_path, now, STALE_HEARTBEAT_MS) {
                        let stale = parent.join(format!("{name}.lock.stale-{owner_id}"));
                        match std::fs::rename(&lease_path, &stale) {
                            Ok(()) => {
                                let _ = std::fs::remove_file(stale);
                                continue;
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                            Err(error) => return Err(error.into()),
                        }
                    }
                    if Instant::now() >= deadline {
                        return Err(Error::Protocol(
                            "timed out waiting for credential store lease".into(),
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(error) => return Err(error.into()),
            }
        }
        let (heartbeat_stop, heartbeat) =
            start_lease_heartbeat(lease_path.clone(), owner_id.clone());
        Ok(Self {
            advisory_file,
            lease_path,
            owner_id,
            heartbeat_stop: Some(heartbeat_stop),
            heartbeat: Some(heartbeat),
        })
    }
}

fn unix_time_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}

fn lease_owner(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|body| serde_json::from_str::<serde_json::Value>(&body).ok())
        .and_then(|value| value.get("ownerId")?.as_str().map(str::to_owned))
}

fn start_lease_heartbeat(
    path: PathBuf,
    owner_id: String,
) -> (std::sync::mpsc::Sender<()>, std::thread::JoinHandle<()>) {
    let (stop, stopped) = std::sync::mpsc::channel();
    let heartbeat = std::thread::spawn(move || {
        loop {
            match stopped.recv_timeout(Duration::from_secs(3)) {
                Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if lease_owner(&path).as_deref() != Some(owner_id.as_str()) {
                        break;
                    }
                    if let Ok(file) = std::fs::OpenOptions::new().read(true).open(&path) {
                        let _ = file.set_times(
                            std::fs::FileTimes::new().set_modified(std::time::SystemTime::now()),
                        );
                    }
                }
            }
        }
    });
    (stop, heartbeat)
}

/// Whether the lease at `path` is abandoned: its heartbeat (the file's
/// mtime) is older than `lease_ms` and, for a cross-language lease, its
/// expiry has passed too.
///
/// A lease this crate wrote (it records the holder's `pid`) is kept alive by
/// [`start_lease_heartbeat`] alone; its `expiresAt` is written once and never
/// renewed. A holder that dies inside the lock (killed, or its process
/// exiting while another thread writes the store) leaves the lease behind
/// with that expiry up to 30 s away. Honouring it kept every store reader
/// and writer on the machine waiting long after the heartbeat stopped (the
/// first of them holding the flock while it waits, so the others time out
/// on the lock), so such a lease lapses with its heartbeat.
fn lease_is_stale(path: &Path, now: u128, lease_ms: u128) -> bool {
    let lease = std::fs::read_to_string(path)
        .ok()
        .and_then(|body| serde_json::from_str::<serde_json::Value>(&body).ok());
    let expires = lease
        .as_ref()
        .and_then(|value| value.get("expiresAt")?.as_u64())
        .map(u128::from);
    let heartbeated = lease
        .as_ref()
        .is_some_and(|value| value.get("pid").is_some());
    let old_heartbeat = std::fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| modified.elapsed().ok())
        .is_some_and(|age| age.as_millis() >= lease_ms);
    match expires {
        Some(expires) if !heartbeated => expires <= now && old_heartbeat,
        Some(_) | None => old_heartbeat,
    }
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        if let Some(stop) = self.heartbeat_stop.take() {
            let _ = stop.send(());
        }
        if let Some(heartbeat) = self.heartbeat.take() {
            let _ = heartbeat.join();
        }
        if lease_owner(&self.lease_path).as_deref() == Some(self.owner_id.as_str()) {
            let _ = std::fs::remove_file(&self.lease_path);
        }
        let _ = fs2::FileExt::unlock(&self.advisory_file);
    }
}

/// Best-effort `0700` on the store directory (unix only).
fn restrict_dir_permissions(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(dir) {
            let mut perms = meta.permissions();
            if perms.mode() & 0o077 != 0 {
                perms.set_mode(0o700);
                let _ = std::fs::set_permissions(dir, perms);
            }
        }
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Best-effort `0600` on the store file (unix only).
fn restrict_file_permissions(file: &std::fs::File) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = file;
}

/// Remove stale `<store>.tmp-*` files left behind by a crashed writer. Only
/// files older than [`ORPHAN_TMP_MAX_AGE_SECS`] are removed, so a concurrent
/// in-flight write is never disturbed.
fn sweep_orphan_temp_files(dir: &Path, store_path: &Path) {
    let Some(stem) = store_path.file_name().and_then(|n| n.to_str()) else {
        return;
    };
    let prefix = format!("{stem}.tmp-");
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with(&prefix) {
            continue;
        }
        let stale = entry
            .metadata()
            .and_then(|m| m.modified())
            .map(|modified| {
                modified
                    .elapsed()
                    .map(|age| age.as_secs() > ORPHAN_TMP_MAX_AGE_SECS)
                    .unwrap_or(false)
            })
            .unwrap_or(false);
        if stale {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::account::Account;
    use crate::token::{
        AccessToken,
        ApiKey,
        Credential,
        OAuthTokens,
        RefreshToken,
        TokenAccount,
        TokenOrganization,
    };

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0).unwrap()
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "anthropic-store-test-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn account(id: &str) -> Account {
        Account::new(
            id,
            Credential::ApiKey {
                key: ApiKey::new("sk-ant-api01-aaaaaaaaaaaaaaaaaaaaaa"),
            },
        )
    }

    fn store_with(ids: &[&str]) -> AccountStore {
        AccountStore {
            version: 1,
            accounts: ids.iter().map(|id| account(id)).collect(),
            ..AccountStore::default()
        }
    }

    fn oauth_tokens(refresh: &str, refresh_expires_at: i64) -> OAuthTokens {
        OAuthTokens {
            access: AccessToken::new("sk-ant-oat01-abcdefghijklmnopqrstuvwxyz012345"),
            refresh: RefreshToken::new(refresh),
            expires_at: at(1_700_000_000),
            refresh_expires_at: Some(at(refresh_expires_at)),
            scopes: vec!["user:inference".into()],
            account: None,
            organization: None,
        }
    }

    #[test]
    fn save_then_load_roundtrips_normal() {
        let dir = tmp_dir("roundtrip");
        let path = dir.join("accounts.json");
        let store = store_with(&["a", "b"]);
        store.save(&path).unwrap();

        let back = AccountStore::load(&path).unwrap();
        assert_eq!(back.accounts.len(), 2);
        assert_eq!(back.accounts[0].id, "a");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn save_refuses_to_wipe_all_accounts_robust() {
        let dir = tmp_dir("wipe");
        let path = dir.join("accounts.json");
        store_with(&["a"]).save(&path).unwrap();

        let empty = AccountStore::default();
        let err = empty.save(&path).unwrap_err();
        assert!(matches!(err, Error::WouldDeleteAllAccounts));
        // The prior store survived.
        assert_eq!(AccountStore::load(&path).unwrap().accounts.len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn explicit_final_account_removal_can_persist_an_empty_store() {
        let dir = tmp_dir("intentional-empty");
        let path = dir.join("accounts.json");
        store_with(&["a"]).save(&path).unwrap();

        AccountStore::default().save_allow_empty(&path).unwrap();
        let reloaded = AccountStore::load(&path).unwrap();
        assert!(reloaded.accounts.is_empty());
        assert!(reloaded.current.is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn save_is_atomic_and_leaves_no_temp_files_normal() {
        let dir = tmp_dir("atomic");
        let path = dir.join("accounts.json");
        store_with(&["a"]).save(&path).unwrap();

        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "temp file leaked: {leftovers:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn sweep_removes_only_stale_orphans_robust() {
        let dir = tmp_dir("sweep");
        let path = dir.join("accounts.json");
        let fresh = dir.join("accounts.json.tmp-111-222");
        let unrelated = dir.join("unrelated.txt");
        std::fs::write(&fresh, b"{}").unwrap();
        std::fs::write(&unrelated, b"x").unwrap();

        sweep_orphan_temp_files(&dir, &path);

        // A just-created temp file belongs to a possibly in-flight writer.
        assert!(fresh.exists(), "fresh temp file must not be swept");
        assert!(unrelated.exists(), "unrelated file must not be swept");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_refuses_symlinked_store_robust() {
        #[cfg(unix)]
        {
            let dir = tmp_dir("symlink");
            let real = dir.join("real.json");
            store_with(&["a"]).save(&real).unwrap();
            let link = dir.join("accounts.json");
            std::os::unix::fs::symlink(&real, &link).unwrap();

            let err = AccountStore::load(&link).unwrap_err();
            assert!(matches!(err, Error::StoreIsSymlink));
            std::fs::remove_dir_all(&dir).ok();
        }
    }

    #[test]
    fn load_or_migrate_prefers_canonical_then_legacy_then_empty_normal() {
        let dir = tmp_dir("migrate");
        let canonical = dir.join("canonical.json");
        let legacy = dir.join("legacy.json");

        // Nothing exists yet → empty.
        let loaded =
            AccountStore::load_or_migrate_from(&canonical, std::slice::from_ref(&legacy)).unwrap();
        assert_eq!(loaded.source, LoadSource::Empty);
        assert!(loaded.store.accounts.is_empty());

        // Only legacy exists → adopted, flagged for migration.
        store_with(&["from-legacy"]).save(&legacy).unwrap();
        let loaded =
            AccountStore::load_or_migrate_from(&canonical, std::slice::from_ref(&legacy)).unwrap();
        assert_eq!(loaded.source, LoadSource::Legacy(legacy.clone()));
        assert_eq!(loaded.store.accounts[0].id, "from-legacy");

        // Canonical wins once present.
        store_with(&["from-canonical"]).save(&canonical).unwrap();
        let loaded = AccountStore::load_or_migrate_from(&canonical, &[legacy]).unwrap();
        assert_eq!(loaded.source, LoadSource::Canonical(canonical));
        assert_eq!(loaded.store.accounts[0].id, "from-canonical");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn pick_skips_disabled_and_rate_limited_robust() {
        let mut store = store_with(&["a", "b", "c"]);
        store.get_mut("a").unwrap().disable("revoked");
        store.get_mut("b").unwrap().mark_rate_limited(at(100));

        assert_eq!(store.pick(at(50)).unwrap().id, "c");
        // Once b's cooldown lapses it is eligible again, ahead of c in order.
        assert_eq!(store.pick(at(100)).unwrap().id, "b");
    }

    #[test]
    fn pick_errors_when_nothing_is_available_robust() {
        let mut store = store_with(&["a"]);
        store.get_mut("a").unwrap().disable("revoked");
        let err = store.pick(at(0)).unwrap_err();
        assert!(matches!(err, Error::NoUsableAccount(_)));
        assert!(
            !err.is_permanent(),
            "exhaustion is retryable, not permanent"
        );
    }

    #[test]
    fn current_account_is_preferred_when_available_normal() {
        let mut store = store_with(&["a", "b"]);
        store.set_current("b").unwrap();
        assert_eq!(store.pick(at(0)).unwrap().id, "b");

        // Pinning an unknown id is rejected rather than silently ignored.
        assert!(matches!(
            store.set_current("ghost"),
            Err(Error::UnknownAccount(_))
        ));
    }

    #[test]
    fn refresh_compare_and_swap_never_overwrites_a_newer_rotation() {
        let dir = tmp_dir("refresh-cas");
        let path = dir.join("accounts.json");
        let old_refresh = "sk-ant-ort01-oldoldoldoldoldoldoldold";
        let new_refresh = "sk-ant-ort01-newnewnewnewnewnewnewnew";
        let stale_refresh = "sk-ant-ort01-stalestalestalestalestale";
        let mut store = AccountStore::default();
        store.upsert(Account::new(
            "oauth",
            Credential::Oauth(oauth_tokens(old_refresh, 1_800_000_000)),
        ));
        store.save(&path).unwrap();

        assert!(
            AccountStore::replace_oauth_after_refresh(
                &path,
                "oauth",
                &RefreshToken::new(old_refresh),
                oauth_tokens(new_refresh, 1_900_000_000),
            )
            .unwrap()
        );
        assert!(
            !AccountStore::replace_oauth_after_refresh(
                &path,
                "oauth",
                &RefreshToken::new(old_refresh),
                oauth_tokens(stale_refresh, 2_000_000_000),
            )
            .unwrap()
        );
        let reloaded = AccountStore::load(&path).unwrap();
        let Credential::Oauth(tokens) = &reloaded.get("oauth").unwrap().credential else {
            unreachable!("OAuth account changed type")
        };
        assert_eq!(tokens.refresh.expose(), new_refresh);
        assert_eq!(tokens.refresh_expires_at, Some(at(1_900_000_000)));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn refresh_compare_and_swap_updates_top_level_email_from_token_metadata() {
        let dir = tmp_dir("refresh-email-sync");
        let path = dir.join("accounts.json");
        let mut store = AccountStore::default();
        store.upsert(Account::new(
            "oauth",
            Credential::Oauth(OAuthTokens {
                access: AccessToken::new("sk-ant-oat01-oldoldoldoldoldoldoldold"),
                refresh: RefreshToken::new("sk-ant-ort01-oldoldoldoldoldoldoldold"),
                expires_at: at(1_700_000_000),
                refresh_expires_at: Some(at(1_800_000_000)),
                scopes: vec!["user:profile".into(), "user:inference".into()],
                account: Some(crate::token::TokenAccount {
                    uuid: "acct".into(),
                    email_address: Some("old@example.com".into()),
                }),
                organization: None,
            }),
        ));
        store.save(&path).unwrap();

        assert!(
            AccountStore::replace_oauth_after_refresh(
                &path,
                "oauth",
                &RefreshToken::new("sk-ant-ort01-oldoldoldoldoldoldoldold"),
                OAuthTokens {
                    access: AccessToken::new("sk-ant-oat01-newnewnewnewnewnewnewnew"),
                    refresh: RefreshToken::new("sk-ant-ort01-newnewnewnewnewnewnewnew"),
                    expires_at: at(1_700_000_100),
                    refresh_expires_at: Some(at(1_800_000_100)),
                    scopes: vec!["user:profile".into(), "user:inference".into()],
                    account: Some(crate::token::TokenAccount {
                        uuid: "acct".into(),
                        email_address: Some("new@example.com".into()),
                    }),
                    organization: None,
                },
            )
            .unwrap()
        );

        let reloaded = AccountStore::load(&path).unwrap();
        assert_eq!(
            reloaded.get("oauth").unwrap().email.as_deref(),
            Some("new@example.com")
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn concurrent_locked_mutations_preserve_unrelated_accounts() {
        let dir = tmp_dir("concurrent-mutate");
        let path = dir.join("accounts.json");
        store_with(&["base"]).save(&path).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|index| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    AccountStore::mutate(&path, |store| {
                        store.upsert(account(&format!("worker-{index}")));
                        Ok(())
                    })
                    .unwrap();
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        let reloaded = AccountStore::load(&path).unwrap();
        assert_eq!(reloaded.accounts.len(), 9);
        for index in 0..8 {
            assert!(reloaded.get(&format!("worker-{index}")).is_some());
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn stale_cross_language_lease_is_recovered() {
        let dir = tmp_dir("stale-lock");
        let path = dir.join("accounts.json");
        let lock = dir.join("accounts.json.lock");
        std::fs::write(&lock, r#"{"ownerId":"abandoned","expiresAt":0}"#).unwrap();
        let file = std::fs::OpenOptions::new().write(true).open(&lock).unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(std::time::SystemTime::UNIX_EPOCH))
            .unwrap();
        store_with(&["a"]).save(&path).unwrap();
        assert!(!lock.exists());
        assert_eq!(AccountStore::load(&path).unwrap().accounts.len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_lease_left_by_a_killed_holder_lapses_with_its_heartbeat() {
        // A holder killed inside the lock (SIGKILL, or the process exiting
        // while another of its threads writes the store): the kernel drops
        // its flock, its lease stays, and the lease's expiry is still 30 s
        // out. Its heartbeat stopped when it died.
        let dir = tmp_dir("killed-holder-lease");
        let path = dir.join("accounts.json");
        store_with(&["a"]).save(&path).unwrap();
        let lock = dir.join("accounts.json.lock");
        std::fs::write(
            &lock,
            format!(
                "{{\"ownerId\":\"killed\",\"pid\":4242,\"expiresAt\":{}}}\n",
                unix_time_millis() + 30_000
            ),
        )
        .unwrap();
        let last_heartbeat = std::time::SystemTime::now() - Duration::from_secs(11);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&lock)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(last_heartbeat))
            .unwrap();

        AccountStore::mutate(&path, |store| {
            store.upsert(account("b"));
            Ok(())
        })
        .unwrap();

        assert!(!lock.exists());
        assert_eq!(AccountStore::load(&path).unwrap().accounts.len(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn malformed_stale_cross_language_lease_is_recovered() {
        let dir = tmp_dir("malformed-stale-lock");
        let path = dir.join("accounts.json");
        let lock = dir.join("accounts.json.lock");
        std::fs::write(&lock, "").unwrap();
        let file = std::fs::OpenOptions::new().write(true).open(&lock).unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(std::time::SystemTime::UNIX_EPOCH))
            .unwrap();
        store_with(&["a"]).save(&path).unwrap();
        assert!(!lock.exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rotate_from_moves_to_the_next_available_normal() {
        let mut store = store_with(&["a", "b", "c"]);
        store.get_mut("b").unwrap().disable("revoked");
        assert_eq!(store.rotate_from("a", at(0)).as_deref(), Some("c"));
        assert_eq!(store.current.as_deref(), Some("c"));
    }

    #[test]
    fn rotate_from_returns_none_when_no_alternative_robust() {
        let mut store = store_with(&["only"]);
        assert_eq!(store.rotate_from("only", at(0)), None);
    }

    #[test]
    fn upsert_replaces_and_remove_clears_current_normal() {
        let mut store = store_with(&["a"]);
        store.upsert(account("a").with_label("relabeled"));
        assert_eq!(store.accounts.len(), 1);
        assert_eq!(store.accounts[0].display_name(), "relabeled");

        store.set_current("a").unwrap();
        assert!(store.remove("a"));
        assert!(store.current.is_none());
        assert!(!store.remove("a"));
    }

    /// A row in the flat schema that predates the shared store.
    fn flat_legacy_json(uuid: &str, refresh: &str, enabled: bool) -> serde_json::Value {
        serde_json::json!({
            "uuid": uuid,
            "name": format!("{uuid}@example.com"),
            "email": format!("{uuid}@example.com"),
            "accessToken": "sk-ant-oat01-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "refreshToken": refresh,
            "expiresAt": 1_786_603_416_722i64,
            "addedAt": 1_778_606_812_194i64,
            "scopes": ["user:inference"],
            "enabled": enabled,
        })
    }

    fn write_flat_legacy(path: &Path, rows: Vec<serde_json::Value>) {
        std::fs::write(
            path,
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "accounts": rows,
                "active_index": 0,
            }))
            .unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn adopt_legacy_persists_new_rows_once_and_never_resurrects() {
        let dir = tmp_dir("adopt-legacy");
        let canonical = dir.join("accounts.json");
        let legacy = dir.join("anthropic-accounts.json");
        store_with(&["native-claude"]).save(&canonical).unwrap();
        let mut dead = flat_legacy_json("dead", "sk-ant-ort01-dead", false);
        dead["disabledReason"] = serde_json::json!("invalid_grant");
        write_flat_legacy(
            &legacy,
            vec![flat_legacy_json("one", "sk-ant-ort01-one", true), dead],
        );
        let paths = std::slice::from_ref(&legacy);
        assert_eq!(AccountStore::adopt_legacy(&canonical, paths).unwrap(), 1);
        let stored = AccountStore::load(&canonical).unwrap();
        let ids: Vec<&str> = stored.accounts.iter().map(|a| a.id.as_str()).collect();
        // The dead row (disabled with invalid_grant) is skipped.
        assert_eq!(ids, ["native-claude", "one"]);
        assert_eq!(stored.migrated_from, [legacy.to_string_lossy().to_string()]);
        // A second pass reads nothing and writes nothing; a removed row stays
        // removed.
        AccountStore::mutate(&canonical, |store| {
            store.remove("one");
            Ok(())
        })
        .unwrap();
        assert_eq!(AccountStore::adopt_legacy(&canonical, paths).unwrap(), 0);
        assert!(AccountStore::load(&canonical).unwrap().get("one").is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn adopt_legacy_creates_the_canonical_store_only_with_rows() {
        let dir = tmp_dir("adopt-legacy-empty");
        let canonical = dir.join("accounts.json");
        let empty = dir.join("empty-legacy.json");
        write_flat_legacy(&empty, vec![]);
        assert_eq!(
            AccountStore::adopt_legacy(&canonical, std::slice::from_ref(&empty)).unwrap(),
            0
        );
        assert!(!canonical.exists(), "no empty store is created");
        assert_eq!(AccountStore::adopt_legacy(&canonical, &[]).unwrap(), 0);
        let legacy = dir.join("jfc.json");
        write_flat_legacy(
            &legacy,
            vec![flat_legacy_json("one", "sk-ant-ort01-one", true)],
        );
        assert_eq!(
            AccountStore::adopt_legacy(&canonical, &[empty, legacy]).unwrap(),
            1
        );
        assert_eq!(AccountStore::load(&canonical).unwrap().accounts.len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn legacy_paths_resolve_from_a_lookup() {
        let env = |key: &str| match key {
            "HOME" => Some("/h".to_owned()),
            "GROK_HOME" => Some("/g".to_owned()),
            _ => None,
        };
        let paths = legacy_store_paths_from_lookup(env);
        let expected: Vec<PathBuf> = [
            "/h/.anthropic-accounts/anthropic-accounts.json",
            "/g/anthropic-accounts.json",
            "/h/.config/jfc/anthropic-accounts.json",
            "/h/.grok/anthropic-accounts.json",
            "/h/.config/opencode/anthropic-accounts.json",
        ]
        .iter()
        .map(PathBuf::from)
        .collect();
        assert_eq!(paths, expected);
        let dir_env = |key: &str| (key == STORE_DIR_ENV).then(|| "/s".to_owned());
        assert_eq!(
            legacy_store_paths_from_lookup(dir_env),
            vec![PathBuf::from("/s/anthropic-accounts.json")]
        );
    }

    #[test]
    fn add_api_key_dedupes_and_never_lands_on_another_row() {
        let mut store = AccountStore::default();
        store.accounts.push(Account::new(
            "work",
            Credential::Oauth(oauth_tokens(
                "sk-ant-ort01-workworkworkworkworkwork",
                1_800_000_000,
            )),
        ));
        let key = "sk-ant-api03-zzzzzzzzzzzzzzzzzzzzzzzzW9x8";
        let (id, added) = store.add_api_key(Some("work"), ApiKey::new(key));
        assert!(added);
        assert_eq!(id, "work-2", "the OAuth row keeps its id and credential");
        assert!(store.get("work").unwrap().credential.is_oauth());
        assert_eq!(store.get("work-2").unwrap().label.as_deref(), Some("work"));
        // The same key again is the same row.
        assert_eq!(
            store.add_api_key(Some("other"), ApiKey::new(key)),
            ("work-2".into(), false)
        );
        let (unnamed, added) = store.add_api_key(
            None,
            ApiKey::new("sk-ant-api03-yyyyyyyyyyyyyyyyyyyyyyyyQ7r6"),
        );
        assert!(added);
        assert_eq!(unnamed, "api-key-Q7r6");
    }

    #[test]
    fn load_or_migrate_adopts_the_flat_legacy_schema() {
        let dir = tmp_dir("flat-legacy");
        let canonical = dir.join("canonical.json");
        let legacy = dir.join("anthropic-accounts.json");
        write_flat_legacy(
            &legacy,
            vec![flat_legacy_json("one", "sk-ant-ort01-one", true)],
        );

        let loaded =
            AccountStore::load_or_migrate_from(&canonical, std::slice::from_ref(&legacy)).unwrap();

        assert_eq!(loaded.source, LoadSource::Legacy(legacy));
        assert_eq!(loaded.store.accounts.len(), 1);
        assert_eq!(loaded.store.accounts[0].id, "one");
        assert!(loaded.store.accounts[0].credential.is_oauth());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_or_migrate_merges_legacy_beside_an_existing_canonical_account() {
        // The regression this guards: a canonical store holding one account
        // used to end resolution before any legacy path was consulted, hiding
        // every other login on the machine.
        let dir = tmp_dir("merge-legacy");
        let canonical = dir.join("canonical.json");
        let legacy = dir.join("anthropic-accounts.json");
        store_with(&["native-claude"]).save(&canonical).unwrap();
        write_flat_legacy(
            &legacy,
            vec![
                flat_legacy_json("one", "sk-ant-ort01-one", true),
                flat_legacy_json("two", "sk-ant-ort01-two", false),
            ],
        );

        let loaded =
            AccountStore::load_or_migrate_from(&canonical, std::slice::from_ref(&legacy)).unwrap();

        assert_eq!(loaded.source, LoadSource::Canonical(canonical));
        let ids: Vec<&str> = loaded
            .store
            .accounts
            .iter()
            .map(|a| a.id.as_str())
            .collect();
        assert_eq!(ids, ["native-claude", "one", "two"]);
        // Disabled state survives adoption rather than silently re-enabling.
        assert!(!loaded.store.accounts[2].enabled);
        assert_eq!(
            loaded.store.migrated_from,
            vec![legacy.to_string_lossy().to_string()]
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_or_migrate_does_not_resurrect_a_removed_account() {
        let dir = tmp_dir("no-resurrect");
        let canonical = dir.join("canonical.json");
        let legacy = dir.join("anthropic-accounts.json");
        write_flat_legacy(
            &legacy,
            vec![flat_legacy_json("one", "sk-ant-ort01-one", true)],
        );

        let first =
            AccountStore::load_or_migrate_from(&canonical, std::slice::from_ref(&legacy)).unwrap();
        assert_eq!(first.store.accounts.len(), 1);

        // Persist the adoption, then remove the account the way a user would.
        let mut persisted = first.store;
        persisted.accounts = store_with(&["kept"]).accounts;
        persisted.save(&canonical).unwrap();

        let second = AccountStore::load_or_migrate_from(&canonical, &[legacy]).unwrap();
        let ids: Vec<&str> = second
            .store
            .accounts
            .iter()
            .map(|a| a.id.as_str())
            .collect();
        assert_eq!(ids, ["kept"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_or_migrate_deduplicates_a_login_seen_through_both_schemas() {
        let dir = tmp_dir("dedupe-legacy");
        let canonical = dir.join("canonical.json");
        let legacy = dir.join("anthropic-accounts.json");

        let mut shared = store_with(&[]);
        shared.accounts.push(Account::new(
            "native-claude",
            Credential::Oauth(oauth_tokens("sk-ant-ort01-shared", 1_800_000_000)),
        ));
        shared.save(&canonical).unwrap();
        write_flat_legacy(
            &legacy,
            vec![flat_legacy_json("legacy-view", "sk-ant-ort01-shared", true)],
        );

        let loaded = AccountStore::load_or_migrate_from(&canonical, &[legacy]).unwrap();

        assert_eq!(loaded.store.accounts.len(), 1);
        assert_eq!(loaded.store.accounts[0].id, "native-claude");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_or_migrate_does_not_admit_the_same_login_from_two_legacy_stores() {
        // Regression: keying only on the refresh token let a rotated copy of
        // the same login through, putting duplicate ids in the store and making
        // every id-keyed update ambiguous.
        let dir = tmp_dir("dupe-legacy");
        let canonical = dir.join("canonical.json");
        let first = dir.join("anthropic-accounts.json");
        let second = dir.join("grok-anthropic-accounts.json");
        write_flat_legacy(
            &first,
            vec![flat_legacy_json("one", "sk-ant-ort01-new", true)],
        );
        // Same uuid, older refresh token — another tool's stale copy.
        write_flat_legacy(
            &second,
            vec![flat_legacy_json("one", "sk-ant-ort01-old", true)],
        );

        let loaded = AccountStore::load_or_migrate_from(&canonical, &[first, second]).unwrap();

        assert_eq!(loaded.store.accounts.len(), 1);
        let ids: HashSet<&str> = loaded
            .store
            .accounts
            .iter()
            .map(|a| a.id.as_str())
            .collect();
        assert_eq!(ids.len(), loaded.store.accounts.len());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn identities_of_two_organizations_are_disjoint() {
        // One email and one account uuid can hold a grant in several
        // organizations; those are separate routable credentials. If their
        // identity keys overlapped, a merge would collapse them and silently
        // drop a working login.
        let account_for = |org: &str, refresh: &str| {
            let mut tokens = oauth_tokens(refresh, 1_800_000_000);
            tokens.account = Some(TokenAccount {
                uuid: "shared-uuid".into(),
                email_address: Some("person@example.com".into()),
            });
            tokens.organization = Some(TokenOrganization { uuid: org.into() });
            Account::new(
                format!("person@example.com ({org})"),
                Credential::Oauth(tokens),
            )
        };

        let a: HashSet<String> = account_identities(&account_for("org-a", "sk-ant-ort01-a"))
            .into_iter()
            .collect();
        let b: HashSet<String> = account_identities(&account_for("org-b", "sk-ant-ort01-b"))
            .into_iter()
            .collect();

        assert!(a.is_disjoint(&b), "a={a:?} b={b:?}");
        assert!(a.contains("uuid:shared-uuid@org-a"));
        assert!(a.contains("email:person@example.com@org-a"));
    }

    #[test]
    fn legacy_store_paths_includes_the_in_directory_filename() {
        // The file predecessors wrote beside the canonical store is the most
        // likely place to find accounts that were never migrated, so it must
        // lead the candidate list.
        let paths = legacy_store_paths();
        assert_eq!(
            paths.first(),
            Some(&store_dir().join("anthropic-accounts.json"))
        );
    }

    /// A store document written by another tool: extra top-level keys, extra
    /// row keys, extra credential keys, and every optional field this crate
    /// models populated.
    fn foreign_store_json(refresh: &str) -> serde_json::Value {
        serde_json::json!({
            "version": 1,
            "current": "oauth",
            "writer": { "name": "anthropic-auth", "version": "9.9.9" },
            "accounts": [
                {
                    "id": "oauth",
                    "label": "Work",
                    "email": "me@example.com",
                    "credential": {
                        "type": "oauth",
                        "access": "sk-ant-oat01-oldoldoldoldoldoldoldold",
                        "refresh": refresh,
                        "expires_at": 1_700_000_000_000i64,
                        "refresh_expires_at": 1_900_000_000_000i64,
                        "scopes": ["user:inference", "user:profile"],
                        "account": { "uuid": "acct", "email_address": "me@example.com" },
                        "organization": { "uuid": "org" },
                        "subscription_type": "max"
                    },
                    "enabled": true,
                    "created_at": "2026-09-01T00:00:00Z",
                    "last_used_at": "2026-09-02T00:00:00Z",
                    "quota": {
                        "five_hour_percent": 12.5,
                        "seven_day_percent": 40.0,
                        "checked_at": "2026-09-02T00:00:00Z"
                    },
                    "host_sidecar": { "pi": { "lastUsed": 123 } }
                },
                {
                    "id": "other",
                    "credential": { "type": "api_key", "key": "sk-ant-api01-aaaaaaaaaaaaaaaaaaaaaa" },
                    "enabled": true,
                    "created_at": "2026-09-01T00:00:00Z",
                    "refresh_lease": {
                        "id": "lease",
                        "until": 1_700_000_000_000i64,
                        "token_fingerprint": "abcdef0123456789"
                    },
                    "dead_refresh_fingerprint": "0123456789abcdef",
                    "notes": ["keep me"]
                }
            ]
        })
    }

    #[test]
    fn row_updates_preserve_every_field_they_do_not_own() {
        let dir = tmp_dir("preserve-fields");
        let path = dir.join("accounts.json");
        let old_refresh = "sk-ant-ort01-oldoldoldoldoldoldoldold";
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&foreign_store_json(old_refresh)).unwrap(),
        )
        .unwrap();

        // Every kind of row update this crate makes.
        AccountStore::mutate(&path, |store| {
            store
                .get_mut("oauth")
                .unwrap()
                .mark_rate_limited(at(1_800_000_000));
            Ok(())
        })
        .unwrap();
        assert!(
            AccountStore::commit_refresh_at(
                &path,
                "oauth",
                &RefreshToken::new(old_refresh),
                None,
                OAuthTokens {
                    access: AccessToken::new("sk-ant-oat01-newnewnewnewnewnewnewnew"),
                    refresh: RefreshToken::new("sk-ant-ort01-newnewnewnewnewnewnewnew"),
                    expires_at: at(1_800_000_000),
                    refresh_expires_at: None,
                    scopes: Vec::new(),
                    account: None,
                    organization: None,
                },
            )
            .unwrap()
        );
        AccountStore::mutate(&path, |store| {
            store.record_quota("other", Some(1.0), None, at(1_800_000_000));
            Ok(())
        })
        .unwrap();

        let raw: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(raw["writer"]["name"], "anthropic-auth");
        let oauth = &raw["accounts"][0];
        assert_eq!(oauth["host_sidecar"]["pi"]["lastUsed"], 123);
        assert_eq!(oauth["credential"]["subscription_type"], "max");
        assert_eq!(oauth["label"], "Work");
        assert_eq!(oauth["email"], "me@example.com");
        assert_eq!(oauth["quota"]["seven_day_percent"], 40.0);
        assert_eq!(oauth["credential"]["account"]["uuid"], "acct");
        assert_eq!(oauth["credential"]["organization"]["uuid"], "org");
        assert_eq!(
            oauth["credential"]["refresh_expires_at"],
            1_900_000_000_000i64
        );
        assert_eq!(
            oauth["credential"]["refresh"],
            "sk-ant-ort01-newnewnewnewnewnewnewnew"
        );
        assert!(oauth["rate_limited_until"].is_string());
        let other = &raw["accounts"][1];
        assert_eq!(other["notes"][0], "keep me");
        assert_eq!(other["dead_refresh_fingerprint"], "0123456789abcdef");
        assert_eq!(other["refresh_lease"]["id"], "lease");
        assert_eq!(other["quota"]["five_hour_percent"], 1.0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_locked_write_clears_stale_flags_and_keeps_real_ones() {
        let dir = tmp_dir("stale-flags");
        let path = dir.join("accounts.json");
        let mut store = AccountStore::default();
        let mut stale = Account::new(
            "stale",
            Credential::Oauth(oauth_tokens(
                "sk-ant-ort01-stalestalestalestale00",
                1_900_000_000,
            )),
        );
        stale.last_error = Some("invalid_grant".into());
        let mut dead = Account::new(
            "dead",
            Credential::Oauth(oauth_tokens(
                "sk-ant-ort01-deaddeaddeaddeaddead00",
                1_900_000_000,
            )),
        );
        dead.dead_refresh_fingerprint = dead.credential_fingerprint();
        dead.record_error("invalid_grant");
        store.upsert(stale);
        store.upsert(dead);
        store.save(&path).unwrap();

        // Any locked write, even one about something else.
        AccountStore::mutate(&path, |store| {
            store.current = Some("dead".into());
            Ok(())
        })
        .unwrap();
        let reloaded = AccountStore::load(&path).unwrap();
        assert_eq!(reloaded.get("stale").unwrap().last_error, None);
        assert_eq!(
            reloaded.get("dead").unwrap().current_error(),
            Some("invalid_grant")
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn replace_after_refresh_clears_everything_bound_to_the_old_token() {
        let dir = tmp_dir("replace-clears");
        let path = dir.join("accounts.json");
        let old = "sk-ant-ort01-oldoldoldoldoldoldoldold";
        let mut account =
            Account::new("oauth", Credential::Oauth(oauth_tokens(old, 1_800_000_000)));
        account.dead_refresh_fingerprint = account.credential_fingerprint();
        account.record_error("invalid_grant");
        account.quota = Some(crate::account::QuotaObservation {
            five_hour_percent: Some(3.0),
            seven_day_percent: None,
            checked_at: Some(at(1_700_000_000)),
        });
        let mut store = AccountStore::default();
        store.upsert(account);
        store.save(&path).unwrap();
        assert!(
            AccountStore::replace_oauth_after_refresh(
                &path,
                "oauth",
                &RefreshToken::new(old),
                oauth_tokens("sk-ant-ort01-newnewnewnewnewnewnewnew", 1_900_000_000),
            )
            .unwrap()
        );
        let row = AccountStore::load(&path).unwrap();
        let row = row.get("oauth").unwrap();
        assert_eq!(row.last_error, None);
        assert_eq!(row.dead_refresh_fingerprint, None);
        assert!(row.refresh_lease.is_none());
        assert!(row.last_refreshed_at.is_some());
        assert_eq!(row.quota.as_ref().unwrap().five_hour_percent, Some(3.0));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn merge_login_updates_the_same_login_in_place() {
        let mut tokens = oauth_tokens("sk-ant-ort01-oldoldoldoldoldoldoldold", 1_800_000_000);
        tokens.account = Some(TokenAccount {
            uuid: "acct".into(),
            email_address: Some("me@example.com".into()),
        });
        tokens.organization = Some(TokenOrganization { uuid: "org".into() });
        let mut existing = Account::new("me@example.com", Credential::Oauth(tokens.clone()));
        existing.label = Some("Work".into());
        existing.quota = Some(crate::account::QuotaObservation {
            five_hour_percent: Some(9.0),
            seven_day_percent: None,
            checked_at: Some(at(1_700_000_000)),
        });
        existing.dead_refresh_fingerprint = existing.credential_fingerprint();
        existing.record_error("invalid_grant");
        existing.enabled = false;
        existing
            .extra
            .insert("host".into(), serde_json::json!({"keep": true}));
        let mut store = AccountStore::default();
        store.upsert(existing);
        store.current = Some("me@example.com".into());

        let mut fresh = tokens;
        fresh.refresh = RefreshToken::new("sk-ant-ort01-freshfreshfreshfresh00");
        let id = store
            .merge_login(Account::new("login-id", Credential::Oauth(fresh.clone())))
            .unwrap();
        assert_eq!(id, "me@example.com");
        assert_eq!(store.accounts.len(), 1);
        let row = store.get("me@example.com").unwrap();
        assert_eq!(row.oauth().unwrap().refresh, fresh.refresh);
        assert!(row.enabled);
        assert_eq!(row.last_error, None);
        assert_eq!(row.dead_refresh_fingerprint, None);
        assert_eq!(row.label.as_deref(), Some("Work"));
        assert_eq!(row.quota.as_ref().unwrap().five_hour_percent, Some(9.0));
        assert_eq!(row.extra["host"]["keep"], true);
        assert_eq!(store.current.as_deref(), Some("me@example.com"));

        // A different login is appended.
        let other = store
            .merge_login(Account::new(
                "other",
                Credential::Oauth(oauth_tokens(
                    "sk-ant-ort01-otherotherotherother0",
                    1_800_000_000,
                )),
            ))
            .unwrap();
        assert_eq!(other, "other");
        assert_eq!(store.accounts.len(), 2);
    }

    #[test]
    fn a_scanned_legacy_file_is_recorded_even_when_every_row_was_skipped() {
        let dir = tmp_dir("legacy-scan");
        let canonical = dir.join("canonical.json");
        let legacy = dir.join("anthropic-accounts.json");
        store_with(&["kept"]).save(&canonical).unwrap();
        let mut dead = flat_legacy_json("dead", "sk-ant-ort01-dead", false);
        dead["disabledReason"] = serde_json::json!("invalid_grant");
        write_flat_legacy(&legacy, vec![dead]);

        let loaded =
            AccountStore::load_or_migrate_from(&canonical, std::slice::from_ref(&legacy)).unwrap();
        let ids: Vec<&str> = loaded
            .store
            .accounts
            .iter()
            .map(|a| a.id.as_str())
            .collect();
        assert_eq!(
            ids,
            ["kept"],
            "a row disabled with invalid_grant is never imported"
        );
        assert_eq!(
            loaded.store.migrated_from,
            vec![legacy.to_string_lossy().to_string()]
        );
        // Persisting it goes through a locked merge, not a snapshot overwrite.
        assert_eq!(
            AccountStore::merge_adopted(
                &canonical,
                &loaded.store.accounts,
                &loaded.store.migrated_from
            )
            .unwrap(),
            0
        );
        let on_disk = AccountStore::load(&canonical).unwrap();
        assert_eq!(on_disk.migrated_from, loaded.store.migrated_from);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn merge_adopted_appends_only_new_logins_and_keeps_rotations_made_since_the_load() {
        let dir = tmp_dir("merge-adopted");
        let path = dir.join("accounts.json");
        let mut on_disk = AccountStore::default();
        on_disk.upsert(Account::new(
            "a",
            Credential::Oauth(oauth_tokens(
                "sk-ant-ort01-aaaaaaaaaaaaaaaaaaaaaaaaa",
                1_900_000_000,
            )),
        ));
        on_disk.save(&path).unwrap();
        // A snapshot taken now, plus one adopted row.
        let mut snapshot = AccountStore::load(&path).unwrap();
        snapshot.accounts.push(Account::new(
            "b",
            Credential::Oauth(oauth_tokens(
                "sk-ant-ort01-bbbbbbbbbbbbbbbbbbbbbbbbb",
                1_900_000_000,
            )),
        ));
        // Meanwhile a peer rotates `a` and adds a field this crate ignores.
        AccountStore::mutate(&path, |store| {
            let row = store.get_mut("a")?;
            row.replace_oauth_tokens(oauth_tokens(
                "sk-ant-ort01-rotatedrotatedrotatedrot",
                1_900_000_000,
            ))?;
            row.extra.insert("peer".into(), serde_json::json!(1));
            Ok(())
        })
        .unwrap();
        let added = AccountStore::merge_adopted(&path, &snapshot.accounts, &["/legacy".to_owned()])
            .unwrap();
        assert_eq!(added, 1);
        let merged = AccountStore::load(&path).unwrap();
        let a = merged.get("a").unwrap();
        assert_eq!(
            a.oauth().unwrap().refresh.expose(),
            "sk-ant-ort01-rotatedrotatedrotatedrot",
            "the peer's rotation survives"
        );
        assert_eq!(a.extra["peer"], 1);
        assert!(merged.get("b").is_some());
        assert_eq!(merged.migrated_from, vec!["/legacy".to_owned()]);
        std::fs::remove_dir_all(&dir).ok();
    }
}
