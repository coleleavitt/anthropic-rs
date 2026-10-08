//! Rotations the store could not save.
//!
//! A refresh spends its refresh token at the token endpoint before the
//! rotation is committed to the store. When that commit fails (the store
//! lock is held past its wait, the file cannot be written, the disk is
//! full), the rotation exists only in the refreshing process while the
//! store still holds the spent token: the next reader presents it, gets
//! `invalid_grant`, and the account is lost. So the rotation is kept:
//!
//! - it is returned to the caller (the refresh itself succeeded);
//! - this process applies it to every store it loads;
//! - it is written beside the store as `<store>.unsaved-<16 hex>` (owner
//!   only, written to a temporary file and renamed), and every reader of
//!   the store through this crate (and so anthropic-napi, and the opencode
//!   and pi plugins through it) applies it on load, so no process sharing
//!   the store presents the spent token;
//! - the next locked write of the store, by any such process, persists it
//!   and removes the record.
//!
//! A record applies only while the row still holds the spent token; once
//! the row holds anything else (the rotation was persisted, or the login
//! was replaced) it is stale and the next locked write removes it. The
//! store file's format is unchanged and an older reader ignores the record;
//! while the refreshing process's claim on the row lasts (it is not
//! released after a failed commit) an older reader does not spend the token
//! either. Records and their errors never carry a token value.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::store::AccountStore;
use crate::token::{OAuthTokens, RefreshToken, token_fingerprint};

/// The record format; a record of any other version is ignored.
const RECORD_VERSION: u32 = 1;
/// The largest record read (a record holds one token set).
const RECORD_MAX_BYTES: u64 = 64 * 1024;

/// One rotation the store could not save.
#[derive(Clone, Serialize, Deserialize)]
struct Record {
    version: u32,
    /// The store row it belongs to.
    account_id: String,
    /// The fingerprint of the refresh token it replaces (spent).
    spent: String,
    /// The rotation.
    tokens: OAuthTokens,
    /// When the refresh produced it.
    #[serde(with = "chrono::serde::ts_milliseconds")]
    refreshed_at: DateTime<Utc>,
}

/// A record a load applied, or found stale: what a later successful write
/// of that store settles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Seen {
    file: PathBuf,
    spent: String,
}

/// This process's records, by store path: they apply even when the record
/// file could not be written.
fn kept() -> &'static Mutex<HashMap<PathBuf, Vec<Record>>> {
    static KEPT: OnceLock<Mutex<HashMap<PathBuf, Vec<Record>>>> = OnceLock::new();
    KEPT.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The record file for `account_id`'s rotation of the token `spent`
/// (a fingerprint).
fn record_file(store_path: &Path, account_id: &str, spent: &str) -> PathBuf {
    let name = store_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("accounts.json");
    let key = token_fingerprint(&format!("{account_id}\0{spent}"));
    store_path.with_file_name(format!("{name}.unsaved-{key}"))
}

/// The prefix every record file of the store at `store_path` starts with.
fn record_prefix(store_path: &Path) -> String {
    let name = store_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("accounts.json");
    format!("{name}.unsaved-")
}

/// Keep `tokens`, the rotation of `account_id`'s spent refresh token
/// `spent`, which the store could not save: in this process, and in a
/// record beside the store for every other process.
///
/// # Errors
///
/// The record could not be written (this process still applies it).
pub(crate) fn keep(
    store_path: &Path,
    account_id: &str,
    spent: &RefreshToken,
    tokens: &OAuthTokens,
) -> Result<()> {
    let record = Record {
        version: RECORD_VERSION,
        account_id: account_id.to_owned(),
        spent: token_fingerprint(spent.expose()),
        tokens: tokens.clone(),
        refreshed_at: Utc::now(),
    };
    {
        let mut kept = kept()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let records = kept.entry(store_path.to_path_buf()).or_default();
        records
            .retain(|known| known.account_id != record.account_id || known.spent != record.spent);
        records.push(record.clone());
    }
    write_record(&record_file(store_path, account_id, &record.spent), &record)
}

/// Write `record` to `file`: owner only, through a temporary file renamed
/// into place, so a reader never sees half of it.
fn write_record(file: &Path, record: &Record) -> Result<()> {
    let body = serde_json::to_vec(record)?;
    let temporary = file.with_file_name(format!(
        "{}.tmp-{}",
        file.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("unsaved"),
        std::process::id()
    ));
    let written = (|| -> Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut handle = options.open(&temporary)?;
        handle.write_all(&body)?;
        handle.sync_all()?;
        std::fs::rename(&temporary, file)?;
        Ok(())
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    written
}

/// The records of the store at `store_path`: this process's, then the
/// files beside it (an unreadable, foreign-readable or unknown-version file
/// is skipped).
fn records(store_path: &Path) -> Vec<(PathBuf, Record)> {
    let mut found: Vec<(PathBuf, Record)> = kept()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(store_path)
        .into_iter()
        .flatten()
        .map(|record| {
            (
                record_file(store_path, &record.account_id, &record.spent),
                record.clone(),
            )
        })
        .collect();
    let prefix = record_prefix(store_path);
    let directory = store_path.parent().unwrap_or_else(|| Path::new("."));
    let Ok(entries) = std::fs::read_dir(directory) else {
        return found;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with(&prefix) || name.contains(".tmp-") {
            continue;
        }
        let file = entry.path();
        if found.iter().any(|(known, _)| *known == file) {
            continue;
        }
        let Ok(raw) = crate::file_security::read_bounded_regular(
            &file,
            RECORD_MAX_BYTES,
            true,
            "unsaved rotation record",
        ) else {
            continue;
        };
        let Ok(record) = serde_json::from_slice::<Record>(&raw) else {
            continue;
        };
        if record.version == RECORD_VERSION {
            found.push((file, record));
        }
    }
    found
}

/// Apply the store's unsaved rotations to `store`: a row that still holds a
/// rotation's spent token holds the rotation instead (as a committed refresh
/// leaves it). Returns every record seen, applied or stale, for
/// [`settle`] after the store is written.
pub(crate) fn apply(store_path: &Path, store: &mut AccountStore) -> Vec<Seen> {
    let mut seen = Vec::new();
    for (file, record) in records(store_path) {
        if let Some(account) = store.accounts.iter_mut().find(|account| {
            account.id == record.account_id
                && account.oauth().is_some_and(|tokens| {
                    token_fingerprint(tokens.refresh.expose()) == record.spent
                })
        }) {
            let mut next = record.tokens.clone();
            if let Some(current) = account.oauth() {
                if next.refresh_expires_at.is_none() {
                    next.refresh_expires_at = current.refresh_expires_at;
                }
                if next.account.is_none() {
                    next.account = current.account.clone();
                }
                if next.organization.is_none() {
                    next.organization = current.organization.clone();
                }
                if next.scopes.is_empty() {
                    next.scopes = current.scopes.clone();
                }
            }
            if account.replace_oauth_tokens(next).is_ok() {
                account.dead_refresh_fingerprint = None;
                account.clear_error();
                account.refresh_lease = None;
                account.last_refreshed_at = Some(record.refreshed_at);
            }
        }
        seen.push(Seen {
            file,
            spent: record.spent,
        });
    }
    seen
}

/// After `store` was written to `store_path`: remove the records `seen`
/// that the written store no longer needs (no row holds their spent token).
pub(crate) fn settle(store_path: &Path, seen: &[Seen], store: &AccountStore) {
    if seen.is_empty() {
        return;
    }
    let held = |spent: &str| {
        store.accounts.iter().any(|account| {
            account
                .oauth()
                .is_some_and(|tokens| token_fingerprint(tokens.refresh.expose()) == spent)
        })
    };
    for record in seen.iter().filter(|record| !held(&record.spent)) {
        let _ = std::fs::remove_file(&record.file);
    }
    let mut kept = kept()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(records) = kept.get_mut(store_path) {
        records.retain(|record| held(&record.spent));
        if records.is_empty() {
            kept.remove(store_path);
        }
    }
}

/// The store rows whose latest rotation is not in the store file yet (kept
/// by this process or recorded beside the store), for a host's notice.
#[must_use]
pub fn unsaved_accounts(store_path: &Path) -> Vec<String> {
    let Ok(store) = AccountStore::load_file(store_path) else {
        return Vec::new();
    };
    let mut accounts: Vec<String> = records(store_path)
        .into_iter()
        .filter(|(_, record)| {
            store.accounts.iter().any(|account| {
                account.id == record.account_id
                    && account.oauth().is_some_and(|tokens| {
                        token_fingerprint(tokens.refresh.expose()) == record.spent
                    })
            })
        })
        .map(|(_, record)| record.account_id)
        .collect();
    accounts.sort();
    accounts.dedup();
    accounts
}

/// Forget this process's records for `store_path`, as another process
/// that never saw them (tests).
#[cfg(test)]
pub(crate) fn forget_kept(store_path: &Path) {
    kept()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(store_path);
}

#[cfg(test)]
mod tests;
