//! Unsaved rotations against a temporary store.

use chrono::Duration;

use super::*;
use crate::account::Account;
use crate::token::{AccessToken, Credential};

fn tokens(tag: &str) -> OAuthTokens {
    OAuthTokens {
        access: AccessToken::new(format!("sk-ant-oat01-{tag}-aaaaaaaaaaaaaaaaaaaa")),
        refresh: RefreshToken::new(format!("sk-ant-ort01-{tag}-aaaaaaaaaaaaaaaaaaaa")),
        expires_at: Utc::now() + Duration::hours(8),
        refresh_expires_at: None,
        scopes: vec!["user:inference".into()],
        account: None,
        organization: None,
    }
}

/// A store in a fresh directory holding one row `row` with `held`.
fn store_with(tag: &str, held: &OAuthTokens) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "anthropic-unsaved-{tag}-{}-{}",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("accounts.json");
    AccountStore {
        accounts: vec![Account::new("row", Credential::Oauth(held.clone()))],
        ..AccountStore::default()
    }
    .save(&path)
    .unwrap();
    path
}

fn held_refresh(store: &AccountStore) -> String {
    store
        .get("row")
        .and_then(Account::oauth)
        .map(|tokens| tokens.refresh.expose().to_string())
        .unwrap_or_default()
}

fn record_files(path: &Path) -> usize {
    std::fs::read_dir(path.parent().unwrap())
        .unwrap()
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().contains(".unsaved-"))
        .count()
}

#[test]
fn the_store_file_keeps_its_format_and_readers_see_the_rotation() {
    let spent = tokens("fmt-spent");
    let rotated = tokens("fmt-rotated");
    let path = store_with("fmt", &spent);
    let before = std::fs::read(&path).unwrap();

    keep(&path, "row", &spent.refresh, &rotated).unwrap();
    forget_kept(&path);

    // An older reader sees the file exactly as it was.
    assert_eq!(std::fs::read(&path).unwrap(), before);
    // This crate's readers see the rotation.
    assert_eq!(
        held_refresh(&AccountStore::load(&path).unwrap()),
        rotated.refresh.expose()
    );
    assert_eq!(unsaved_accounts(&path), vec!["row".to_string()]);
    // The record is owner-only and carries no token in its name.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let record = record_file(&path, "row", &token_fingerprint(spent.refresh.expose()));
        assert_eq!(
            std::fs::metadata(&record).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(!record.to_string_lossy().contains("sk-ant"));
    }
    std::fs::remove_dir_all(path.parent().unwrap()).ok();
}

#[test]
fn a_stale_record_never_applies_and_the_next_write_removes_it() {
    let spent = tokens("stale-spent");
    let newer = tokens("stale-newer");
    let path = store_with("stale", &spent);
    keep(&path, "row", &spent.refresh, &tokens("stale-rotated")).unwrap();
    forget_kept(&path);
    // The row moved on (a re-login) before the rotation was saved.
    std::fs::write(
        &path,
        serde_json::to_vec(&AccountStore {
            accounts: vec![Account::new("row", Credential::Oauth(newer.clone()))],
            ..AccountStore::default()
        })
        .unwrap(),
    )
    .unwrap();

    assert_eq!(
        held_refresh(&AccountStore::load(&path).unwrap()),
        newer.refresh.expose()
    );
    assert!(unsaved_accounts(&path).is_empty());
    AccountStore::mutate(&path, |_| Ok(())).unwrap();
    assert_eq!(record_files(&path), 0);
    std::fs::remove_dir_all(path.parent().unwrap()).ok();
}

#[cfg(unix)]
#[test]
fn a_record_others_can_read_or_of_another_version_is_ignored() {
    use std::os::unix::fs::PermissionsExt;
    let spent = tokens("ignored-spent");
    let path = store_with("ignored", &spent);
    keep(&path, "row", &spent.refresh, &tokens("ignored-rotated")).unwrap();
    forget_kept(&path);
    let record = record_file(&path, "row", &token_fingerprint(spent.refresh.expose()));
    std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o644)).unwrap();

    assert_eq!(
        held_refresh(&AccountStore::load(&path).unwrap()),
        spent.refresh.expose()
    );

    std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&record).unwrap()).unwrap();
    document["version"] = 2.into();
    std::fs::write(&record, serde_json::to_vec(&document).unwrap()).unwrap();

    assert_eq!(
        held_refresh(&AccountStore::load(&path).unwrap()),
        spent.refresh.expose()
    );
    std::fs::remove_dir_all(path.parent().unwrap()).ok();
}

#[test]
fn this_process_applies_its_rotation_even_without_the_record() {
    let spent = tokens("memory-spent");
    let rotated = tokens("memory-rotated");
    let path = store_with("memory", &spent);
    keep(&path, "row", &spent.refresh, &rotated).unwrap();
    let record = record_file(&path, "row", &token_fingerprint(spent.refresh.expose()));
    std::fs::remove_file(record).unwrap();

    assert_eq!(
        held_refresh(&AccountStore::load(&path).unwrap()),
        rotated.refresh.expose()
    );
    AccountStore::mutate(&path, |_| Ok(())).unwrap();
    assert_eq!(
        held_refresh(&AccountStore::load_file(&path).unwrap()),
        rotated.refresh.expose()
    );
    std::fs::remove_dir_all(path.parent().unwrap()).ok();
}
