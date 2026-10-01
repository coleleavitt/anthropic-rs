//! Publishing a store rotation back into Claude Code's plaintext credential
//! file (`$CLAUDE_CONFIG_DIR/.credentials.json`, default
//! `~/.claude/.credentials.json`).
//!
//! Anthropic rotates the refresh token on every refresh and revokes the whole
//! family when a superseded one is presented. When the shared store spends a
//! refresh token that Claude Code's file also holds (the login was imported
//! from Claude Code, or both sides were seeded with the same grant), staying
//! silent forks the family: the store moves forward, Claude Code keeps the
//! spent token, and its next refresh kills the login for both. Claude Code
//! stats the file and drops its credential cache when the mtime changes, so a
//! write here is how the rotation reaches it.
//!
//! The write is deliberately narrow:
//!
//! - [`publish_native_rotation`]: only when the file still holds **exactly
//!   the refresh token that was just spent** (a Claude Code that rotated on
//!   its own is never clobbered); [`publish_native_login`] (publish by
//!   account, `super::link`): also when Claude Code is logged into the same
//!   account (`.claude.json`) and its copy is older, since a newer login
//!   revokes an older one; never for a different account. A file that
//!   already holds the new token is left alone (no pointless mtime bump);
//! - never creates the file, never follows a symlink, never overwrites a file
//!   it cannot parse (it may be mid-write, and a clobbered file logs the user
//!   out of Claude Code);
//! - keeps every field it does not own (`subscriptionType`, `rateLimitTier`,
//!   `clientId`, unknown top-level keys such as `mcpOAuth`);
//! - writes a `0600` temp sibling, `fsync`s it and renames it into place, and
//!   never changes the directory's permissions;
//! - runs under Claude Code's own credential-write lock: the
//!   `proper-lockfile` directory `<config dir>/.storage-write.lock`
//!   (`mkdir`-exclusive, stale after 15 s by mtime, 10 retries of 100 ms to
//!   1 s; Claude Code 2.1.285 `secureStorage` write path). Claude Code's own
//!   read-modify-write of the file happens under the same lock.
//!
//! [`NativePublish`] is the policy knob shared by every consumer: it is set
//! on the OAuth client (`OAuthClient::native_publish`, used by
//! `OAuthClient::refresh_shared`), so ckl, the napi binding and any other
//! Rust caller behave the same way.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde_json::Value;

use crate::token::{OAuthTokens, RefreshToken};

/// Environment variable that turns the publish off: `0`, `false`, `no` or
/// `off` disable it; unset, empty, `1`, `true`, `on` or `auto` leave it on
/// ([`NativePublish::Auto`]).
pub const NATIVE_PUBLISH_ENV: &str = "ANTHROPIC_NATIVE_PUBLISH";

/// Claude Code's credential-write lock directory, inside its config dir.
pub const NATIVE_WRITE_LOCK_NAME: &str = ".storage-write.lock";

/// A lock directory whose mtime is older than this belongs to a dead holder
/// (Claude Code's `stale: 15000`).
pub const NATIVE_WRITE_LOCK_STALE: Duration = Duration::from_secs(15);

const LOCK_RETRIES: u32 = 10;
const LOCK_MIN_WAIT: Duration = Duration::from_millis(100);
const LOCK_MAX_WAIT: Duration = Duration::from_millis(1_000);

/// Whether (and where) a rotation is published to Claude Code's file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativePublish {
    /// Never publish.
    Off,
    /// Publish to the path Claude Code itself uses
    /// ([`super::native_claude_credentials_path`]) when that file holds the
    /// spent token. Suppressed while OAuth test mode is on, so a test run can
    /// never read or rewrite a developer's real credential.
    Auto,
    /// Publish to this file when it holds the spent token. An explicit path
    /// is honoured in test mode too (that is how the publish is tested).
    At(PathBuf),
}

impl Default for NativePublish {
    /// [`NativePublish::from_env`].
    fn default() -> Self {
        Self::from_env()
    }
}

impl NativePublish {
    /// [`NATIVE_PUBLISH_ENV`] from the process environment.
    pub fn from_env() -> Self {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// [`NATIVE_PUBLISH_ENV`] from an arbitrary lookup (a JS host's
    /// environment snapshot).
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        match lookup(NATIVE_PUBLISH_ENV) {
            Some(value) if !native_publish_enabled_value(&value) => Self::Off,
            _ => Self::Auto,
        }
    }

    /// The file to publish to, or `None` when the publish is off or (for
    /// [`NativePublish::Auto`]) suppressed by test mode.
    pub fn target(&self, test_mode: bool) -> Option<PathBuf> {
        match self {
            Self::Off => None,
            Self::Auto if test_mode => None,
            Self::Auto => Some(super::native_claude_credentials_path()),
            Self::At(path) => Some(path.clone()),
        }
    }
}

/// Whether a raw [`NATIVE_PUBLISH_ENV`] value leaves the publish on.
pub fn native_publish_enabled_value(value: &str) -> bool {
    let value = value.trim();
    !(value == "0"
        || value.eq_ignore_ascii_case("false")
        || value.eq_ignore_ascii_case("no")
        || value.eq_ignore_ascii_case("off"))
}

/// What a publish attempt did. Nothing here carries a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativePublishOutcome {
    /// The file held the spent token and now holds the rotation.
    Written,
    /// The file already holds the rotated token; nothing was written.
    Unchanged,
    /// The file holds some other credential (Claude Code rotated on its own,
    /// a newer login of the same account, or an unidentified login); left
    /// alone.
    NotHeld,
    /// Claude Code is logged into a different account (its `.claude.json`
    /// `oauthAccount` names another account or organization); never
    /// written.
    OtherAccount,
    /// There is no credential to replace (no file, or, for the Keychain
    /// backend, no item); it is never created.
    Absent,
    /// The file is not JSON (possibly mid-write); refused rather than
    /// clobbered.
    Unparseable,
    /// The file is a symlink, not a regular file, or too large; refused.
    Refused(&'static str),
    /// Claude Code's write lock stayed held by a live holder; nothing was
    /// written.
    LockBusy,
    /// An I/O error; the message is secret-free.
    Failed(String),
}

impl NativePublishOutcome {
    /// A stable wire code (`written`, `unchanged`, `not_held`,
    /// `other_account`, `absent`, `unparseable`, `refused`, `lock_busy`,
    /// `failed`).
    pub fn code(&self) -> &'static str {
        match self {
            Self::Written => "written",
            Self::Unchanged => "unchanged",
            Self::NotHeld => "not_held",
            Self::OtherAccount => "other_account",
            Self::Absent => "absent",
            Self::Unparseable => "unparseable",
            Self::Refused(_) => "refused",
            Self::LockBusy => "lock_busy",
            Self::Failed(_) => "failed",
        }
    }
}

/// Write `rotated` into Claude Code's credential file at `path` when its
/// `claudeAiOauth.refreshToken` is exactly `spent`. See the module docs for
/// every rule. Never panics and never returns token bytes.
pub fn publish_native_rotation(
    path: &Path,
    spent: &RefreshToken,
    rotated: &OAuthTokens,
) -> NativePublishOutcome {
    let files = super::link::ClaudeCodeFiles::for_credentials(path);
    publish_with(&files, rotated, &|held, _| {
        if held == Some(spent.expose()) {
            Verdict::Write
        } else {
            Verdict::Skip(NativePublishOutcome::NotHeld)
        }
    })
}

/// Publish by account (one login per account, `super::link`): write
/// `rotated` into Claude Code's credential file when it holds `spent`
/// (when given), **or** when Claude Code is logged into the same account
/// as `rotated` (`.claude.json` `oauthAccount.{accountUuid,
/// organizationUuid}` equal to `rotated`'s account and organization) and
/// the file's copy is older (its access token expires before `rotated`'s),
/// even though it holds a different refresh token: a newer login of an
/// account revokes the older one, so that token is dead. A copy that is not
/// older is a newer Claude Code login and is left alone
/// ([`NativePublishOutcome::NotHeld`]); a file of a different account is
/// never written ([`NativePublishOutcome::OtherAccount`]).
/// Every other rule of [`publish_native_rotation`] holds (never created,
/// no symlinks, unparseable refused, unknown keys kept, `0600` atomic
/// replace under Claude Code's `.storage-write.lock`, the decision re-made
/// under the lock).
pub fn publish_native_login(
    files: &super::link::ClaudeCodeFiles,
    spent: Option<&RefreshToken>,
    rotated: &OAuthTokens,
) -> NativePublishOutcome {
    publish_native_login_guarded(files, spent, None, rotated)
}

/// [`publish_native_login`] for a caller that judged Claude Code's copy
/// older moments ago: with `native_before` (the refresh token Claude Code
/// held then), a copy of the same account is replaced only when it is still
/// exactly that token (or `spent`). Anything else was written since, by a
/// Claude Code `/login` or refresh, and is a newer login that this must
/// never overwrite ([`NativePublishOutcome::NotHeld`]), whatever its expiry.
/// Without `native_before` it is [`publish_native_login`].
pub fn publish_native_login_guarded(
    files: &super::link::ClaudeCodeFiles,
    spent: Option<&RefreshToken>,
    native_before: Option<&RefreshToken>,
    rotated: &OAuthTokens,
) -> NativePublishOutcome {
    let target = super::link::ClaudeCodeIdentity::of_tokens(rotated);
    publish_with(files, rotated, &|held, held_expires_at| {
        if held.is_some() && spent.is_some_and(|spent| held == Some(spent.expose())) {
            return Verdict::Write;
        }
        let Some(target) = &target else {
            return Verdict::Skip(NativePublishOutcome::NotHeld);
        };
        match super::link::read_claude_code_identity(&files.config) {
            Some(native) if native.same_account(target) => match native_before {
                Some(before) if held == Some(before.expose()) => Verdict::Write,
                Some(_) => Verdict::Skip(NativePublishOutcome::NotHeld),
                None if held_expires_at
                    .is_some_and(|at| at >= rotated.expires_at.timestamp_millis()) =>
                {
                    Verdict::Skip(NativePublishOutcome::NotHeld)
                }
                None => Verdict::Write,
            },
            Some(_) => Verdict::Skip(NativePublishOutcome::OtherAccount),
            None => Verdict::Skip(NativePublishOutcome::NotHeld),
        }
    })
}

enum Verdict {
    Write,
    Skip(NativePublishOutcome),
}

fn publish_with(
    files: &super::link::ClaudeCodeFiles,
    rotated: &OAuthTokens,
    decide: &dyn Fn(Option<&str>, Option<i64>) -> Verdict,
) -> NativePublishOutcome {
    // Decide without the lock first: a credential that is not to be written
    // (the common case) is never locked, only read.
    match prepare(files, rotated, decide) {
        Prepared::Write(_) => {}
        Prepared::Done(outcome) => return outcome,
    }
    let Ok(_lock) = NativeWriteLock::try_acquire(files.config_directory()) else {
        return NativePublishOutcome::LockBusy;
    };
    // Re-read under Claude Code's write lock: it may have written meanwhile.
    match prepare(files, rotated, decide) {
        Prepared::Write(bytes) => match super::source::write_raw(files, &bytes) {
            Ok(()) => NativePublishOutcome::Written,
            Err(message) => NativePublishOutcome::Failed(message),
        },
        Prepared::Done(outcome) => outcome,
    }
}

enum Prepared {
    /// The merged document to write.
    Write(Vec<u8>),
    /// Nothing to write, and why.
    Done(NativePublishOutcome),
}

fn prepare(
    files: &super::link::ClaudeCodeFiles,
    rotated: &OAuthTokens,
    decide: &dyn Fn(Option<&str>, Option<i64>) -> Verdict,
) -> Prepared {
    use Prepared::Done;

    use super::source::NativeRaw;
    let raw = match super::source::read_raw(files, false) {
        NativeRaw::Present(raw) => raw,
        // Never created: no file, or no Keychain item.
        NativeRaw::Absent => return Done(NativePublishOutcome::Absent),
        NativeRaw::Refused(why) => return Done(NativePublishOutcome::Refused(why)),
        NativeRaw::Unavailable(message) => {
            return Done(NativePublishOutcome::Failed(crate::token::redact_secrets(
                &message,
            )));
        }
    };
    let Ok(mut document) = serde_json::from_slice::<Value>(&raw) else {
        return Done(NativePublishOutcome::Unparseable);
    };
    let Some(root) = document.as_object_mut() else {
        return Done(NativePublishOutcome::Unparseable);
    };
    let Some(oauth) = root.get_mut("claudeAiOauth").and_then(Value::as_object_mut) else {
        return Done(NativePublishOutcome::NotHeld);
    };
    let held = oauth.get("refreshToken").and_then(Value::as_str);
    if held == Some(rotated.refresh.expose()) {
        return Done(NativePublishOutcome::Unchanged);
    }
    let held_expires_at = oauth.get("expiresAt").and_then(Value::as_i64);
    if let Verdict::Skip(outcome) = decide(held, held_expires_at) {
        return Done(outcome);
    }
    oauth.insert(
        "accessToken".into(),
        Value::String(rotated.access.expose().to_owned()),
    );
    oauth.insert(
        "refreshToken".into(),
        Value::String(rotated.refresh.expose().to_owned()),
    );
    oauth.insert(
        "expiresAt".into(),
        Value::from(rotated.expires_at.timestamp_millis()),
    );
    // Claude Code keeps the prior refresh expiry when a refresh omits it.
    if let Some(at) = rotated.refresh_expires_at {
        oauth.insert(
            "refreshTokenExpiresAt".into(),
            Value::from(at.timestamp_millis()),
        );
    }
    if !rotated.scopes.is_empty() {
        oauth.insert(
            "scopes".into(),
            Value::Array(rotated.scopes.iter().cloned().map(Value::String).collect()),
        );
    }
    match serde_json::to_vec(&document) {
        Ok(bytes) => Prepared::Write(bytes),
        Err(_) => Done(NativePublishOutcome::Failed(
            "could not serialize the native document".into(),
        )),
    }
}

/// Replace `path` with `bytes` through a `0600` temp sibling (`fsync`,
/// symlink re-check, `rename`, directory `fsync`). Unlike the store writer it
/// never creates or re-permissions the directory: it is Claude Code's.
pub(crate) fn write_replace_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(".credentials.json");
    let temporary = directory.join(format!(
        "{name}.tmp-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    let written = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(std::io::Error::other("the target became a symlink"));
        }
        std::fs::rename(&temporary, path)
    })();
    if let Err(error) = written {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    if let Ok(dir) = std::fs::File::open(directory) {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Claude Code's `proper-lockfile` credential-write lock (see
/// [`ProperLock`]) on `<config dir>/.storage-write.lock`.
pub(crate) struct NativeWriteLock;

impl NativeWriteLock {
    pub(crate) fn try_acquire(config_directory: &Path) -> Result<ProperLock, LockFailure> {
        ProperLock::try_acquire(
            &config_directory.join(NATIVE_WRITE_LOCK_NAME),
            NATIVE_WRITE_LOCK_STALE,
        )
    }
}

/// Why a [`ProperLock`] was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LockFailure {
    /// A live holder kept it through every retry.
    Busy,
    /// `mkdir` failed for another reason (e.g. `NotFound`: no config dir).
    Io(std::io::ErrorKind),
}

/// A `proper-lockfile` lock: a directory created with `mkdir` (atomic),
/// treated as abandoned once its mtime is older than `stale`, removed on
/// release. Retries 10 times, waiting 100 ms doubling to 1 s (about 7 s in
/// all).
pub(crate) struct ProperLock {
    path: PathBuf,
}

impl ProperLock {
    pub(crate) fn acquire(path: &Path, stale: Duration) -> Option<Self> {
        Self::try_acquire(path, stale).ok()
    }

    pub(crate) fn try_acquire(path: &Path, stale: Duration) -> Result<Self, LockFailure> {
        let mut wait = LOCK_MIN_WAIT;
        for attempt in 0..=LOCK_RETRIES {
            match std::fs::create_dir(path) {
                Ok(()) => {
                    return Ok(Self {
                        path: path.to_path_buf(),
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if lock_is_stale(path, stale) {
                        // A dead holder: take it over the way proper-lockfile
                        // does (remove, then compete for mkdir again).
                        let _ = std::fs::remove_dir(path);
                        continue;
                    }
                }
                Err(error) => return Err(LockFailure::Io(error.kind())),
            }
            if attempt == LOCK_RETRIES {
                break;
            }
            std::thread::sleep(wait);
            wait = (wait * 2).min(LOCK_MAX_WAIT);
        }
        Err(LockFailure::Busy)
    }
}

impl Drop for ProperLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(&self.path);
    }
}

fn lock_is_stale(path: &Path, stale: Duration) -> bool {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|mtime| SystemTime::now().duration_since(mtime).ok())
        .is_some_and(|age| age > stale)
}

/// Non-secret facts about Claude Code's credential file (for an explicit
/// `import-native`): no token bytes, only expiry, scopes, plan labels and the
/// refresh token's fingerprint (to tell whether the store already holds it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeOAuthSummary {
    /// The file read.
    pub path: PathBuf,
    /// Access-token expiry, epoch ms.
    pub expires_at: i64,
    /// Refresh-token expiry, epoch ms, when recorded.
    pub refresh_expires_at: Option<i64>,
    /// Granted scopes.
    pub scopes: Vec<String>,
    /// `subscriptionType` (display only).
    pub subscription_type: Option<String>,
    /// `rateLimitTier` (display only).
    pub rate_limit_tier: Option<String>,
    /// [`crate::token_fingerprint`] of the refresh token.
    pub refresh_fingerprint: String,
}

/// Summarize the credential Claude Code holds at `path` (default: its own
/// path). `Ok(None)` when there is no file. A file that exists but cannot be
/// used (symlink, group/world readable, malformed) is an error, like
/// [`super::import_native_claude_file`].
pub fn read_native_claude_summary(
    path: Option<&Path>,
) -> crate::Result<Option<NativeOAuthSummary>> {
    let path = path
        .map(Path::to_path_buf)
        .unwrap_or_else(super::native_claude_credentials_path);
    if std::fs::symlink_metadata(&path)
        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    {
        return Ok(None);
    }
    let imported = super::import_native_claude_file(Some(&path))?;
    Ok(Some(NativeOAuthSummary {
        path,
        expires_at: imported.tokens.expires_at.timestamp_millis(),
        refresh_expires_at: imported
            .tokens
            .refresh_expires_at
            .map(|at| at.timestamp_millis()),
        scopes: imported.tokens.scopes.clone(),
        subscription_type: imported.subscription_type.clone(),
        rate_limit_tier: imported.rate_limit_tier.clone(),
        refresh_fingerprint: crate::token::token_fingerprint(imported.tokens.refresh.expose()),
    }))
}

/// [`read_native_claude_summary`] through the backend of `files`: the
/// credential file, or Claude Code's Keychain item. `Ok(None)` when there is
/// none; a Keychain read that cannot be made right now (locked, `security`
/// failed) is [`crate::Error::LinkBusy`]. For the Keychain, `path` is the
/// `.credentials.json` path Claude Code would fall back to.
pub fn read_claude_code_summary(
    files: &super::link::ClaudeCodeFiles,
) -> crate::Result<Option<NativeOAuthSummary>> {
    let super::source::CredentialBackend::Keychain(item) = &files.backend else {
        return read_native_claude_summary(Some(&files.credentials));
    };
    let raw = match super::source::read_raw(files, true) {
        super::source::NativeRaw::Present(raw) => raw,
        super::source::NativeRaw::Absent | super::source::NativeRaw::Refused(_) => {
            return Ok(None);
        }
        super::source::NativeRaw::Unavailable(reason) => {
            return Err(super::link::link_busy(reason));
        }
    };
    let imported = super::parse_native_document(
        &raw,
        super::NativeClaudeCredentialSource::SecureStorage {
            service: item.service.clone(),
            account: item.account.clone(),
        },
    )?;
    Ok(Some(NativeOAuthSummary {
        path: files.credentials.clone(),
        expires_at: imported.tokens.expires_at.timestamp_millis(),
        refresh_expires_at: imported
            .tokens
            .refresh_expires_at
            .map(|at| at.timestamp_millis()),
        scopes: imported.tokens.scopes.clone(),
        subscription_type: imported.subscription_type.clone(),
        rate_limit_tier: imported.rate_limit_tier.clone(),
        refresh_fingerprint: crate::token::token_fingerprint(imported.tokens.refresh.expose()),
    }))
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::*;
    use crate::token::AccessToken;

    // Port of anthropic-auth `core/src/tests/native-claude-publish.test.ts`
    // (9 cases) plus the spent-token, symlink and lock rules. Temp dirs only;
    // the real `~/.claude` is never touched.

    const OLD_ACCESS: &str = "sk-ant-oat01-oldoldoldoldoldoldoldoldold";
    const OLD_REFRESH: &str = "sk-ant-ort01-oldoldoldoldoldoldoldoldold";
    const NEW_ACCESS: &str = "sk-ant-oat01-newnewnewnewnewnewnewnewnew";
    const NEW_REFRESH: &str = "sk-ant-ort01-newnewnewnewnewnewnewnewnew";

    fn native(refresh: &str) -> Value {
        serde_json::json!({
            "claudeAiOauth": {
                "accessToken": OLD_ACCESS,
                "refreshToken": refresh,
                "expiresAt": 1_787_687_839_410_i64,
                "refreshTokenExpiresAt": 1_789_790_571_410_i64,
                "scopes": ["user:inference", "user:profile"],
                "subscriptionType": "max",
                "rateLimitTier": "default_claude_max_20x"
            }
        })
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "anthropic-native-publish-{tag}-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_private(path: &Path, contents: &[u8]) {
        std::fs::write(path, contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn native_file(tag: &str, contents: &Value) -> (PathBuf, PathBuf) {
        let dir = temp_dir(tag);
        let path = dir.join(".credentials.json");
        write_private(&path, &serde_json::to_vec(contents).unwrap());
        (dir, path)
    }

    fn rotated() -> OAuthTokens {
        OAuthTokens {
            access: AccessToken::new(NEW_ACCESS),
            refresh: RefreshToken::new(NEW_REFRESH),
            expires_at: Utc.timestamp_millis_opt(1_787_700_000_000).unwrap(),
            refresh_expires_at: Some(Utc.timestamp_millis_opt(1_789_800_000_000).unwrap()),
            scopes: vec!["user:inference".into(), "user:profile".into()],
            account: None,
            organization: None,
        }
    }

    fn spent() -> RefreshToken {
        RefreshToken::new(OLD_REFRESH)
    }

    fn read(path: &Path) -> Value {
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    #[test]
    fn publishes_a_rotation_so_claude_code_stops_holding_a_dead_token() {
        let (dir, path) = native_file("written", &native(OLD_REFRESH));
        assert_eq!(
            publish_native_rotation(&path, &spent(), &rotated()),
            NativePublishOutcome::Written
        );
        let written = read(&path);
        assert_eq!(written["claudeAiOauth"]["accessToken"], NEW_ACCESS);
        assert_eq!(written["claudeAiOauth"]["refreshToken"], NEW_REFRESH);
        assert_eq!(written["claudeAiOauth"]["expiresAt"], 1_787_700_000_000_i64);
        assert_eq!(
            written["claudeAiOauth"]["refreshTokenExpiresAt"],
            1_789_800_000_000_i64
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn preserves_fields_a_refresh_never_returns() {
        let (dir, path) = native_file("login-fields", &native(OLD_REFRESH));
        let mut rotation = rotated();
        rotation.refresh_expires_at = None;
        publish_native_rotation(&path, &spent(), &rotation);
        let written = read(&path);
        assert_eq!(written["claudeAiOauth"]["subscriptionType"], "max");
        assert_eq!(
            written["claudeAiOauth"]["rateLimitTier"],
            "default_claude_max_20x"
        );
        // An omitted refresh expiry keeps the recorded one (as Claude Code does).
        assert_eq!(
            written["claudeAiOauth"]["refreshTokenExpiresAt"],
            1_789_790_571_410_i64
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn preserves_unknown_top_level_keys_the_file_is_claude_codes() {
        let mut document = native(OLD_REFRESH);
        document["somethingElse"] = serde_json::json!({ "keep": true });
        document["mcpOAuth"] = serde_json::json!({ "server": { "token": "x" } });
        let (dir, path) = native_file("unknown-keys", &document);
        assert_eq!(
            publish_native_rotation(&path, &spent(), &rotated()),
            NativePublishOutcome::Written
        );
        let written = read(&path);
        assert_eq!(
            written["somethingElse"],
            serde_json::json!({ "keep": true })
        );
        assert_eq!(written["mcpOAuth"]["server"]["token"], "x");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn keeps_the_file_owner_only_and_leaves_no_temp_or_lock_behind() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, path) = native_file("mode", &native(OLD_REFRESH));
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        publish_native_rotation(&path, &spent(), &rotated());
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        // The directory is Claude Code's: its mode is not changed.
        let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o755);
        let names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec![".credentials.json".to_owned()], "{names:?}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn reports_absent_and_never_creates_the_file() {
        let dir = temp_dir("absent");
        let path = dir.join(".credentials.json");
        assert_eq!(
            publish_native_rotation(&path, &spent(), &rotated()),
            NativePublishOutcome::Absent
        );
        assert!(!path.exists());
        let missing_dir = dir.join("no-such-config");
        assert_eq!(
            publish_native_rotation(&missing_dir.join(".credentials.json"), &spent(), &rotated()),
            NativePublishOutcome::Absent
        );
        assert!(!missing_dir.exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn refuses_to_clobber_a_file_it_cannot_parse() {
        let dir = temp_dir("unparseable");
        let path = dir.join(".credentials.json");
        write_private(&path, b"{ truncated");
        assert_eq!(
            publish_native_rotation(&path, &spent(), &rotated()),
            NativePublishOutcome::Unparseable
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"{ truncated");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn is_a_no_op_when_the_native_copy_already_holds_the_rotation() {
        let (dir, path) = native_file("unchanged", &native(NEW_REFRESH));
        let before = std::fs::read(&path).unwrap();
        let mtime = std::fs::metadata(&path).unwrap().modified().unwrap();
        assert_eq!(
            publish_native_rotation(&path, &spent(), &rotated()),
            NativePublishOutcome::Unchanged
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(std::fs::metadata(&path).unwrap().modified().unwrap(), mtime);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_file_holding_another_token_is_left_alone() {
        let (dir, path) = native_file(
            "not-held",
            &native("sk-ant-ort01-someoneelsesomeoneelse000"),
        );
        let before = std::fs::read(&path).unwrap();
        assert_eq!(
            publish_native_rotation(&path, &spent(), &rotated()),
            NativePublishOutcome::NotHeld
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        // No claudeAiOauth entry at all: nothing to keep in step.
        write_private(&path, br#"{"mcpOAuth":{}}"#);
        assert_eq!(
            publish_native_rotation(&path, &spent(), &rotated()),
            NativePublishOutcome::NotHeld
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_symlinked_credential_file() {
        let (dir, real) = native_file("symlink", &native(OLD_REFRESH));
        let link = dir.join("linked.json");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let before = std::fs::read(&real).unwrap();
        assert!(matches!(
            publish_native_rotation(&link, &spent(), &rotated()),
            NativePublishOutcome::Refused(_)
        ));
        assert_eq!(std::fs::read(&real).unwrap(), before);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn waits_for_claude_codes_write_lock_and_takes_over_a_stale_one() {
        let (dir, path) = native_file("lock", &native(OLD_REFRESH));
        let lock = dir.join(NATIVE_WRITE_LOCK_NAME);
        // A live holder (fresh mtime) that releases shortly: the publish
        // waits for it instead of writing under Claude Code's feet.
        std::fs::create_dir(&lock).unwrap();
        let release = {
            let lock = lock.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(350));
                std::fs::remove_dir(&lock).unwrap();
            })
        };
        let started = std::time::Instant::now();
        assert_eq!(
            publish_native_rotation(&path, &spent(), &rotated()),
            NativePublishOutcome::Written
        );
        assert!(started.elapsed() >= Duration::from_millis(300));
        release.join().unwrap();
        assert!(!lock.exists(), "the publish releases its own lock");

        // An abandoned lock (mtime older than 15 s) is taken over at once.
        write_private(&path, &serde_json::to_vec(&native(OLD_REFRESH)).unwrap());
        std::fs::create_dir(&lock).unwrap();
        let old = std::fs::File::open(&lock).unwrap();
        old.set_modified(SystemTime::now() - Duration::from_secs(60))
            .unwrap();
        let started = std::time::Instant::now();
        assert_eq!(
            publish_native_rotation(&path, &spent(), &rotated()),
            NativePublishOutcome::Written
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(!lock.exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_lock_held_throughout_is_lock_busy_and_writes_nothing() {
        let (dir, path) = native_file("busy", &native(OLD_REFRESH));
        let lock = dir.join(NATIVE_WRITE_LOCK_NAME);
        std::fs::create_dir(&lock).unwrap();
        // Keep the holder's mtime fresh, the way proper-lockfile does.
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let keeper = {
            let (lock, stop) = (lock.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                    if let Ok(dir) = std::fs::File::open(&lock) {
                        let _ = dir.set_modified(SystemTime::now());
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }
            })
        };
        let before = std::fs::read(&path).unwrap();
        assert_eq!(
            publish_native_rotation(&path, &spent(), &rotated()),
            NativePublishOutcome::LockBusy
        );
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        keeper.join().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(lock.exists(), "a foreign live lock is never removed");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn reads_the_credential_claude_code_holds_without_its_tokens() {
        let (dir, path) = native_file("summary", &native(OLD_REFRESH));
        let summary = read_native_claude_summary(Some(&path)).unwrap().unwrap();
        assert_eq!(
            summary.refresh_fingerprint,
            crate::token::token_fingerprint(OLD_REFRESH)
        );
        assert_eq!(summary.expires_at, 1_787_687_839_410);
        assert_eq!(summary.subscription_type.as_deref(), Some("max"));
        let debug = format!("{summary:?}");
        assert!(!debug.contains(OLD_REFRESH) && !debug.contains(OLD_ACCESS));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn summary_is_none_when_absent_and_an_error_when_unreadable() {
        let dir = temp_dir("summary-absent");
        assert!(
            read_native_claude_summary(Some(&dir.join(".credentials.json")))
                .unwrap()
                .is_none()
        );
        let bad = dir.join("bad.json");
        write_private(&bad, b"not json");
        assert!(read_native_claude_summary(Some(&bad)).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn policy_resolution() {
        assert_eq!(NativePublish::from_lookup(|_| None), NativePublish::Auto);
        for off in ["0", "false", "OFF", " no "] {
            assert_eq!(
                NativePublish::from_lookup(|_| Some(off.into())),
                NativePublish::Off,
                "{off:?}"
            );
        }
        for on in ["", "1", "true", "auto", "on"] {
            assert_eq!(
                NativePublish::from_lookup(|_| Some(on.into())),
                NativePublish::Auto,
                "{on:?}"
            );
        }
        // Auto never resolves a path in test mode; an explicit one does.
        assert_eq!(NativePublish::Auto.target(true), None);
        assert_eq!(NativePublish::Off.target(false), None);
        let explicit = PathBuf::from("/tmp/x/.credentials.json");
        assert_eq!(
            NativePublish::At(explicit.clone()).target(true),
            Some(explicit)
        );
    }
}
