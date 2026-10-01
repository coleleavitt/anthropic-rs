//! Where Claude Code keeps its OAuth credentials: the plaintext
//! `.credentials.json` ([`CredentialBackend::File`]) or, on macOS, the login
//! Keychain ([`CredentialBackend::Keychain`]).
//!
//! EVIDENCED (Claude Code 2.1.286, `@anthropic-ai/claude-code-darwin-arm64`
//! bundle; the 2.0.29 / 2.1.36 `cli.js` agree): on macOS the secure storage
//! is `keychain` with a `plaintext` fallback (`zn() → b(I, w)`). The
//! Keychain item is a generic password with
//!
//! - **service** `QN("-credentials")` = `` `Claude Code${OAUTH_FILE_SUFFIX}-credentials${suffix}` ``,
//!   where `OAUTH_FILE_SUFFIX` is `""` for production and `suffix` is
//!   `-<first 8 hex of sha256(dir)>` when `CLAUDE_CONFIG_DIR` (or a non-empty
//!   `CLAUDE_SECURESTORAGE_CONFIG_DIR`) names a custom directory, else empty
//!   ([`native_claude_credentials_keychain_service`]);
//! - **account** `ok()` = `process.env.USER || os.userInfo().username`,
//!   `claude-code-user` when that is not `/^[a-zA-Z0-9._-]+$/`
//!   ([`super::native_claude_keyring_account`]);
//! - **data** the same JSON document as `.credentials.json`
//!   (`{"claudeAiOauth": {...}, ...}`).
//!
//! Claude Code reads it with `security find-generic-password -a <account>
//! -w -s <service>` (2 s timeout; exit 44 = no item, 36 = keychain locked /
//! interaction not allowed) and writes it with `security -i`, feeding
//! `add-generic-password -U -a "<account>" -s "<service>" -X "<hex>"` on
//! stdin (argv `-X <hex>` only when that line exceeds 4032 bytes). Every
//! read-modify-write runs under the same `<config dir>/.storage-write.lock`
//! as the file backend, so the locking here is unchanged.
//!
//! This module does the same through `/usr/bin/security` (or
//! [`SECURITY_BIN_ENV`]). The secret never goes on argv for a document under
//! the 4032-byte stdin limit (a Claude Code document is about 600 bytes);
//! above it the hex-encoded document is passed as `-X <hex>`, exactly as
//! Claude Code does, and is then visible to same-user process listings for
//! the lifetime of the `security` call. Claude Code itself creates the item
//! through `security`, so the item's access list already trusts that binary
//! and a read does not raise a Keychain dialog (INFERRED from macOS ACL
//! behaviour: the creating application is on the item's trusted list).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use super::link::ClaudeCodeFiles;

/// Selects Claude Code's credential backend: `file`, `keychain`, or `auto`
/// (unset or empty is `auto`: the Keychain on macOS when there is no
/// `.credentials.json`, else the file).
pub const CREDENTIALS_BACKEND_ENV: &str = "ANTHROPIC_CLAUDE_CREDENTIALS_BACKEND";

/// The `security` binary for the Keychain backend (tests point it at a
/// fake). Default [`DEFAULT_SECURITY_BIN`].
pub const SECURITY_BIN_ENV: &str = "ANTHROPIC_SECURITY_BIN";

/// macOS's `security` tool.
pub const DEFAULT_SECURITY_BIN: &str = "/usr/bin/security";

/// Claude Code's Keychain service for OAuth credentials, before the custom
/// config-dir suffix.
pub const NATIVE_CLAUDE_CREDENTIALS_KEYCHAIN_SERVICE: &str = "Claude Code-credentials";

/// Claude Code's own `security` timeout (2 s).
const SECURITY_TIMEOUT: Duration = Duration::from_secs(2);
/// Claude Code's limit for an `add-generic-password` line on `security -i`.
const SECURITY_STDIN_LIMIT: usize = 4032;
/// `errSecItemNotFound`.
const EXIT_ITEM_NOT_FOUND: i32 = 44;
/// `errSecInteractionNotAllowed` (the keychain is locked).
const EXIT_INTERACTION_NOT_ALLOWED: i32 = 36;
const MAX_DOCUMENT_BYTES: usize = 64 * 1024;

/// Where Claude Code keeps its credentials.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum CredentialBackend {
    /// `<config dir>/.credentials.json` (Linux, Windows, and macOS when the
    /// Keychain is unavailable).
    #[default]
    File,
    /// A generic-password item in the macOS login Keychain.
    Keychain(KeychainItem),
}

/// The Keychain item Claude Code stores its credentials in, and the
/// `security` binary used to reach it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeychainItem {
    /// Generic-password service (`Claude Code-credentials[-<sha8>]`).
    pub service: String,
    /// Generic-password account (the login user name).
    pub account: String,
    /// The `security` binary.
    pub security: PathBuf,
}

impl KeychainItem {
    /// Claude Code's item for an environment lookup, reached through
    /// [`SECURITY_BIN_ENV`] or [`DEFAULT_SECURITY_BIN`].
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        Self {
            service: native_claude_credentials_keychain_service_from_lookup(&lookup),
            account: keychain_account_from_lookup(&lookup),
            security: lookup(SECURITY_BIN_ENV)
                .filter(|v| !v.trim().is_empty())
                .map_or_else(|| PathBuf::from(DEFAULT_SECURITY_BIN), PathBuf::from),
        }
    }
}

impl CredentialBackend {
    /// A stable code: `file` or `keychain`.
    pub fn code(&self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Keychain(_) => "keychain",
        }
    }

    /// The backend Claude Code uses for `credentials` (its
    /// `.credentials.json` path), from an environment lookup:
    /// [`CREDENTIALS_BACKEND_ENV`] when it says `file` or `keychain`;
    /// otherwise the Keychain on macOS when `credentials` does not exist
    /// (Claude Code writes the file only when the Keychain write fails),
    /// else the file.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>, credentials: &Path) -> Self {
        if let Some(explicit) = Self::explicit_from_lookup(&lookup) {
            return explicit;
        }
        let file_present = std::fs::symlink_metadata(credentials).is_ok();
        if cfg!(target_os = "macos") && !file_present {
            Self::Keychain(KeychainItem::from_lookup(&lookup))
        } else {
            Self::File
        }
    }

    /// Only an explicit [`CREDENTIALS_BACKEND_ENV`] (`file` / `keychain`);
    /// `None` for unset, empty or `auto`.
    pub fn explicit_from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Option<Self> {
        let value = lookup(CREDENTIALS_BACKEND_ENV)?;
        match value.trim().to_ascii_lowercase().as_str() {
            "file" => Some(Self::File),
            "keychain" => Some(Self::Keychain(KeychainItem::from_lookup(&lookup))),
            _ => None,
        }
    }
}

/// Claude Code's Keychain service for its OAuth credentials, from the
/// process environment ([`native_claude_credentials_keychain_service_from_lookup`]).
pub fn native_claude_credentials_keychain_service() -> String {
    native_claude_credentials_keychain_service_from_lookup(|key| std::env::var(key).ok())
}

/// `Claude Code-credentials`, plus `-<first 8 hex of sha256(NFC dir)>` when
/// a custom directory is configured: a set `CLAUDE_SECURESTORAGE_CONFIG_DIR`
/// (empty means the default, unsuffixed), else a non-empty
/// `CLAUDE_CONFIG_DIR`. Same derivation as Claude Code's `QN("-credentials")`.
pub fn native_claude_credentials_keychain_service_from_lookup(
    lookup: impl Fn(&str) -> Option<String>,
) -> String {
    let custom = match lookup("CLAUDE_SECURESTORAGE_CONFIG_DIR") {
        Some(value) if value.is_empty() => None,
        Some(value) => Some(value),
        None => lookup("CLAUDE_CONFIG_DIR").filter(|v| !v.is_empty()),
    };
    match custom {
        None => NATIVE_CLAUDE_CREDENTIALS_KEYCHAIN_SERVICE.to_owned(),
        Some(directory) => {
            let normalized = directory.nfc().collect::<String>();
            let digest = Sha256::digest(normalized.as_bytes());
            let suffix: String = digest[..4].iter().map(|b| format!("{b:02x}")).collect();
            format!("{NATIVE_CLAUDE_CREDENTIALS_KEYCHAIN_SERVICE}-{suffix}")
        }
    }
}

/// `$USER` (else `$USERNAME`) when it is `[A-Za-z0-9._-]+`, else
/// `claude-code-user`, as Claude Code's `ok()`.
fn keychain_account_from_lookup(lookup: impl Fn(&str) -> Option<String>) -> String {
    let candidate = lookup("USER")
        .filter(|v| !v.is_empty())
        .or_else(|| lookup("USERNAME").filter(|v| !v.is_empty()));
    match candidate {
        Some(name) if safe_keychain_name(&name) => name,
        _ => "claude-code-user".to_owned(),
    }
}

fn safe_keychain_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Whether the login Keychain is locked, probed with `security
/// show-keychain-info` (no UI; exit 36 = locked / interaction not allowed,
/// the probe Claude Code itself uses before writing). A caller that must
/// never raise an unlock dialog (a read-only diagnosis) checks this before
/// reading the item. `false` when `security` cannot tell.
pub fn keychain_is_locked(item: &KeychainItem) -> bool {
    run_security(&item.security, &["show-keychain-info"], None)
        .is_ok_and(|run| run.code == Some(EXIT_INTERACTION_NOT_ALLOWED))
}

/// One raw read of Claude Code's credential document.
#[derive(Debug)]
pub(crate) enum NativeRaw {
    /// The document bytes.
    Present(Vec<u8>),
    /// No credential (no file, no Keychain item).
    Absent,
    /// The source exists but is never used: a symlink, not a regular file,
    /// group/world readable (strict reads), or oversized.
    Refused(&'static str),
    /// It could not be read right now: an I/O error, the Keychain is
    /// locked, `security` failed or timed out. Transient.
    Unavailable(String),
}

/// Read Claude Code's credential document through the backend of `files`.
/// `strict` also refuses a group/world-accessible file (the import rule).
pub(crate) fn read_raw(files: &ClaudeCodeFiles, strict: bool) -> NativeRaw {
    match &files.backend {
        CredentialBackend::File => read_file(&files.credentials, strict),
        CredentialBackend::Keychain(item) => read_keychain(item),
    }
}

/// Replace Claude Code's credential document through the backend of
/// `files`. The caller holds Claude Code's write lock and has just read the
/// document (it exists). The error is secret-free.
pub(crate) fn write_raw(files: &ClaudeCodeFiles, bytes: &[u8]) -> Result<(), String> {
    match &files.backend {
        CredentialBackend::File => super::publish::write_replace_private(&files.credentials, bytes)
            .map_err(|error| {
                crate::token::redact_secrets(&format!("native credential file: {error}"))
            }),
        CredentialBackend::Keychain(item) => write_keychain(item, bytes),
    }
}

fn read_file(path: &Path, strict: bool) -> NativeRaw {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return NativeRaw::Absent,
        Err(error) => return NativeRaw::Unavailable(format!("native credential file: {error}")),
        Ok(meta) if meta.file_type().is_symlink() => {
            return NativeRaw::Refused("the native credential file is a symlink");
        }
        Ok(meta) if !meta.is_file() => {
            return NativeRaw::Refused("the native credential file is not a regular file");
        }
        Ok(_) => {}
    }
    match crate::file_security::read_bounded_regular(
        path,
        MAX_DOCUMENT_BYTES as u64,
        strict,
        "native credential file",
    ) {
        Ok(raw) => NativeRaw::Present(raw),
        Err(crate::Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            NativeRaw::Absent
        }
        Err(crate::Error::StoreIsSymlink) => {
            NativeRaw::Refused("the native credential file is a symlink")
        }
        Err(crate::Error::Protocol(_)) => NativeRaw::Refused(
            "the native credential file is not a private regular file or exceeds 64 KiB",
        ),
        Err(error) => NativeRaw::Unavailable(crate::token::redact_secrets(&error.to_string())),
    }
}

fn read_keychain(item: &KeychainItem) -> NativeRaw {
    let args = [
        "find-generic-password",
        "-a",
        item.account.as_str(),
        "-w",
        "-s",
        item.service.as_str(),
    ];
    match run_security(&item.security, &args, None) {
        Err(reason) => NativeRaw::Unavailable(reason),
        Ok(run) if run.code == Some(0) => {
            let text = String::from_utf8_lossy(&run.stdout);
            let text = text.trim();
            if text.is_empty() {
                return NativeRaw::Absent;
            }
            // `-w` prints the data as text, or as hex when it is not
            // printable.
            if text.starts_with('{') {
                NativeRaw::Present(text.as_bytes().to_vec())
            } else if let Some(decoded) = decode_hex(text) {
                NativeRaw::Present(decoded)
            } else {
                NativeRaw::Present(text.as_bytes().to_vec())
            }
        }
        Ok(run) if run.code == Some(EXIT_ITEM_NOT_FOUND) => NativeRaw::Absent,
        Ok(run) if run.code == Some(EXIT_INTERACTION_NOT_ALLOWED) => {
            NativeRaw::Unavailable("the macOS keychain is locked (security exited 36)".to_owned())
        }
        Ok(run) => NativeRaw::Unavailable(match run.code {
            Some(code) => format!("security exited {code}"),
            None => "security was killed by a signal".to_owned(),
        }),
    }
}

fn write_keychain(item: &KeychainItem, bytes: &[u8]) -> Result<(), String> {
    // Both names are interpolated into a `security -i` command line.
    if !safe_keychain_name(&item.account)
        || item.service.is_empty()
        || item
            .service
            .chars()
            .any(|c| c == '"' || c == '\\' || c.is_control())
    {
        return Err("refusing an unsafe keychain service or account name".to_owned());
    }
    let hex = encode_hex(bytes);
    let line = format!(
        "add-generic-password -U -a \"{}\" -s \"{}\" -X \"{hex}\"\n",
        item.account, item.service
    );
    let run = if line.len() <= SECURITY_STDIN_LIMIT {
        run_security(&item.security, &["-i"], Some(line.as_bytes()))?
    } else {
        // Claude Code's fallback for an oversized document: the hex form on
        // argv (visible to same-user process listings while it runs).
        run_security(
            &item.security,
            &[
                "add-generic-password",
                "-U",
                "-a",
                item.account.as_str(),
                "-s",
                item.service.as_str(),
                "-X",
                hex.as_str(),
            ],
            None,
        )?
    };
    match run.code {
        Some(0) => Ok(()),
        Some(EXIT_INTERACTION_NOT_ALLOWED) => {
            Err("the macOS keychain is locked (security exited 36)".to_owned())
        }
        Some(code) => Err(format!("security exited {code}")),
        None => Err("security was killed by a signal".to_owned()),
    }
}

struct SecurityRun {
    code: Option<i32>,
    stdout: Vec<u8>,
}

/// Run `security` with no UI-bearing stdin, bounded by Claude Code's 2 s
/// timeout (killed after). Stderr is discarded: it can echo the command.
fn run_security(bin: &Path, args: &[&str], stdin: Option<&[u8]>) -> Result<SecurityRun, String> {
    let mut child = Command::new(bin)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("could not run security: {}", error.kind()))?;
    if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take()) {
        let _ = pipe.write_all(input);
    }
    let reader = child.stdout.take().map(|stdout| {
        std::thread::spawn(move || {
            let mut out = Vec::new();
            let _ = stdout
                .take(MAX_DOCUMENT_BYTES as u64 * 2 + 1)
                .read_to_end(&mut out);
            out
        })
    });
    let deadline = Instant::now() + SECURITY_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("security timed out".to_owned());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(error) => return Err(format!("security wait failed: {}", error.kind())),
        }
    };
    let stdout = reader
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default();
    if stdout.len() > MAX_DOCUMENT_BYTES * 2 {
        return Err("security returned an oversized item".to_owned());
    }
    Ok(SecurityRun {
        code: status.code(),
        stdout,
    })
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A fake `security` (python3) over a JSON file of
    /// `{"<service>\u0000<account>": "<data>"}`. Supports
    /// `find-generic-password -a A -w -s S`, `add-generic-password -U -a A
    /// -s S -X HEX` (argv or one `security -i` stdin line) and logs every
    /// argv to `<dir>/argv.log`. `<dir>/mode` set to `locked`, `fail` or
    /// `hang` makes every call exit 36, exit 1, or sleep past the timeout.
    pub(crate) fn fake_security(dir: &Path) -> PathBuf {
        let script = dir.join("fake-security");
        let source = r#"#!/usr/bin/env python3
import json, os, shlex, sys, time
here = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(here, "keychain.json")
with open(os.path.join(here, "argv.log"), "a") as log:
    log.write(json.dumps(sys.argv[1:]) + "\n")
mode = ""
try:
    mode = open(os.path.join(here, "mode")).read().strip()
except OSError:
    pass
if mode == "locked":
    sys.exit(36)
if mode == "fail":
    sys.exit(1)
if mode == "hang":
    time.sleep(10)
    sys.exit(0)
def load():
    try:
        return json.load(open(db_path))
    except OSError:
        return {}
def opts(args):
    out, i = {}, 0
    while i < len(args):
        a = args[i]
        if a in ("-a", "-s", "-X"):
            out[a] = args[i + 1]; i += 2
        else:
            out[a] = True; i += 1
    return out
def run(args):
    cmd, o = args[0], opts(args[1:])
    if cmd == "show-keychain-info":
        return 0
    key = o.get("-s", "") + "\u0000" + o.get("-a", "")
    db = load()
    if cmd == "find-generic-password":
        if key not in db:
            return 44
        sys.stdout.write(db[key] + "\n")
        return 0
    if cmd == "add-generic-password":
        if key in db and "-U" not in o:
            return 45
        db[key] = bytes.fromhex(o["-X"]).decode("utf-8")
        tmp = db_path + ".tmp"
        json.dump(db, open(tmp, "w"))
        os.replace(tmp, db_path)
        return 0
    return 2
args = sys.argv[1:]
if args == ["-i"]:
    code = 0
    for line in sys.stdin.read().splitlines():
        if line.strip():
            code = run(shlex.split(line)) or code
    sys.exit(code)
sys.exit(run(args))
"#;
        std::fs::write(&script, source).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        script
    }

    /// Seed the fake Keychain with `data` for `item`.
    pub(crate) fn seed(dir: &Path, item: &KeychainItem, data: &str) {
        let path = dir.join("keychain.json");
        let mut db: serde_json::Map<String, serde_json::Value> = std::fs::read(&path)
            .ok()
            .and_then(|raw| serde_json::from_slice(&raw).ok())
            .unwrap_or_default();
        db.insert(
            format!("{}\u{0}{}", item.service, item.account),
            serde_json::Value::String(data.to_owned()),
        );
        std::fs::write(&path, serde_json::to_vec(&db).unwrap()).unwrap();
    }

    /// The fake Keychain's data for `item`.
    pub(crate) fn stored(dir: &Path, item: &KeychainItem) -> Option<String> {
        let db: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("keychain.json")).ok()?).ok()?;
        db[format!("{}\u{0}{}", item.service, item.account)]
            .as_str()
            .map(str::to_owned)
    }

    pub(crate) fn item(dir: &Path) -> KeychainItem {
        KeychainItem {
            service: NATIVE_CLAUDE_CREDENTIALS_KEYCHAIN_SERVICE.to_owned(),
            account: "tester".to_owned(),
            security: fake_security(dir),
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "anthropic-keychain-{tag}-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn keychain_files(dir: &Path, item: &KeychainItem) -> ClaudeCodeFiles {
        ClaudeCodeFiles::for_credentials(&dir.join(".credentials.json"))
            .with_backend(CredentialBackend::Keychain(item.clone()))
    }

    #[test]
    fn service_and_account_derive_like_claude_code() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |key: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == key)
                    .map(|(_, v)| (*v).to_owned())
            }
        };
        assert_eq!(
            native_claude_credentials_keychain_service_from_lookup(env(&[])),
            "Claude Code-credentials"
        );
        let expected = {
            let digest = Sha256::digest(b"/tmp/cc");
            format!(
                "Claude Code-credentials-{}",
                digest[..4]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            )
        };
        assert_eq!(
            native_claude_credentials_keychain_service_from_lookup(env(&[(
                "CLAUDE_CONFIG_DIR",
                "/tmp/cc"
            )])),
            expected
        );
        // An empty CLAUDE_SECURESTORAGE_CONFIG_DIR means the default dir.
        assert_eq!(
            native_claude_credentials_keychain_service_from_lookup(env(&[
                ("CLAUDE_SECURESTORAGE_CONFIG_DIR", ""),
                ("CLAUDE_CONFIG_DIR", "/tmp/cc")
            ])),
            "Claude Code-credentials"
        );
        assert_eq!(
            native_claude_credentials_keychain_service_from_lookup(env(&[(
                "CLAUDE_SECURESTORAGE_CONFIG_DIR",
                "/tmp/cc"
            )])),
            expected
        );
        assert_eq!(
            keychain_account_from_lookup(env(&[("USER", "cole")])),
            "cole"
        );
        assert_eq!(
            keychain_account_from_lookup(env(&[("USER", "bad name")])),
            "claude-code-user"
        );
        assert_eq!(keychain_account_from_lookup(env(&[])), "claude-code-user");
    }

    #[test]
    fn backend_selection_and_override() {
        let dir = temp_dir("select");
        let credentials = dir.join(".credentials.json");
        let keychain = |key: &str| match key {
            CREDENTIALS_BACKEND_ENV => Some("keychain".to_owned()),
            SECURITY_BIN_ENV => Some("/tmp/fake-security".to_owned()),
            "USER" => Some("tester".to_owned()),
            _ => None,
        };
        match CredentialBackend::from_lookup(keychain, &credentials) {
            CredentialBackend::Keychain(item) => {
                assert_eq!(item.security, PathBuf::from("/tmp/fake-security"));
                assert_eq!(item.account, "tester");
                assert_eq!(item.service, "Claude Code-credentials");
            }
            other => panic!("{other:?}"),
        }
        let file = |key: &str| (key == CREDENTIALS_BACKEND_ENV).then(|| "file".to_owned());
        assert_eq!(
            CredentialBackend::from_lookup(file, &credentials),
            CredentialBackend::File
        );
        // Auto: the file off macOS; on macOS the Keychain unless the file
        // exists.
        let auto = CredentialBackend::from_lookup(|_| None, &credentials);
        assert_eq!(
            auto.code(),
            if cfg!(target_os = "macos") {
                "keychain"
            } else {
                "file"
            }
        );
        std::fs::write(&credentials, b"{}").unwrap();
        assert_eq!(
            CredentialBackend::from_lookup(|_| None, &credentials),
            CredentialBackend::File
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn reads_an_item_absent_and_failure_modes() {
        let dir = temp_dir("read");
        let item = item(&dir);
        let files = keychain_files(&dir, &item);
        assert!(matches!(read_raw(&files, true), NativeRaw::Absent));
        seed(&dir, &item, r#"{"claudeAiOauth":{"accessToken":"a"}}"#);
        match read_raw(&files, true) {
            NativeRaw::Present(raw) => {
                assert_eq!(raw, br#"{"claudeAiOauth":{"accessToken":"a"}}"#);
            }
            other => panic!("{other:?}"),
        }
        // Another account's item is not this one.
        let other = KeychainItem {
            account: "someone-else".into(),
            ..item.clone()
        };
        assert!(matches!(
            read_raw(&keychain_files(&dir, &other), true),
            NativeRaw::Absent
        ));
        for (mode, expect) in [
            ("locked", "locked"),
            ("fail", "exited 1"),
            ("hang", "timed out"),
        ] {
            std::fs::write(dir.join("mode"), mode).unwrap();
            let started = Instant::now();
            match read_raw(&files, true) {
                NativeRaw::Unavailable(reason) => assert!(reason.contains(expect), "{reason}"),
                other => panic!("{mode}: {other:?}"),
            }
            assert!(started.elapsed() < Duration::from_secs(5));
        }
        std::fs::remove_file(dir.join("mode")).unwrap();
        // A missing binary is a transient failure, never "absent".
        let missing = keychain_files(
            &dir,
            &KeychainItem {
                security: dir.join("no-such-security"),
                ..item
            },
        );
        assert!(matches!(
            read_raw(&missing, true),
            NativeRaw::Unavailable(_)
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn writes_over_stdin_never_argv() {
        let dir = temp_dir("write");
        let item = item(&dir);
        let files = keychain_files(&dir, &item);
        let secret = r#"{"claudeAiOauth":{"refreshToken":"sk-ant-ort01-secretsecret"}}"#;
        write_raw(&files, secret.as_bytes()).unwrap();
        assert_eq!(stored(&dir, &item).as_deref(), Some(secret));
        let argv = std::fs::read_to_string(dir.join("argv.log")).unwrap();
        assert_eq!(argv.trim(), r#"["-i"]"#, "the document never goes on argv");
        assert!(!argv.contains("sk-ant") && !argv.contains(&encode_hex(secret.as_bytes())));
        // An oversized document falls back to argv `-X <hex>`, like Claude
        // Code (documented exposure).
        let big = format!(r#"{{"pad":"{}"}}"#, "x".repeat(SECURITY_STDIN_LIMIT));
        write_raw(&files, big.as_bytes()).unwrap();
        assert_eq!(stored(&dir, &item).as_deref(), Some(big.as_str()));
        // Failures are errors, never silent.
        std::fs::write(dir.join("mode"), "locked").unwrap();
        assert!(write_raw(&files, b"{}").unwrap_err().contains("locked"));
        std::fs::write(dir.join("mode"), "fail").unwrap();
        assert!(write_raw(&files, b"{}").is_err());
        // Unsafe names are refused before anything runs.
        let unsafe_files = keychain_files(
            &dir,
            &KeychainItem {
                service: "x\" -s \"y".into(),
                ..item
            },
        );
        assert!(write_raw(&unsafe_files, b"{}").is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn hex_round_trip() {
        assert_eq!(decode_hex(&encode_hex(b"{\"a\":1}")).unwrap(), b"{\"a\":1}");
        assert!(decode_hex("abc").is_none());
        assert!(decode_hex("zz").is_none());
    }
}
