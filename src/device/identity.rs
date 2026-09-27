use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use p256::elliptic_curve::rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::store::store_dir;

const DEVICE_DOCUMENT_MAX_BYTES: u64 = 16 * 1024;
const LOCK_WAIT: Duration = Duration::from_secs(12);

/// Native-compatible 32-byte global device identifier rendered as 64 hex characters.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeviceId(String);

impl DeviceId {
    /// Generate a fresh identifier with the operating-system CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
    }

    /// Parse a canonical 64-character lowercase hexadecimal identifier.
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(Error::Protocol(
                "device id must be 64 lowercase hex characters".into(),
            ));
        }
        Ok(Self(value))
    }

    /// Read the wire representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The per-account Claude Code device id derived from this installation
    /// secret (merged anthropic-auth: `sha256_hex(secret + "\0" + cache_key)`,
    /// see [`crate::claude_code::derive_claude_code_device_id`]). The
    /// installation id itself is never sent as a device id, so distinct
    /// accounts never share one.
    pub fn account_device_id(&self, cache_key: &str) -> String {
        crate::claude_code::derive_claude_code_device_id(&self.0, cache_key)
    }
}

impl std::fmt::Debug for DeviceId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_tuple("DeviceId").field(&self.0).finish()
    }
}

#[derive(Serialize, Deserialize)]
struct DeviceDocument {
    version: u32,
    device_id: DeviceId,
}

/// Atomic persistent device ID store, separate from account credentials.
pub struct DeviceIdentityStore {
    path: PathBuf,
}

impl DeviceIdentityStore {
    /// Default `~/.anthropic-accounts/device.json` location.
    pub fn default_path() -> PathBuf {
        store_dir().join("device.json")
    }

    /// Store at an explicit path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Read the existing ID or generate and atomically persist one. Concurrent
    /// creators serialize through a sibling lock file and observe one result.
    pub fn load_or_create(&self) -> Result<DeviceId> {
        let _lock = DeviceLock::acquire(&self.path, LOCK_WAIT)?;
        match std::fs::symlink_metadata(&self.path) {
            Ok(_) => read_document(&self.path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let device_id = DeviceId::generate();
                write_document(&self.path, &device_id)?;
                Ok(device_id)
            }
            Err(error) => Err(error.into()),
        }
    }
}

fn read_document(path: &Path) -> Result<DeviceId> {
    let bytes = crate::file_security::read_bounded_regular(
        path,
        DEVICE_DOCUMENT_MAX_BYTES,
        true,
        "device identity document",
    )?;
    let document: DeviceDocument =
        crate::file_security::parse_json_redacted(&bytes, "device identity document")?;
    if document.version != 1 {
        return Err(Error::Protocol(format!(
            "unsupported device identity version {}",
            document.version
        )));
    }
    DeviceId::parse(document.device_id.0)
}

fn write_document(path: &Path, device_id: &DeviceId) -> Result<()> {
    refuse_symlink_if_present(path)?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    refuse_symlink(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("device.json");
    let temporary = parent.join(format!(".{file_name}.tmp-{}", uuid::Uuid::new_v4()));
    let body = serde_json::to_vec_pretty(&DeviceDocument {
        version: 1,
        device_id: device_id.clone(),
    })?;
    let write_result = (|| -> Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(&body)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(error) = write_result {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = refuse_symlink_if_present(path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error.into());
    }
    if let Ok(directory) = std::fs::File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(())
}

fn refuse_symlink(path: &Path) -> Result<()> {
    if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(Error::StoreIsSymlink);
    }
    Ok(())
}

fn refuse_symlink_if_present(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(Error::StoreIsSymlink),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

struct DeviceLock {
    advisory_file: std::fs::File,
    lease_path: PathBuf,
    owner_id: String,
    heartbeat_stop: Option<std::sync::mpsc::Sender<()>>,
    heartbeat: Option<std::thread::JoinHandle<()>>,
}

impl DeviceLock {
    fn acquire(target: &Path, wait: Duration) -> Result<Self> {
        const LEASE_MS: u128 = 30_000;
        const STALE_HEARTBEAT_MS: u128 = 10_000;

        let lease_path = target.with_extension("json.lock");
        let advisory_path = target.with_extension("json.flock");
        let parent = lease_path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)?;
        refuse_symlink(parent)?;
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            advisory_file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        let deadline = Instant::now() + wait;
        loop {
            match fs2::FileExt::try_lock_exclusive(&advisory_file) {
                Ok(()) => break,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(Error::Protocol(
                            "timed out waiting for device identity lock".into(),
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(error) => return Err(error.into()),
            }
        }

        let owner_id = uuid::Uuid::new_v4().to_string();
        loop {
            let now = device_unix_time_millis();
            let body = format!(
                "{{\"version\":1,\"ownerId\":\"{owner_id}\",\"pid\":{},\"expiresAt\":{}}}\n",
                std::process::id(),
                now.saturating_add(LEASE_MS)
            );
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lease_path)
            {
                Ok(mut lease) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        lease.set_permissions(std::fs::Permissions::from_mode(0o600))?;
                    }
                    lease.write_all(body.as_bytes())?;
                    lease.sync_all()?;
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if device_lease_is_stale(&lease_path, now, STALE_HEARTBEAT_MS) {
                        let stale = lease_path.with_extension(format!("lock.stale-{owner_id}"));
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
                            "timed out waiting for device identity lease".into(),
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(error) => return Err(error.into()),
            }
        }
        let (heartbeat_stop, heartbeat) =
            start_device_lease_heartbeat(lease_path.clone(), owner_id.clone());
        Ok(Self {
            advisory_file,
            lease_path,
            owner_id,
            heartbeat_stop: Some(heartbeat_stop),
            heartbeat: Some(heartbeat),
        })
    }
}

fn device_unix_time_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}

fn device_lease_owner(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|body| serde_json::from_str::<serde_json::Value>(&body).ok())
        .and_then(|value| value.get("ownerId")?.as_str().map(str::to_owned))
}

fn start_device_lease_heartbeat(
    path: PathBuf,
    owner_id: String,
) -> (std::sync::mpsc::Sender<()>, std::thread::JoinHandle<()>) {
    let (stop, stopped) = std::sync::mpsc::channel();
    let heartbeat = std::thread::spawn(move || {
        loop {
            match stopped.recv_timeout(Duration::from_secs(3)) {
                Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if device_lease_owner(&path).as_deref() != Some(owner_id.as_str()) {
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

fn device_lease_is_stale(path: &Path, now: u128, lease_ms: u128) -> bool {
    let expires = std::fs::read_to_string(path)
        .ok()
        .and_then(|body| serde_json::from_str::<serde_json::Value>(&body).ok())
        .and_then(|value| value.get("expiresAt")?.as_u64())
        .map(u128::from);
    let old_heartbeat = std::fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| modified.elapsed().ok())
        .is_some_and(|age| age.as_millis() >= lease_ms);
    match expires {
        Some(expires) => expires <= now && old_heartbeat,
        None => old_heartbeat,
    }
}

impl Drop for DeviceLock {
    fn drop(&mut self) {
        if let Some(stop) = self.heartbeat_stop.take() {
            let _ = stop.send(());
        }
        if let Some(heartbeat) = self.heartbeat.take() {
            let _ = heartbeat.join();
        }
        if device_lease_owner(&self.lease_path).as_deref() == Some(self.owner_id.as_str()) {
            let _ = std::fs::remove_file(&self.lease_path);
        }
        let _ = fs2::FileExt::unlock(&self.advisory_file);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_directory(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("anthropic-device-{tag}-{}", uuid::Uuid::new_v4()))
    }

    #[test]
    fn persists_one_stable_32_byte_device_id() {
        let root = temporary_directory("stable");
        let store = DeviceIdentityStore::new(root.join("device.json"));
        let first = store.load_or_create().unwrap();
        let second = store.load_or_create().unwrap();
        assert_eq!(first, second);
        assert_eq!(first.as_str().len(), 64);
        let _ = std::fs::remove_dir_all(root);
    }

    /// Per-account ids survive a restart (re-load) and differ per account.
    #[test]
    fn account_device_ids_are_stable_across_restarts_and_distinct() {
        let root = temporary_directory("per-account");
        let path = root.join("device.json");
        let first = DeviceIdentityStore::new(&path).load_or_create().unwrap();
        let reloaded = DeviceIdentityStore::new(&path).load_or_create().unwrap();
        let a = first.account_device_id("identity:acct-a");
        assert_eq!(a, reloaded.account_device_id("identity:acct-a"));
        assert_ne!(a, first.account_device_id("identity:acct-b"));
        assert_ne!(a, first.as_str());
        // Merged-TS Bun vector for a fixed secret.
        let fixed = DeviceId::parse("a".repeat(64)).unwrap();
        assert_eq!(
            fixed.account_device_id("identity:acct-1"),
            "402cc9d2902492a43d1c3e3e52b43843fc2cd9a57d057dcd8660e80da6293435"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn concurrent_creators_observe_one_identity() {
        let root = temporary_directory("concurrent");
        let path = root.join("device.json");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    DeviceIdentityStore::new(path).load_or_create().unwrap()
                })
            })
            .collect();
        let identities: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert!(identities.iter().all(|id| id == &identities[0]));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn stale_cross_language_lease_is_recovered() {
        let root = temporary_directory("stale-lock");
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("device.json");
        let lock_path = path.with_extension("json.lock");
        std::fs::write(
            &lock_path,
            r#"{"version":1,"ownerId":"abandoned","expiresAt":0}"#,
        )
        .unwrap();
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&lock_path)
            .unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(std::time::SystemTime::UNIX_EPOCH))
            .unwrap();
        let id = DeviceIdentityStore::new(&path).load_or_create().unwrap();
        assert_eq!(id.as_str().len(), 64);
        assert!(!lock_path.exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn malformed_stale_cross_language_lease_is_recovered() {
        let root = temporary_directory("malformed-stale-lock");
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("device.json");
        let lock_path = path.with_extension("json.lock");
        std::fs::write(&lock_path, "").unwrap();
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&lock_path)
            .unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(std::time::SystemTime::UNIX_EPOCH))
            .unwrap();
        DeviceIdentityStore::new(&path).load_or_create().unwrap();
        assert!(!lock_path.exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_identity_and_writes_private_permissions() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let root = temporary_directory("symlink");
        std::fs::create_dir_all(&root).unwrap();
        let real = root.join("real.json");
        std::fs::write(
            &real,
            r#"{"version":1,"device_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
        )
        .unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = root.join("device.json");
        symlink(&real, &link).unwrap();
        assert!(matches!(
            DeviceIdentityStore::new(&link).load_or_create(),
            Err(Error::StoreIsSymlink)
        ));
        std::fs::remove_file(&link).unwrap();

        DeviceIdentityStore::new(&link).load_or_create().unwrap();
        let mode = std::fs::metadata(&link).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0);
        let _ = std::fs::remove_dir_all(root);
    }
}
