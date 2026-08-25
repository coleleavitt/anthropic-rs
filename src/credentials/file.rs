use std::io::Write;
use std::path::{Path, PathBuf};

use crate::credentials::SecretStore;
use crate::error::{Error, Result};

/// Explicit plaintext fallback vault. Secrets are individual `0600` files in a
/// `0700` directory; callers must opt into this backend deliberately.
pub struct FileSecretStore {
    root: PathBuf,
}

impl FileSecretStore {
    /// Create a file-backed vault rooted at `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { root: path.into() }
    }

    fn path(&self, key: &str) -> Result<PathBuf> {
        if key.is_empty()
            || key.len() > 200
            || !key.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.')
            })
        {
            return Err(Error::SecretStore("invalid secret key".into()));
        }
        Ok(self.root.join(key))
    }

    fn prepare_root(&self) -> Result<()> {
        std::fs::create_dir_all(&self.root)?;
        refuse_symlink(&self.root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.root, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
}

impl SecretStore for FileSecretStore {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let path = self.path(key)?;
        match crate::file_security::read_bounded_regular(&path, 1024 * 1024, true, "secret file") {
            Ok(bytes) => Ok(Some(bytes)),
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(Error::Protocol(message)) => Err(Error::SecretStore(message)),
            Err(error) => Err(error),
        }
    }

    fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        if value.len() > 1024 * 1024 {
            return Err(Error::SecretStore("secret exceeds 1 MiB".into()));
        }
        self.prepare_root()?;
        let path = self.path(key)?;
        refuse_symlink_if_present(&path)?;
        let temporary = self
            .root
            .join(format!(".{key}.tmp-{}", uuid::Uuid::new_v4()));
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
            file.write_all(value)?;
            file.sync_all()?;
            Ok(())
        })();
        if let Err(error) = write_result {
            let _ = std::fs::remove_file(&temporary);
            return Err(error);
        }
        if let Err(error) = refuse_symlink_if_present(&path) {
            let _ = std::fs::remove_file(&temporary);
            return Err(error);
        }
        if let Err(error) = std::fs::rename(&temporary, &path) {
            let _ = std::fs::remove_file(&temporary);
            return Err(error.into());
        }
        if let Ok(directory) = std::fs::File::open(&self.root) {
            let _ = directory.sync_all();
        }
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<()> {
        let path = self.path(key)?;
        refuse_symlink_if_present(&path)?;
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_root(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("anthropic-vault-{tag}-{}", uuid::Uuid::new_v4()))
    }

    #[test]
    fn round_trips_and_deletes_secret() {
        let root = temporary_root("round-trip");
        let vault = FileSecretStore::new(&root);
        vault.put("oauth:test", b"secret").unwrap();
        assert_eq!(
            vault.get("oauth:test").unwrap().as_deref(),
            Some(b"secret".as_slice())
        );
        vault.delete("oauth:test").unwrap();
        assert!(vault.get("oauth:test").unwrap().is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn writes_private_files_and_refuses_symlinks_or_public_secrets() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let root = temporary_root("security");
        let vault = FileSecretStore::new(&root);
        vault.put("oauth:test", b"secret").unwrap();
        assert_eq!(
            std::fs::metadata(root.join("oauth:test"))
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );

        std::fs::set_permissions(
            root.join("oauth:test"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(matches!(
            vault.get("oauth:test"),
            Err(Error::SecretStore(_))
        ));

        std::fs::remove_file(root.join("oauth:test")).unwrap();
        let outside = root.join("outside");
        std::fs::write(&outside, b"do not overwrite").unwrap();
        symlink(&outside, root.join("oauth:test")).unwrap();
        assert!(matches!(
            vault.put("oauth:test", b"new"),
            Err(Error::StoreIsSymlink)
        ));
        assert_eq!(std::fs::read(&outside).unwrap(), b"do not overwrite");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_path_traversal_keys() {
        let root = temporary_root("key-validation");
        let vault = FileSecretStore::new(&root);
        assert!(matches!(
            vault.put("../escape", b"secret"),
            Err(Error::SecretStore(_))
        ));
        assert!(!root.parent().unwrap().join("escape").exists());
    }
}
