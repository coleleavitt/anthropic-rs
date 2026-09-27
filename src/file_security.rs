//! Descriptor-based bounded reads for private state files.

use std::io::Read;
use std::path::Path;

use crate::error::{Error, Result};

pub(crate) fn read_bounded_regular(
    path: &Path,
    maximum_bytes: u64,
    require_private_permissions: bool,
    label: &'static str,
) -> Result<Vec<u8>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if is_symlink_loop(&error) => return Err(Error::StoreIsSymlink),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(Error::Protocol(format!("{label} is not a regular file")));
    }
    if metadata.len() > maximum_bytes {
        return Err(Error::Protocol(format!("{label} exceeds its size limit")));
    }
    #[cfg(unix)]
    if require_private_permissions {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::Protocol(format!(
                "{label} must not be group/world accessible"
            )));
        }
    }
    #[cfg(not(unix))]
    let _ = require_private_permissions;

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum_bytes {
        return Err(Error::Protocol(format!("{label} exceeds its size limit")));
    }
    Ok(bytes)
}

fn is_symlink_loop(error: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        error.raw_os_error() == Some(libc::ELOOP)
    }
    #[cfg(not(unix))]
    {
        let _ = error;
        false
    }
}

/// Parse a private JSON document without ever surfacing parser text.
///
/// `serde_json` messages can quote the offending value (`invalid type: string
/// "sk-ant-…"`), and these documents hold OAuth tokens. Only the position
/// survives. Mirrors anthropic-auth's `parseJsonRedacted` (dfb6bc0).
pub(crate) fn parse_json_redacted<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    what: &'static str,
) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|error| Error::InvalidJson {
        what,
        line: error.line(),
        column: error.column(),
    })
}

/// Atomically replace `path` with `bytes`: user-only temp sibling, `fsync`,
/// refuse a symlinked target, `rename`, directory `fsync`. The parent is
/// created `0700` when missing.
pub(crate) fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.as_os_str().is_empty() {
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(Error::StoreIsSymlink);
    }
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("state.json");
    let tmp = parent.join(format!(
        "{name}.tmp-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    let write = (|| -> Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(error) = write {
        let _ = std::fs::remove_file(&tmp);
        return Err(error);
    }
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(Error::StoreIsSymlink);
    }
    if let Err(error) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(error.into());
    }
    if let Ok(directory) = std::fs::File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_errors_never_echo_document_text() {
        #[derive(serde::Deserialize, Debug)]
        #[allow(dead_code)]
        struct Doc {
            expires: u64,
        }
        let secret = "sk-ant-ort01-SECRETSECRETSECRETSECRET";
        let body = format!("{{\"expires\": \"{secret}\"}}");
        let error = parse_json_redacted::<Doc>(body.as_bytes(), "credential store").unwrap_err();
        let text = error.to_string();
        assert!(!text.contains("SECRET"), "{text}");
        assert!(matches!(error, Error::InvalidJson { line: 1, .. }));

        let truncated = parse_json_redacted::<Doc>(b"{\"expires\": ", "credential store");
        assert!(matches!(truncated, Err(Error::InvalidJson { .. })));
    }

    #[test]
    fn atomic_private_write_is_user_only_and_refuses_symlinks() {
        let dir = std::env::temp_dir().join(format!("anthropic-fs-{}", uuid::Uuid::new_v4()));
        let path = dir.join("state.json");
        write_private_atomic(&path, b"{}\n").unwrap();
        write_private_atomic(&path, b"{\"a\":1}\n").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"{\"a\":1}\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
            let link = dir.join("link.json");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(matches!(
                write_private_atomic(&link, b"{}"),
                Err(Error::StoreIsSymlink)
            ));
        }
        // No temp siblings are left behind.
        let leftovers = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .count();
        assert_eq!(leftovers, 0);
        let _ = std::fs::remove_dir_all(dir);
    }
}
