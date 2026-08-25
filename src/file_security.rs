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
