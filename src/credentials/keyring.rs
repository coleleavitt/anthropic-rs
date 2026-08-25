use crate::credentials::SecretStore;
use crate::error::{Error, Result};

/// Operating-system credential vault backed by `keyring-rs`.
pub struct KeyringSecretStore {
    service: String,
}

impl KeyringSecretStore {
    /// Create a vault namespace. The default recommended service is
    /// `anthropic-rs`; native Claude import remains read-only and separate.
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn entry(&self, key: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(&self.service, key)
            .map_err(|error| Error::SecretStore(error.to_string()))
    }
}

impl SecretStore for KeyringSecretStore {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        match self.entry(key)?.get_secret() {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(Error::SecretStore(error.to_string())),
        }
    }

    fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        self.entry(key)?
            .set_secret(value)
            .map_err(|error| Error::SecretStore(error.to_string()))
    }

    fn delete(&self, key: &str) -> Result<()> {
        match self.entry(key)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(Error::SecretStore(error.to_string())),
        }
    }
}
