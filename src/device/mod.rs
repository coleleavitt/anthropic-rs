//! Trusted-device, Remote Control attestation, persistent identity, and Cowork
//! remote-device binding contracts.

/// Remote Control attestation status normalization and filtering policy.
pub mod attestation;
/// Cowork P-256 remote-device registration and session binding.
pub mod cowork;
/// Persistent installation-wide Claude device identity.
pub mod identity;
/// Trusted-device enrollment and request-header support.
pub mod trusted;

pub use attestation::{AttestationPolicy, AttestationStatus, VerifiedLevel};
pub use cowork::{
    CoworkDeviceClient, CoworkDeviceKey, CoworkPlatform, CreateSessionBinding,
    RegisteredCoworkDevice, build_bind_preimage,
};
pub use identity::{DeviceId, DeviceIdentityStore};
pub use trusted::{
    TRUSTED_DEVICE_TOKEN_ENV, TrustedDeviceClient, TrustedDeviceEnrollment, TrustedDeviceToken,
    trusted_device_header, trusted_device_token_from_env,
};

fn validate_device_base_url(base_url: &str) -> crate::Result<()> {
    let parsed = url::Url::parse(base_url)?;
    let secure = parsed.scheme() == "https";
    let loopback = parsed.scheme() == "http"
        && parsed.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        });
    if !secure && !loopback {
        return Err(crate::Error::Protocol(
            "device endpoint must use HTTPS unless it targets loopback".into(),
        ));
    }
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(crate::Error::Protocol(
            "device endpoint must not contain credentials, a query, or a fragment".into(),
        ));
    }
    Ok(())
}
