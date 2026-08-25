use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// Server-computed Remote Control device attestation status.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum AttestationStatus {
    /// No meaningful status was supplied.
    Unspecified,
    /// The sender supplied no device attestation.
    Absent,
    /// A full device signature was verified.
    Verified,
    /// The bridge gate verified the sender without a stronger client proof.
    VerifiedByGate,
    /// The supplied device proof was invalid.
    Invalid,
    /// The proof was not evaluated.
    Unchecked,
    /// A keyless trusted device was verified.
    VerifiedKeylessDevice,
    /// An Anthropic service vouched for the event; always accepted.
    ServiceVouched,
    /// A future status unknown to this crate.
    Unknown(String),
}

impl AttestationStatus {
    /// Normalize the string or numeric wire representation used by bridge events.
    pub fn from_wire(value: &serde_json::Value) -> Self {
        match value {
            serde_json::Value::Number(number) => match number.as_u64() {
                Some(0) => Self::Unspecified,
                Some(1) => Self::Absent,
                Some(2) => Self::Verified,
                Some(3) => Self::VerifiedByGate,
                Some(4) => Self::Invalid,
                Some(5) => Self::Unchecked,
                Some(other) => Self::Unknown(other.to_string()),
                None => Self::Unspecified,
            },
            serde_json::Value::String(raw) => {
                let normalized = raw
                    .strip_prefix("DEVICE_ATTESTATION_STATUS_")
                    .unwrap_or(raw);
                match normalized {
                    "UNSPECIFIED" => Self::Unspecified,
                    "ABSENT" => Self::Absent,
                    "VERIFIED" => Self::Verified,
                    "VERIFIED_BY_GATE" => Self::VerifiedByGate,
                    "INVALID" => Self::Invalid,
                    "UNCHECKED" => Self::Unchecked,
                    "VERIFIED_KEYLESS_DEVICE" => Self::VerifiedKeylessDevice,
                    "SERVICE_VOUCHED" => Self::ServiceVouched,
                    unknown => Self::Unknown(unknown.to_owned()),
                }
            }
            _ => Self::Unspecified,
        }
    }

    fn threshold_rank(&self) -> Option<u8> {
        match self {
            Self::Verified => Some(0),
            Self::VerifiedKeylessDevice => Some(1),
            Self::VerifiedByGate => Some(2),
            _ => None,
        }
    }
}

/// Threshold accepted by the native bridge attestation filter.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerifiedLevel {
    /// Accept only fully verified device signatures.
    #[default]
    Verified,
    /// Also accept verified keyless devices.
    VerifiedKeylessDevice,
    /// Also accept events verified only by the bridge gate.
    VerifiedByGate,
}

impl VerifiedLevel {
    fn rank(self) -> u8 {
        match self {
            Self::Verified => 0,
            Self::VerifiedKeylessDevice => 1,
            Self::VerifiedByGate => 2,
        }
    }
}

/// Fail-closed policy for accepting or dropping inbound Remote Control events.
#[derive(Debug, Clone)]
pub struct AttestationPolicy {
    /// Whether unverified events are actively dropped.
    enforce: bool,
    /// Maximum accepted verification threshold.
    accept_level: VerifiedLevel,
    /// Explicit exceptions for otherwise unverified statuses.
    accept_statuses: BTreeSet<AttestationStatus>,
}

#[derive(Deserialize)]
struct EnforcedConfig {
    #[serde(default)]
    accept_level: VerifiedLevel,
    #[serde(default)]
    accept_statuses: Vec<ExceptionStatus>,
}

#[derive(Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ExceptionStatus {
    Unspecified,
    Absent,
    Invalid,
    Unchecked,
}

impl From<ExceptionStatus> for AttestationStatus {
    fn from(status: ExceptionStatus) -> Self {
        match status {
            ExceptionStatus::Unspecified => Self::Unspecified,
            ExceptionStatus::Absent => Self::Absent,
            ExceptionStatus::Invalid => Self::Invalid,
            ExceptionStatus::Unchecked => Self::Unchecked,
        }
    }
}

impl Default for AttestationPolicy {
    fn default() -> Self {
        Self {
            enforce: false,
            accept_level: VerifiedLevel::Verified,
            accept_statuses: BTreeSet::new(),
        }
    }
}

impl AttestationPolicy {
    /// Construct a non-enforcing policy. Unverified statuses are observed but
    /// accepted, matching native Remote Control's default.
    pub fn permissive() -> Self {
        Self::default()
    }

    /// Construct an enforcing policy after restricting explicit exceptions to
    /// the four unverified statuses accepted by native Claude configuration.
    pub fn enforced(
        accept_level: VerifiedLevel,
        accept_statuses: impl IntoIterator<Item = AttestationStatus>,
    ) -> crate::Result<Self> {
        let accept_statuses = accept_statuses.into_iter().collect::<BTreeSet<_>>();
        if accept_statuses.iter().any(|status| {
            !matches!(
                status,
                AttestationStatus::Unspecified
                    | AttestationStatus::Absent
                    | AttestationStatus::Invalid
                    | AttestationStatus::Unchecked
            )
        }) {
            return Err(crate::Error::Protocol(
                "attestation exceptions contain a status native Claude does not permit".into(),
            ));
        }
        Ok(Self {
            enforce: true,
            accept_level,
            accept_statuses,
        })
    }

    /// Parse native enforced configuration. Malformed input fails closed to
    /// `VERIFIED` with no exceptions, exactly like Claude Code 2.1.233.
    pub fn from_config_value_fail_closed(value: &serde_json::Value) -> Self {
        match serde_json::from_value::<EnforcedConfig>(value.clone()) {
            Ok(config) => Self {
                enforce: true,
                accept_level: config.accept_level,
                accept_statuses: config
                    .accept_statuses
                    .into_iter()
                    .map(AttestationStatus::from)
                    .collect(),
            },
            Err(_) => Self {
                enforce: true,
                accept_level: VerifiedLevel::Verified,
                accept_statuses: BTreeSet::new(),
            },
        }
    }

    /// Whether this policy actively drops unverified events.
    pub fn is_enforcing(&self) -> bool {
        self.enforce
    }

    /// Maximum accepted native verification threshold.
    pub fn accept_level(&self) -> VerifiedLevel {
        self.accept_level
    }

    /// Explicit unverified-status exceptions.
    pub fn accept_statuses(&self) -> &BTreeSet<AttestationStatus> {
        &self.accept_statuses
    }

    /// Whether an event carrying `status` is accepted.
    pub fn accepts(&self, status: &AttestationStatus) -> bool {
        if matches!(status, AttestationStatus::ServiceVouched) {
            return true;
        }
        if status
            .threshold_rank()
            .is_some_and(|rank| rank <= self.accept_level.rank())
        {
            return true;
        }
        !self.enforce || self.accept_statuses.contains(status)
    }

    /// Native event-filter convention: `true` means drop.
    pub fn should_drop(&self, status: &AttestationStatus) -> bool {
        !self.accepts(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_all_native_statuses() {
        assert_eq!(
            AttestationStatus::from_wire(&serde_json::json!("DEVICE_ATTESTATION_STATUS_VERIFIED")),
            AttestationStatus::Verified
        );
        assert_eq!(
            AttestationStatus::from_wire(&serde_json::json!(3)),
            AttestationStatus::VerifiedByGate
        );
        assert!(matches!(
            AttestationStatus::from_wire(&serde_json::json!("FUTURE")),
            AttestationStatus::Unknown(_)
        ));
    }

    #[test]
    fn numeric_statuses_match_the_native_zero_through_five_mapping() {
        let expected = [
            AttestationStatus::Unspecified,
            AttestationStatus::Absent,
            AttestationStatus::Verified,
            AttestationStatus::VerifiedByGate,
            AttestationStatus::Invalid,
            AttestationStatus::Unchecked,
        ];
        for (number, status) in expected.into_iter().enumerate() {
            assert_eq!(
                AttestationStatus::from_wire(&serde_json::json!(number)),
                status
            );
        }
        assert_eq!(
            AttestationStatus::from_wire(&serde_json::json!(6)),
            AttestationStatus::Unknown("6".into())
        );
    }

    #[test]
    fn enforced_policy_matches_native_threshold_order() {
        let policy =
            AttestationPolicy::enforced(VerifiedLevel::VerifiedKeylessDevice, std::iter::empty())
                .unwrap();
        assert!(policy.accepts(&AttestationStatus::Verified));
        assert!(policy.accepts(&AttestationStatus::VerifiedKeylessDevice));
        assert!(!policy.accepts(&AttestationStatus::VerifiedByGate));
        assert!(policy.accepts(&AttestationStatus::ServiceVouched));
        assert!(policy.should_drop(&AttestationStatus::Absent));
    }

    #[test]
    fn exceptions_and_non_enforcing_mode_match_native_filtering() {
        let default = AttestationPolicy::default();
        assert!(default.accepts(&AttestationStatus::Absent));
        assert!(default.accepts(&AttestationStatus::Invalid));

        let mut exceptions = BTreeSet::new();
        exceptions.insert(AttestationStatus::Unchecked);
        let enforced = AttestationPolicy::enforced(VerifiedLevel::Verified, exceptions).unwrap();
        assert!(enforced.accepts(&AttestationStatus::Unchecked));
        assert!(!enforced.accepts(&AttestationStatus::Unknown("FUTURE".into())));
    }

    #[test]
    fn malformed_enforcement_config_fails_closed_and_exceptions_are_restricted() {
        let malformed = AttestationPolicy::from_config_value_fail_closed(&serde_json::json!({
            "accept_level": "FUTURE",
            "accept_statuses": ["VERIFIED"],
        }));
        assert!(malformed.is_enforcing());
        assert_eq!(malformed.accept_level(), VerifiedLevel::Verified);
        assert!(malformed.accept_statuses().is_empty());
        assert!(malformed.accepts(&AttestationStatus::Verified));
        assert!(!malformed.accepts(&AttestationStatus::Absent));

        let configured = AttestationPolicy::from_config_value_fail_closed(&serde_json::json!({
            "accept_level": "VERIFIED_KEYLESS_DEVICE",
            "accept_statuses": ["ABSENT", "UNCHECKED"],
        }));
        assert!(configured.accepts(&AttestationStatus::Absent));
        assert!(configured.accepts(&AttestationStatus::Unchecked));
        assert!(configured.accepts(&AttestationStatus::VerifiedKeylessDevice));
        assert!(!configured.accepts(&AttestationStatus::VerifiedByGate));

        assert!(
            AttestationPolicy::enforced(
                VerifiedLevel::Verified,
                [AttestationStatus::ServiceVouched]
            )
            .is_err()
        );
    }
}
