//! Stable, provider-independent principal identifiers.
//!
//! A `PrincipalId` is assigned by Ryuki's internal principal authority. It is
//! deliberately only constructible from an already assigned UUID or its exact
//! canonical wire representation; this module has no provider-subject, email,
//! claim, hashing, or name-based derivation API.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;
use uuid::Uuid;

/// A canonical, stable internal principal identifier.
///
/// The wire representation is always the lowercase hyphenated UUID form. The
/// UUID is non-secret, but it carries no provider subject or other external
/// identity material.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrincipalId(Uuid);

/// Why a candidate principal identifier was rejected.
///
/// Error values intentionally do not retain or render the rejected input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PrincipalIdError {
    #[error("principal id is not a UUID")]
    InvalidUuid,
    #[error("principal id must use canonical lowercase hyphenated UUID text")]
    NonCanonical,
    #[error("principal id must not be the nil UUID")]
    Nil,
}

impl PrincipalId {
    /// Admit an already assigned internal UUID.
    ///
    /// This constructor does not generate or derive identifiers and rejects
    /// the nil sentinel.
    pub fn from_uuid(value: Uuid) -> Result<Self, PrincipalIdError> {
        if value.is_nil() {
            return Err(PrincipalIdError::Nil);
        }
        Ok(Self(value))
    }

    /// Borrow the UUID for storage adapters without exposing mutable state.
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }

    /// Return the already assigned UUID for typed storage adapters.
    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl FromStr for PrincipalId {
    type Err = PrincipalIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parsed = Uuid::parse_str(value).map_err(|_| PrincipalIdError::InvalidUuid)?;
        if parsed.hyphenated().to_string() != value {
            return Err(PrincipalIdError::NonCanonical);
        }
        Self::from_uuid(parsed)
    }
}

impl TryFrom<&str> for PrincipalId {
    type Error = PrincipalIdError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl TryFrom<String> for PrincipalId {
    type Error = PrincipalIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl TryFrom<Uuid> for PrincipalId {
    type Error = PrincipalIdError;

    fn try_from(value: Uuid) -> Result<Self, Self::Error> {
        Self::from_uuid(value)
    }
}

impl From<PrincipalId> for Uuid {
    fn from(value: PrincipalId) -> Self {
        value.into_uuid()
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0.hyphenated())
    }
}

impl fmt::Debug for PrincipalId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PrincipalId")
            .field(&self.to_string())
            .finish()
    }
}

impl Serialize for PrincipalId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for PrincipalId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANONICAL: &str = "018f3f54-8f5e-7bb7-9f06-1f3cc6f819d0";

    #[test]
    fn canonical_text_round_trips_exactly() {
        let principal: PrincipalId = CANONICAL.parse().expect("canonical UUID");

        assert_eq!(principal.to_string(), CANONICAL);
        assert_eq!(principal.as_uuid().to_string(), CANONICAL);
        assert_eq!(PrincipalId::try_from(principal.into_uuid()), Ok(principal));
    }

    #[test]
    fn nil_uuid_is_never_admitted() {
        assert_eq!(
            PrincipalId::from_uuid(Uuid::nil()),
            Err(PrincipalIdError::Nil)
        );
        assert_eq!(
            "00000000-0000-0000-0000-000000000000".parse::<PrincipalId>(),
            Err(PrincipalIdError::Nil)
        );
    }

    #[test]
    fn alternate_uuid_spellings_are_rejected() {
        for candidate in [
            "018F3F54-8F5E-7BB7-9F06-1F3CC6F819D0",
            "018f3f548f5e7bb79f061f3cc6f819d0",
            "{018f3f54-8f5e-7bb7-9f06-1f3cc6f819d0}",
            "urn:uuid:018f3f54-8f5e-7bb7-9f06-1f3cc6f819d0",
            " 018f3f54-8f5e-7bb7-9f06-1f3cc6f819d0",
            "018f3f54-8f5e-7bb7-9f06-1f3cc6f819d0 ",
        ] {
            assert!(
                candidate.parse::<PrincipalId>().is_err(),
                "candidate must not be accepted"
            );
        }

        assert_eq!(
            "018F3F54-8F5E-7BB7-9F06-1F3CC6F819D0".parse::<PrincipalId>(),
            Err(PrincipalIdError::NonCanonical)
        );
    }

    #[test]
    fn malformed_values_are_rejected_without_echoing_input() {
        let candidate = "provider-subject:private-value";
        let error = candidate
            .parse::<PrincipalId>()
            .expect_err("provider subjects are not principal ids");

        assert_eq!(error, PrincipalIdError::InvalidUuid);
        assert!(!error.to_string().contains(candidate));
    }

    #[test]
    fn serde_uses_only_the_canonical_string_form() {
        let principal: PrincipalId = CANONICAL.parse().expect("canonical UUID");
        let encoded = serde_json::to_string(&principal).expect("serialize principal id");

        assert_eq!(encoded, format!("\"{CANONICAL}\""));
        assert_eq!(
            serde_json::from_str::<PrincipalId>(&encoded).expect("deserialize principal id"),
            principal
        );
        assert!(serde_json::from_str::<PrincipalId>("123").is_err());
        assert!(
            serde_json::from_str::<PrincipalId>("\"018F3F54-8F5E-7BB7-9F06-1F3CC6F819D0\"")
                .is_err()
        );
        assert!(
            serde_json::from_str::<PrincipalId>("\"00000000-0000-0000-0000-000000000000\"")
                .is_err()
        );
    }

    #[test]
    fn debug_output_is_typed_and_contains_only_the_internal_id() {
        let principal: PrincipalId = CANONICAL.parse().expect("canonical UUID");

        assert_eq!(
            format!("{principal:?}"),
            format!("PrincipalId(\"{CANONICAL}\")")
        );
    }
}
