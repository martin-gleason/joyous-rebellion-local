//! Domain newtypes for type-safe identifiers and sensitive values.
//!
//! These types prevent mixing up IDs of different domain entities at compile time
//! and ensure sensitive values like JWT tokens and encryption keys are handled safely.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Generate a newtype ID wrapper around [`Uuid`].
///
/// Each generated type is `Copy`, `Eq`, `Hash`, and `Serialize/Deserialize`.
macro_rules! newtype_id {
    ($name:ident) => {
        #[doc = concat!("A type-safe ", stringify!($name), " wrapping a UUID.")]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name(Uuid);

        impl $name {
            /// Create a new ID from a [`Uuid`].
            #[must_use]
            pub fn new(id: Uuid) -> Self {
                Self(id)
            }

            /// Generate a new random ID.
            #[must_use]
            pub fn random() -> Self {
                Self(Uuid::new_v4())
            }

            /// Get the inner [`Uuid`].
            #[must_use]
            pub fn into_inner(self) -> Uuid {
                self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl From<Uuid> for $name {
            fn from(id: Uuid) -> Self {
                Self(id)
            }
        }
    };
}

newtype_id!(CampaignId);
newtype_id!(UserId);
newtype_id!(DeviceId);
newtype_id!(DocumentId);
newtype_id!(ContactId);
newtype_id!(RelationshipId);
newtype_id!(EventId);
newtype_id!(TurfId);
newtype_id!(InteractionId);

/// An opaque document name used by the sync protocol.
///
/// The server treats document names as opaque strings (e.g., "contact", "relationship").
/// It does not validate or interpret them — the client decides granularity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DocumentName(String);

impl DocumentName {
    /// Create a new document name.
    #[must_use]
    pub fn new(name: String) -> Self {
        Self(name)
    }

    /// Get the name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for DocumentName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for DocumentName {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// A JWT token that intentionally does NOT implement `Clone` or `Debug`
/// to prevent accidental duplication or logging of tokens.
pub struct JwtToken(String);

impl JwtToken {
    /// Create a new JWT token.
    #[must_use]
    pub fn new(token: String) -> Self {
        Self(token)
    }

    /// Get the token value as bytes for comparison.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Get the token value as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An encryption key that uses [`Zeroizing`] to clear memory on drop.
///
/// Does NOT implement `Clone`, `Debug`, or `Serialize` to prevent
/// accidental exposure of key material.
pub struct EncryptionKey(Zeroizing<Vec<u8>>);

impl EncryptionKey {
    /// Create a new encryption key from raw bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Get the key bytes for cryptographic operations.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newtype_ids_are_distinct() {
        let uuid = Uuid::new_v4();
        let campaign = CampaignId::new(uuid);
        let user = UserId::new(uuid);
        assert_eq!(campaign.into_inner(), user.into_inner());
    }

    #[test]
    fn newtype_id_display() {
        let uuid = Uuid::nil();
        let id = CampaignId::new(uuid);
        assert_eq!(id.to_string(), "00000000-0000-0000-0000-000000000000");
    }

    #[test]
    fn device_id_works() {
        let id = DeviceId::random();
        let id2 = DeviceId::new(id.into_inner());
        assert_eq!(id, id2);
    }

    #[test]
    fn document_name_from_str() {
        let name = DocumentName::from("contact");
        assert_eq!(name.as_str(), "contact");
        assert_eq!(name.to_string(), "contact");
    }

    #[test]
    fn jwt_token_as_bytes() {
        let token = JwtToken::new("test-token".to_string());
        assert_eq!(token.as_bytes(), b"test-token");
    }

    #[test]
    fn encryption_key_as_bytes() {
        let key = EncryptionKey::new(vec![1, 2, 3, 4]);
        assert_eq!(key.as_bytes(), &[1, 2, 3, 4]);
    }
}
