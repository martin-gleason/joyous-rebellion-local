//! Test factories and assertion helpers for reproducible tests.

use crate::errors::UserRole;
use crate::newtypes::{CampaignId, ContactId, DeviceId, DocumentId, UserId};
use uuid::Uuid;

/// A deterministic campaign ID for use in tests.
///
/// Always returns the same UUID: `00000000-0000-0000-0000-000000000001`.
#[must_use]
pub fn test_campaign_id() -> CampaignId {
    CampaignId::new(Uuid::from_u128(1))
}

/// A deterministic user ID for use in tests.
///
/// Always returns the same UUID: `00000000-0000-0000-0000-000000000002`.
#[must_use]
pub fn test_user_id() -> UserId {
    UserId::new(Uuid::from_u128(2))
}

/// A deterministic document ID for use in tests.
///
/// Always returns the same UUID: `00000000-0000-0000-0000-000000000003`.
#[must_use]
pub fn test_document_id() -> DocumentId {
    DocumentId::new(Uuid::from_u128(3))
}

/// A deterministic device ID for use in tests.
///
/// Always returns the same UUID: `00000000-0000-0000-0000-000000000004`.
#[must_use]
pub fn test_device_id() -> DeviceId {
    DeviceId::new(Uuid::from_u128(4))
}

/// Generate `n` deterministic contact IDs for use in tests.
///
/// IDs are sequential starting from UUID suffix 100.
#[must_use]
pub fn test_contact_ids(n: usize) -> Vec<ContactId> {
    (0..n)
        .map(|i| ContactId::new(Uuid::from_u128(100 + i as u128)))
        .collect()
}

/// Fields that should be hidden from roles below a certain privilege level.
const SENSITIVE_FIELDS: &[&str] = &[
    "ssn",
    "social_security",
    "bank_account",
    "routing_number",
    "credit_card",
    "salary",
    "donation_amount",
    "password_hash",
    "api_key",
    "encryption_key",
];

/// Assert that a JSON value has been properly filtered for RBAC.
///
/// Checks that sensitive fields are not present when viewed by roles
/// below `Operator` level.
///
/// # Panics
///
/// Panics if sensitive fields are found for low-privilege roles.
pub fn assert_rbac_filtered(value: &serde_json::Value, role: UserRole) {
    if role.has_privilege_of(&UserRole::Operator) {
        return;
    }

    let fields = collect_field_names(value);
    for sensitive in SENSITIVE_FIELDS {
        assert!(
            !fields.contains(&sensitive.to_string()),
            "Role {role:?} should not see field '{sensitive}' — RBAC filtering missing"
        );
    }
}

/// Recursively collect all field names from a JSON value.
fn collect_field_names(value: &serde_json::Value) -> Vec<String> {
    let mut names = Vec::new();
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                names.push(key.clone());
                names.extend(collect_field_names(val));
            }
        }
        serde_json::Value::Array(arr) => {
            for val in arr {
                names.extend(collect_field_names(val));
            }
        }
        _ => {}
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn deterministic_ids_are_stable() {
        assert_eq!(test_campaign_id(), test_campaign_id());
        assert_eq!(test_user_id(), test_user_id());
        assert_eq!(test_document_id(), test_document_id());
        assert_eq!(test_device_id(), test_device_id());
    }

    #[test]
    fn contact_ids_are_sequential() {
        let ids = test_contact_ids(3);
        assert_eq!(ids.len(), 3);
        assert_ne!(ids[0], ids[1]);
        assert_ne!(ids[1], ids[2]);
    }

    #[test]
    fn rbac_allows_operator_to_see_sensitive() {
        let data = json!({"name": "Test", "salary": 50000});
        assert_rbac_filtered(&data, UserRole::Operator);
    }

    #[test]
    #[should_panic(expected = "RBAC filtering missing")]
    fn rbac_blocks_volunteer_from_sensitive() {
        let data = json!({"name": "Test", "salary": 50000});
        assert_rbac_filtered(&data, UserRole::Volunteer);
    }

    #[test]
    fn rbac_allows_non_sensitive_for_volunteer() {
        let data = json!({"name": "Test", "email": "test@example.com"});
        assert_rbac_filtered(&data, UserRole::Volunteer);
    }
}
