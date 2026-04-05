// Copyright (C) 2026 Martin Gleason & Arthur Dennis
// Licensed under AGPL-3.0-or-later

//! RBAC document access matrix.
//!
//! Defines which Automerge documents each role can subscribe to via the sync protocol.
//! The server enforces this at connection/subscription time.

use crate::errors::UserRole;
use std::collections::HashSet;

/// All syncable table names from the Swift app's `AutomergeDocumentManager.syncableTables`.
/// Updated for v0.4.0: 31 tables (original 13 + 9 v0.3.0 + 9 Field Ops Phase 1A).
pub const ALL_SYNCABLE_TABLES: &[&str] = &[
    // Original 13 (v0.2.3)
    "contact",
    "relationship",
    "event",
    "eventAttendee",
    "interaction",
    "commitment",
    "organization",
    "orgMembership",
    "contactTag",
    "turf",
    "canvassingScript",
    "doorKnockResult",
    "user",
    // v0.3.0 additions (9 new)
    "address",
    "elevatedPermission",
    "voterRecord",
    "electionHistory",
    "politicalSubdivision",
    "addressCondition",
    "shift",
    "incident",
    "issueRating",
    // v0.4.0 Field Ops Phase 1A (9 new)
    "enlistCode",
    "turfPacket",
    "turfBank",
    "turfDrop",
    "dropCode",
    "importedList",
    "listSlice",
    "listContact",
    "listResult",
];

/// All syncable table names for the Mutual Aid domain.
pub const MA_SYNCABLE_TABLES: &[&str] = &[
    "mutualAidSite",
    "mutualAidItem",
    "mutualAidTransaction",
    "rideRequest",
    "rideLog",
    "driverProfile",
    "complianceLedger",
    "demandSignal",
];

/// Returns the set of MA document names a given role is allowed to sync.
///
/// Campaign roles get no MA access except Principal and Operator who receive
/// the "demandSignal" read bridge.
#[must_use]
pub fn ma_allowed_documents(role: &UserRole) -> HashSet<&'static str> {
    match role {
        // MaAdmin: all 8 MA tables
        UserRole::MaAdmin => MA_SYNCABLE_TABLES.iter().copied().collect(),

        // MaDriver: 6 tables (no complianceLedger, no demandSignal)
        UserRole::MaDriver => [
            "mutualAidSite",
            "mutualAidItem",
            "mutualAidTransaction",
            "rideRequest",
            "rideLog",
            "driverProfile",
        ]
        .into_iter()
        .collect(),

        // MaVolunteer: 3 tables
        UserRole::MaVolunteer => [
            "mutualAidSite",
            "mutualAidItem",
            "mutualAidTransaction",
        ]
        .into_iter()
        .collect(),

        // CommunityMember: rideRequest only (own records enforced client-side)
        UserRole::CommunityMember => ["rideRequest"].into_iter().collect(),

        // Campaign Principal/Operator: demandSignal read bridge only
        UserRole::Principal | UserRole::Operator => {
            ["demandSignal"].into_iter().collect()
        }

        // All other campaign roles: no MA access
        UserRole::Analyst
        | UserRole::FundraisingDirector
        | UserRole::Scout
        | UserRole::Volunteer => HashSet::new(),
    }
}

/// Returns the set of document names a given role is allowed to sync.
///
/// The server treats document names as opaque strings but uses this matrix
/// to enforce subscription-level RBAC.
#[must_use]
pub fn allowed_documents(role: &UserRole) -> HashSet<&'static str> {
    match role {
        // Principal and Operator: full access to all campaign documents + demandSignal bridge
        UserRole::Principal | UserRole::Operator => {
            let mut docs: HashSet<&'static str> = ALL_SYNCABLE_TABLES.iter().copied().collect();
            docs.insert("demandSignal");
            docs
        }

        // Analyst: contacts, relationships, events, voter data, address conditions,
        // plus turfPacket/turfBank (read-only field ops) and list tables.
        // No enlistCode, turfDrop, dropCode, or user admin.
        UserRole::Analyst => [
            "contact",
            "relationship",
            "event",
            "eventAttendee",
            "interaction",
            "commitment",
            "organization",
            "orgMembership",
            "contactTag",
            "address",
            "voterRecord",
            "electionHistory",
            "politicalSubdivision",
            "addressCondition",
            "incident",
            "turfPacket",
            "turfBank",
            "importedList",
            "listSlice",
            "listContact",
            "listResult",
        ]
        .into_iter()
        .collect(),

        // Fundraising Director: contacts, events, imported lists.
        // No relationships, field ops, enlistCode, turf*, or dropCode.
        UserRole::FundraisingDirector => [
            "contact",
            "event",
            "eventAttendee",
            "interaction",
            "commitment",
            "organization",
            "orgMembership",
            "contactTag",
            "address",
            "importedList",
            "listSlice",
            "listContact",
            "listResult",
        ]
        .into_iter()
        .collect(),

        // Scout: contacts, events, field operations, shifts, incidents, address conditions,
        // plus enlistCode, turfPacket, turfBank, turfDrop, dropCode, and list view tables.
        UserRole::Scout => [
            "contact",
            "event",
            "eventAttendee",
            "interaction",
            "commitment",
            "turf",
            "canvassingScript",
            "doorKnockResult",
            "address",
            "addressCondition",
            "shift",
            "incident",
            "issueRating",
            "enlistCode",
            "turfPacket",
            "turfBank",
            "turfDrop",
            "dropCode",
            "listSlice",
            "listContact",
            "listResult",
        ]
        .into_iter()
        .collect(),

        // MA roles: no campaign document access
        UserRole::MaAdmin
        | UserRole::MaDriver
        | UserRole::MaVolunteer
        | UserRole::CommunityMember => HashSet::new(),

        // Volunteer: minimal field ops — contacts, assigned turf, canvassing, incidents,
        // plus turfPacket, turfDrop, and list view tables.
        UserRole::Volunteer => [
            "contact",
            "event",
            "eventAttendee",
            "interaction",
            "commitment",
            "turf",
            "canvassingScript",
            "doorKnockResult",
            "address",
            "addressCondition",
            "incident",
            "issueRating",
            "turfPacket",
            "turfDrop",
            "listSlice",
            "listContact",
            "listResult",
        ]
        .into_iter()
        .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principal_has_all_tables() {
        let docs = allowed_documents(&UserRole::Principal);
        // ALL_SYNCABLE_TABLES + demandSignal bridge
        assert_eq!(docs.len(), ALL_SYNCABLE_TABLES.len() + 1);
        for table in ALL_SYNCABLE_TABLES {
            assert!(docs.contains(table), "Principal missing: {table}");
        }
        assert!(docs.contains("demandSignal"), "Principal missing demandSignal bridge");
    }

    #[test]
    fn operator_has_all_tables() {
        let docs = allowed_documents(&UserRole::Operator);
        assert_eq!(docs.len(), ALL_SYNCABLE_TABLES.len() + 1);
        assert!(docs.contains("demandSignal"), "Operator missing demandSignal bridge");
    }

    #[test]
    fn volunteer_cannot_access_user_table() {
        let docs = allowed_documents(&UserRole::Volunteer);
        assert!(!docs.contains("user"), "Volunteer should not access user table");
    }

    #[test]
    fn volunteer_cannot_access_relationship() {
        let docs = allowed_documents(&UserRole::Volunteer);
        assert!(
            !docs.contains("relationship"),
            "Volunteer should not access relationship table"
        );
    }

    #[test]
    fn analyst_cannot_access_canvassing() {
        let docs = allowed_documents(&UserRole::Analyst);
        assert!(!docs.contains("turf"));
        assert!(!docs.contains("canvassingScript"));
        assert!(!docs.contains("doorKnockResult"));
    }

    #[test]
    fn analyst_can_access_voter_data() {
        let docs = allowed_documents(&UserRole::Analyst);
        assert!(docs.contains("voterRecord"));
        assert!(docs.contains("electionHistory"));
        assert!(docs.contains("politicalSubdivision"));
    }

    #[test]
    fn analyst_field_ops_access() {
        let docs = allowed_documents(&UserRole::Analyst);
        assert!(!docs.contains("enlistCode"), "Analyst should not access enlistCode");
        assert!(docs.contains("turfPacket"));
        assert!(docs.contains("turfBank"));
        assert!(!docs.contains("turfDrop"), "Analyst should not access turfDrop");
        assert!(!docs.contains("dropCode"), "Analyst should not access dropCode");
        assert!(docs.contains("importedList"));
        assert!(docs.contains("listSlice"));
        assert!(docs.contains("listContact"));
        assert!(docs.contains("listResult"));
    }

    #[test]
    fn fundraising_director_cannot_access_relationship() {
        let docs = allowed_documents(&UserRole::FundraisingDirector);
        assert!(!docs.contains("relationship"));
        assert!(!docs.contains("shift"));
        assert!(!docs.contains("incident"));
    }

    #[test]
    fn fundraising_director_field_ops_access() {
        let docs = allowed_documents(&UserRole::FundraisingDirector);
        assert!(!docs.contains("enlistCode"));
        assert!(!docs.contains("turfPacket"));
        assert!(!docs.contains("turfBank"));
        assert!(!docs.contains("turfDrop"));
        assert!(!docs.contains("dropCode"));
        assert!(docs.contains("importedList"));
        assert!(docs.contains("listSlice"));
        assert!(docs.contains("listContact"));
        assert!(docs.contains("listResult"));
    }

    #[test]
    fn scout_can_access_canvassing() {
        let docs = allowed_documents(&UserRole::Scout);
        assert!(docs.contains("turf"));
        assert!(docs.contains("canvassingScript"));
        assert!(docs.contains("doorKnockResult"));
        assert!(docs.contains("shift"));
        assert!(docs.contains("incident"));
        assert!(docs.contains("addressCondition"));
        assert!(docs.contains("issueRating"));
    }

    #[test]
    fn scout_field_ops_access() {
        let docs = allowed_documents(&UserRole::Scout);
        assert!(docs.contains("enlistCode"));
        assert!(docs.contains("turfPacket"));
        assert!(docs.contains("turfBank"));
        assert!(docs.contains("turfDrop"));
        assert!(docs.contains("dropCode"));
        assert!(!docs.contains("importedList"), "Scout should not access importedList");
        assert!(docs.contains("listSlice"));
        assert!(docs.contains("listContact"));
        assert!(docs.contains("listResult"));
    }

    #[test]
    fn volunteer_field_ops_access() {
        let docs = allowed_documents(&UserRole::Volunteer);
        assert!(!docs.contains("enlistCode"), "Volunteer should not access enlistCode");
        assert!(docs.contains("turfPacket"));
        assert!(!docs.contains("turfBank"), "Volunteer should not access turfBank");
        assert!(docs.contains("turfDrop"));
        assert!(!docs.contains("dropCode"), "Volunteer should not access dropCode");
        assert!(!docs.contains("importedList"), "Volunteer should not access importedList");
        assert!(docs.contains("listSlice"));
        assert!(docs.contains("listContact"));
        assert!(docs.contains("listResult"));
    }

    #[test]
    fn all_campaign_roles_have_contact_access() {
        let roles = [
            UserRole::Principal,
            UserRole::Operator,
            UserRole::Analyst,
            UserRole::FundraisingDirector,
            UserRole::Scout,
            UserRole::Volunteer,
        ];
        for role in &roles {
            let docs = allowed_documents(role);
            assert!(docs.contains("contact"), "{role:?} should access contacts");
        }
    }

    // ── Mutual Aid RBAC tests ───────────────────────────────────────────

    #[test]
    fn ma_syncable_tables_has_8_entries() {
        assert_eq!(MA_SYNCABLE_TABLES.len(), 8);
    }

    #[test]
    fn ma_admin_gets_all_8_ma_tables() {
        let docs = ma_allowed_documents(&UserRole::MaAdmin);
        assert_eq!(docs.len(), 8);
        for table in MA_SYNCABLE_TABLES {
            assert!(docs.contains(table), "MaAdmin missing: {table}");
        }
    }

    #[test]
    fn ma_driver_gets_6_tables() {
        let docs = ma_allowed_documents(&UserRole::MaDriver);
        assert_eq!(docs.len(), 6);
        assert!(docs.contains("mutualAidSite"));
        assert!(docs.contains("mutualAidItem"));
        assert!(docs.contains("mutualAidTransaction"));
        assert!(docs.contains("rideRequest"));
        assert!(docs.contains("rideLog"));
        assert!(docs.contains("driverProfile"));
        assert!(!docs.contains("complianceLedger"), "MaDriver should not access complianceLedger");
        assert!(!docs.contains("demandSignal"), "MaDriver should not access demandSignal");
    }

    #[test]
    fn ma_volunteer_gets_3_tables() {
        let docs = ma_allowed_documents(&UserRole::MaVolunteer);
        assert_eq!(docs.len(), 3);
        assert!(docs.contains("mutualAidSite"));
        assert!(docs.contains("mutualAidItem"));
        assert!(docs.contains("mutualAidTransaction"));
    }

    #[test]
    fn community_member_gets_ride_request_only() {
        let docs = ma_allowed_documents(&UserRole::CommunityMember);
        assert_eq!(docs.len(), 1);
        assert!(docs.contains("rideRequest"));
    }

    #[test]
    fn campaign_principal_operator_get_demand_signal_bridge() {
        // Via allowed_documents (campaign RBAC)
        let principal_docs = allowed_documents(&UserRole::Principal);
        assert!(principal_docs.contains("demandSignal"));
        let operator_docs = allowed_documents(&UserRole::Operator);
        assert!(operator_docs.contains("demandSignal"));

        // Via ma_allowed_documents (MA RBAC) — same bridge
        let principal_ma = ma_allowed_documents(&UserRole::Principal);
        assert_eq!(principal_ma.len(), 1);
        assert!(principal_ma.contains("demandSignal"));
        let operator_ma = ma_allowed_documents(&UserRole::Operator);
        assert_eq!(operator_ma.len(), 1);
        assert!(operator_ma.contains("demandSignal"));
    }

    #[test]
    fn campaign_principal_operator_get_no_other_ma_tables() {
        for role in &[UserRole::Principal, UserRole::Operator] {
            let docs = ma_allowed_documents(role);
            for table in MA_SYNCABLE_TABLES {
                if *table != "demandSignal" {
                    assert!(!docs.contains(table), "{role:?} should not get MA table {table}");
                }
            }
        }
    }

    #[test]
    fn campaign_scout_volunteer_get_zero_ma_access() {
        for role in &[UserRole::Scout, UserRole::Volunteer] {
            let docs = ma_allowed_documents(role);
            assert!(docs.is_empty(), "{role:?} should have zero MA access");
        }
    }

    #[test]
    fn ma_roles_get_zero_campaign_access() {
        for role in &[
            UserRole::MaAdmin,
            UserRole::MaDriver,
            UserRole::MaVolunteer,
            UserRole::CommunityMember,
        ] {
            let docs = allowed_documents(role);
            assert!(docs.is_empty(), "{role:?} should have zero campaign access");
        }
    }
}
