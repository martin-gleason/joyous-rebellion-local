//! User revocation list.
//!
//! An in-memory set of revoked user IDs. Checked during JWT validation
//! to reject tokens from users the Principal has deactivated.

use jr_patterns::UserId;
use std::collections::HashSet;

/// In-memory revocation list for deactivated users.
///
/// The Principal can revoke users via `POST /campaigns/{id}/revoke`.
/// Revoked users are rejected at JWT validation time, before any
/// sync messages are processed.
#[derive(Debug, Default)]
pub struct RevocationList {
    revoked: HashSet<UserId>,
}

impl RevocationList {
    /// Create an empty revocation list.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a user to the revocation list.
    pub fn revoke(&mut self, user_id: UserId) {
        self.revoked.insert(user_id);
    }

    /// Remove a user from the revocation list.
    pub fn unrevoke(&mut self, user_id: &UserId) {
        self.revoked.remove(user_id);
    }

    /// Check if a user is revoked.
    #[must_use]
    pub fn is_revoked(&self, user_id: &UserId) -> bool {
        self.revoked.contains(user_id)
    }

    /// Number of revoked users.
    #[must_use]
    pub fn len(&self) -> usize {
        self.revoked.len()
    }

    /// Whether the revocation list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.revoked.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn empty_list_revokes_nobody() {
        let list = RevocationList::new();
        let user = UserId::new(Uuid::new_v4());
        assert!(!list.is_revoked(&user));
        assert!(list.is_empty());
    }

    #[test]
    fn revoke_and_check() {
        let mut list = RevocationList::new();
        let user = UserId::new(Uuid::new_v4());
        list.revoke(user);
        assert!(list.is_revoked(&user));
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn unrevoke() {
        let mut list = RevocationList::new();
        let user = UserId::new(Uuid::new_v4());
        list.revoke(user);
        list.unrevoke(&user);
        assert!(!list.is_revoked(&user));
    }

    #[test]
    fn different_users_independent() {
        let mut list = RevocationList::new();
        let user_a = UserId::new(Uuid::new_v4());
        let user_b = UserId::new(Uuid::new_v4());
        list.revoke(user_a);
        assert!(list.is_revoked(&user_a));
        assert!(!list.is_revoked(&user_b));
    }
}
