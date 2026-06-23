//! Authorization matrix (spec §7). Enforced server-side; the frontend only
//! hides controls as a convenience. Every check takes the `Actor` derived from
//! a validated session — never a client-supplied role flag (§11 trust
//! boundary).

use crate::error::{DomainError, DomainResult};
use crate::model::Actor;

/// A discrete capability a request may require.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capability {
    /// Read groups/OKRs/updates/history — everyone authenticated.
    Read,
    /// Create/edit/delete groups & OKRs, revert, assign — admin only.
    ManageOkrs,
    /// Create/edit/delete users, issue codes, promote/demote — admin only.
    ManageUsers,
    /// Post an update or toggle done on an OKR — gated on assignment for
    /// everyone, admins included (§7 note, Q10a/b). `assignees` is the OKR's
    /// current assignee set.
    ContributeToOkr { assignees: Vec<String> },
    /// Edit the actor's own display name — everyone.
    EditOwnName,
    /// Manage the actor's own passkeys / push subscription — everyone.
    ManageOwnAuth,
    /// Edit or delete a specific update — author or admin (§9 updates).
    ModifyUpdate { author_id: String },
}

/// Returns `true` if `actor` holds `cap`. Pure and total.
pub fn allows(actor: &Actor, cap: &Capability) -> bool {
    match cap {
        Capability::Read | Capability::EditOwnName | Capability::ManageOwnAuth => true,
        Capability::ManageOkrs | Capability::ManageUsers => actor.is_admin,
        Capability::ContributeToOkr { assignees } => assignees.iter().any(|a| a == &actor.user_id),
        Capability::ModifyUpdate { author_id } => actor.is_admin || *author_id == actor.user_id,
    }
}

/// Convenience wrapper returning `Forbidden` when not permitted.
pub fn require(actor: &Actor, cap: Capability) -> DomainResult<()> {
    if allows(actor, &cap) {
        Ok(())
    } else {
        Err(DomainError::Forbidden)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admin() -> Actor {
        Actor {
            user_id: "admin".into(),
            is_admin: true,
        }
    }
    fn user(id: &str) -> Actor {
        Actor {
            user_id: id.into(),
            is_admin: false,
        }
    }

    #[test]
    fn read_is_open_to_all_authenticated() {
        assert!(allows(&user("u"), &Capability::Read));
        assert!(allows(&admin(), &Capability::Read));
    }

    #[test]
    fn management_is_admin_only() {
        assert!(allows(&admin(), &Capability::ManageOkrs));
        assert!(allows(&admin(), &Capability::ManageUsers));
        assert!(!allows(&user("u"), &Capability::ManageOkrs));
        assert!(!allows(&user("u"), &Capability::ManageUsers));
    }

    #[test]
    fn contribute_requires_assignment_even_for_admins() {
        let cap = || Capability::ContributeToOkr {
            assignees: vec!["alice".into(), "bob".into()],
        };
        assert!(allows(&user("alice"), &cap()));
        assert!(!allows(&user("carol"), &cap()));
        // Admin not assigned -> cannot contribute (Q10a/b).
        assert!(!allows(&admin(), &cap()));
        // Admin assigned to self -> can contribute.
        let cap_admin = Capability::ContributeToOkr {
            assignees: vec!["admin".into()],
        };
        assert!(allows(&admin(), &cap_admin));
    }

    #[test]
    fn update_modification_is_author_or_admin() {
        let cap = Capability::ModifyUpdate {
            author_id: "alice".into(),
        };
        assert!(allows(&user("alice"), &cap));
        assert!(allows(&admin(), &cap));
        assert!(!allows(&user("bob"), &cap));
    }

    #[test]
    fn require_returns_forbidden() {
        assert!(matches!(
            require(&user("u"), Capability::ManageUsers),
            Err(DomainError::Forbidden)
        ));
        assert!(require(&admin(), Capability::ManageUsers).is_ok());
    }
}
