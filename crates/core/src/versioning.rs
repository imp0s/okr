//! Formal versioning model (spec §5), implemented as a pure state machine so
//! the counter / revert / burn rules are exhaustively unit-testable
//! independent of any storage backend.
//!
//! Both groups and OKRs use this. `VersionState` is the small projection of an
//! entity's version bookkeeping; the worker maps it onto the persisted
//! `current_version` / `next_version_counter` columns and the per-version
//! `valid` flags.

use crate::error::{DomainError, DomainResult};
use std::collections::BTreeSet;

/// The versioning bookkeeping for a single entity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionState {
    /// Monotonic; only ever increases (§5.1).
    pub next_version_counter: u64,
    /// Points at the authoritative version for display (§5.1).
    pub current_version: u64,
    /// Versions that are still valid (not burned by a revert, §5.3).
    pub valid_versions: BTreeSet<u64>,
}

/// Outcome of an edit: a freshly allocated version number and the updated
/// state. The caller persists a new `*_version` row with `valid = true`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditOutcome {
    pub new_version: u64,
    pub state: VersionState,
}

/// Outcome of a revert: which versions were burned, plus the updated state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevertOutcome {
    pub target_version: u64,
    /// Versions whose `valid` flag must be set to false.
    pub burned: Vec<u64>,
    pub state: VersionState,
}

impl VersionState {
    /// Create a brand-new entity: version `1`, counter → 2, current = 1 (§5.1).
    pub fn create() -> EditOutcome {
        let mut valid = BTreeSet::new();
        valid.insert(1);
        EditOutcome {
            new_version: 1,
            state: VersionState {
                next_version_counter: 2,
                current_version: 1,
                valid_versions: valid,
            },
        }
    }

    /// Edit the definition (§5.2): allocate `next_version_counter`, increment
    /// the counter, mark the new version valid, set it current.
    pub fn edit(&self) -> EditOutcome {
        let new_version = self.next_version_counter;
        let mut state = self.clone();
        state.next_version_counter += 1;
        state.current_version = new_version;
        state.valid_versions.insert(new_version);
        EditOutcome { new_version, state }
    }

    /// Revert to an earlier valid version `n` (§5.3). Admin-only and
    /// non-reversible — enforced by the authorization layer, not here.
    ///
    /// Rules:
    ///   1. `current_version = n`.
    ///   2. every version `> n` is burned (`valid = false`); their numbers stay
    ///      permanently consumed — the counter is **not** rewound.
    ///   3. the next edit allocates the current counter value, skipping burned
    ///      numbers.
    pub fn revert_to(&self, n: u64) -> DomainResult<RevertOutcome> {
        if !self.valid_versions.contains(&n) {
            return Err(DomainError::Conflict(format!(
                "cannot revert to version {n}: not a valid version"
            )));
        }
        if n == self.current_version {
            return Err(DomainError::Conflict(format!(
                "version {n} is already current"
            )));
        }
        let mut state = self.clone();
        let burned: Vec<u64> = state
            .valid_versions
            .iter()
            .copied()
            .filter(|&v| v > n)
            .collect();
        for v in &burned {
            state.valid_versions.remove(v);
        }
        state.current_version = n;
        // next_version_counter intentionally unchanged (§5.3 rule 2).
        Ok(RevertOutcome {
            target_version: n,
            burned,
            state,
        })
    }

    /// Whether a given version number is currently valid.
    pub fn is_valid(&self, version: u64) -> bool {
        self.valid_versions.contains(&version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn versions(s: &VersionState) -> Vec<u64> {
        s.valid_versions.iter().copied().collect()
    }

    /// The worked example from spec §5.3, verified step by step.
    #[test]
    fn spec_worked_example() {
        // Step 1: create -> counter 2, current 1, valid {1}
        let mut state = VersionState::create().state;
        assert_eq!(state.next_version_counter, 2);
        assert_eq!(state.current_version, 1);
        assert_eq!(versions(&state), vec![1]);

        // Step 2: edit -> counter 3, current 2, valid {1,2}
        let e = state.edit();
        assert_eq!(e.new_version, 2);
        state = e.state;
        assert_eq!(state.next_version_counter, 3);
        assert_eq!(state.current_version, 2);
        assert_eq!(versions(&state), vec![1, 2]);

        // Step 3: edit -> counter 4, current 3, valid {1,2,3}
        let e = state.edit();
        assert_eq!(e.new_version, 3);
        state = e.state;
        assert_eq!(state.next_version_counter, 4);
        assert_eq!(state.current_version, 3);
        assert_eq!(versions(&state), vec![1, 2, 3]);

        // Step 4: revert to 1 -> counter 4 (unchanged), current 1, valid {1} (2,3 burned)
        let r = state.revert_to(1).unwrap();
        assert_eq!(r.burned, vec![2, 3]);
        state = r.state;
        assert_eq!(state.next_version_counter, 4);
        assert_eq!(state.current_version, 1);
        assert_eq!(versions(&state), vec![1]);

        // Step 5: edit -> counter 5, current 4, valid {1,4} (2,3 still burned)
        let e = state.edit();
        assert_eq!(e.new_version, 4); // skips burned 2,3
        state = e.state;
        assert_eq!(state.next_version_counter, 5);
        assert_eq!(state.current_version, 4);
        assert_eq!(versions(&state), vec![1, 4]);
    }

    #[test]
    fn revert_to_burned_version_is_rejected() {
        let mut state = VersionState::create().state;
        state = state.edit().state; // v2
        state = state.edit().state; // v3
        state = state.revert_to(1).unwrap().state; // burns 2,3
        let err = state.revert_to(2).unwrap_err();
        assert!(matches!(err, DomainError::Conflict(_)));
    }

    #[test]
    fn revert_to_current_is_rejected() {
        let state = VersionState::create().state;
        assert!(matches!(
            state.revert_to(1).unwrap_err(),
            DomainError::Conflict(_)
        ));
    }

    #[test]
    fn revert_to_unknown_version_is_rejected() {
        let state = VersionState::create().state;
        assert!(matches!(
            state.revert_to(99).unwrap_err(),
            DomainError::Conflict(_)
        ));
    }

    #[test]
    fn counter_is_monotonic_across_revert_then_edit() {
        let mut state = VersionState::create().state;
        for _ in 0..5 {
            state = state.edit().state;
        }
        let before = state.next_version_counter;
        state = state.revert_to(1).unwrap().state;
        assert_eq!(
            state.next_version_counter, before,
            "counter must not rewind"
        );
        let e = state.edit();
        assert_eq!(e.new_version, before);
    }
}
