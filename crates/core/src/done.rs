//! Done-state resolution (spec §5.4). Done is recorded *per version*; the
//! effective state for a version is the last record written against it, or
//! not-done if none. A new version starts not-done.

use crate::model::OkrDone;

/// Effective done state for `version`, given all done records for the OKR.
/// Returns the most recently set record for that version, else `false`.
pub fn effective_done(records: &[OkrDone], version: u64) -> bool {
    records
        .iter()
        .filter(|r| r.version == version)
        .max_by_key(|r| r.set_at)
        .map(|r| r.done)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(version: u64, done: bool, set_at: i64) -> OkrDone {
        OkrDone {
            okr_id: "o1".into(),
            version,
            done,
            set_by: "u".into(),
            set_at,
        }
    }

    #[test]
    fn no_record_is_not_done() {
        assert!(!effective_done(&[], 1));
        assert!(!effective_done(&[rec(2, true, 10)], 1));
    }

    #[test]
    fn latest_record_for_version_wins() {
        let records = vec![rec(1, true, 10), rec(1, false, 20), rec(1, true, 15)];
        assert!(!effective_done(&records, 1)); // set_at=20 is latest -> false
    }

    #[test]
    fn done_is_isolated_per_version() {
        // A new version (3) starts not-done even if version 1 was done.
        let records = vec![rec(1, true, 10)];
        assert!(effective_done(&records, 1));
        assert!(!effective_done(&records, 3));
    }
}
