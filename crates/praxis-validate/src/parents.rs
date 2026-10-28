// SPDX-License-Identifier: Apache-2.0
//! Generic causal-parent checks (`spec/PROTOCOL.md` §12 step 4: "For each
//! parent in `prev`: if known, check `ts` monotonicity; if unknown ->
//! pending"; §5.3: `ts` MUST be ≥ every parent's `ts`).
//!
//! Steps 1 ("decode; reject if not canonical; enforce limits & `crit`") and 2
//! ("check `suite` supported; `v==1`") of §12 need no code here: both are
//! already enforced structurally by `praxis_types::decode_object` (M1-02)
//! and by `Suite`/`FormatVersion`'s own validating `Deserialize` impls
//! (M1-01) — by the time a Rust `Object` value exists at all, those two
//! steps have already passed.

use praxis_types::{Cid, Ts};

use crate::error::ValidateError;

/// What this validator's caller currently knows about some object id,
/// without specifying *how* it knows it (store-backed, in-memory, ...) —
/// that lookup needs I/O this crate deliberately does not have
/// (`docs/ARCHITECTURE.md` §3).
pub trait ParentLookup {
    /// Returns the `ts` of `cid` if it is already known (validated and
    /// stored), or `None` if it has not been seen yet.
    fn ts_of(&self, cid: &Cid) -> Option<Ts>;
}

/// Checks every entry in `prev` against `lookup`: known parents must have
/// `ts <= object_ts` (`spec/PROTOCOL.md` §5.3); unknown ones make this
/// object *pending* rather than immediately rejected. Returns the CIDs of
/// any still-unknown parents (empty if every parent is known and consistent).
///
/// # Errors
/// Returns [`ValidateError::TsNotMonotonic`] if a known parent's `ts` is
/// after `object_ts`.
pub fn check_parents(
    object_ts: Ts,
    prev: &[Cid],
    lookup: &impl ParentLookup,
) -> Result<Vec<Cid>, ValidateError> {
    let mut pending = Vec::new();
    for parent in prev {
        match lookup.ts_of(parent) {
            Some(parent_ts) => {
                if object_ts < parent_ts {
                    return Err(ValidateError::TsNotMonotonic(object_ts, parent_ts));
                }
            }
            None => pending.push(*parent),
        }
    }
    Ok(pending)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use praxis_types::CidCodec;

    use super::*;

    struct MapLookup(HashMap<Cid, Ts>);

    impl ParentLookup for MapLookup {
        fn ts_of(&self, cid: &Cid) -> Option<Ts> {
            self.0.get(cid).copied()
        }
    }

    fn cid(seed: &[u8]) -> Cid {
        Cid::from_canonical_bytes(CidCodec::DagCbor, seed)
    }

    #[test]
    fn all_parents_known_and_consistent_is_accepted_with_no_pending() {
        let parent = cid(b"parent");
        let lookup = MapLookup(HashMap::from([(parent, Ts::from_millis(100))]));
        let pending = check_parents(Ts::from_millis(200), &[parent], &lookup).unwrap();
        assert_eq!(pending, Vec::<Cid>::new());
    }

    #[test]
    fn a_known_parent_with_a_later_ts_is_rejected() {
        let parent = cid(b"parent");
        let lookup = MapLookup(HashMap::from([(parent, Ts::from_millis(500))]));
        let err = check_parents(Ts::from_millis(200), &[parent], &lookup).unwrap_err();
        assert!(
            matches!(err, ValidateError::TsNotMonotonic(got, want) if got == Ts::from_millis(200) && want == Ts::from_millis(500))
        );
    }

    #[test]
    fn equal_ts_to_a_parent_is_accepted() {
        let parent = cid(b"parent");
        let lookup = MapLookup(HashMap::from([(parent, Ts::from_millis(100))]));
        let pending = check_parents(Ts::from_millis(100), &[parent], &lookup).unwrap();
        assert_eq!(pending, Vec::<Cid>::new());
    }

    #[test]
    fn an_unknown_parent_is_reported_pending_not_rejected() {
        let unknown = cid(b"unknown");
        let lookup = MapLookup(HashMap::new());
        let pending = check_parents(Ts::from_millis(0), &[unknown], &lookup).unwrap();
        assert_eq!(pending, vec![unknown]);
    }

    #[test]
    fn a_mix_of_known_and_unknown_parents_checks_known_and_reports_unknown() {
        let known = cid(b"known");
        let unknown = cid(b"unknown");
        let lookup = MapLookup(HashMap::from([(known, Ts::from_millis(50))]));
        let pending = check_parents(Ts::from_millis(100), &[known, unknown], &lookup).unwrap();
        assert_eq!(pending, vec![unknown]);
    }

    #[test]
    fn no_parents_is_trivially_accepted() {
        let lookup = MapLookup(HashMap::new());
        let pending = check_parents(Ts::from_millis(0), &[], &lookup).unwrap();
        assert_eq!(pending, Vec::<Cid>::new());
    }
}
