// SPDX-License-Identifier: Apache-2.0
//! The Praxis protocol reference validator (`spec/PROTOCOL.md` §12).
//!
//! Scope: this crate has no I/O (`docs/ARCHITECTURE.md` §3), so it provides
//! the *rules* as composable, independently testable pieces rather than one
//! `validate(bytes) -> Accepted/Rejected` entry point:
//! - [`parse_content`]: kind-dispatched `Value` -> typed `Content` (§12 step 6).
//! - [`check_parents`]: `ts` monotonicity against known causal parents, and
//!   pending-parent classification for unknown ones (§12 step 4).
//! - [`CaseLog`]: the case-lifecycle state machine, rules C1-C8 (§6).
//!
//! Steps 1-2 of §12 (canonical decode, `crit`, `suite`/`v` support) need no
//! code here: they're already enforced structurally by
//! `praxis_types::decode_object` and by `Suite`/`FormatVersion`'s own
//! validating `Deserialize` (M1-01/M1-02) — by the time a Rust `Object`
//! value exists, those have already passed. Step 3 (signer authorization +
//! signature verification) is `praxis-identity`'s `IdentityLog`
//! (`is_authorized` plus `praxis_crypto::verify_object`), not duplicated here.
//!
//! Orchestrating all of the above end to end — deciding which `CaseLog` or
//! `IdentityLog` a given object belongs to, persisting them, looking up
//! causal parents by CID — needs real storage this crate doesn't have;
//! that's `praxis-core`'s job (M2-05).
//!
//! Errors are typed (`thiserror`), with stable `E_*` codes (AGENTS.md §3 `DoD`).
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod case_log;
mod content_dispatch;
mod error;
mod parents;

pub use case_log::CaseLog;
pub use content_dispatch::parse_content;
pub use error::ValidateError;
pub use parents::{check_parents, ParentLookup};

// OPEN(Q-010): legal-discoverability / "privileged mode" implications of validation
// and storage are a design question, not a validator concern; tracked in
// docs/EVALUATION.md §7 and docs/PRIVACY_AND_THREAT_MODEL.md (T12).
