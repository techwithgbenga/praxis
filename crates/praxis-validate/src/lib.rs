// SPDX-License-Identifier: Apache-2.0
//! The Praxis protocol reference validator (`spec/PROTOCOL.md` §12): canonical
//! dag-cbor decode, identity/signature resolution, causal (`prev`/`ts`) checks, and
//! the case-lifecycle rules C1-C8 (`spec/PROTOCOL.md` §6).
//!
//! Errors are typed (`thiserror`), with stable `E_*` codes (AGENTS.md §3 `DoD`).
//!
//! M1-02 (codec), M1-03 (CIDs) and M1-07 fill this in.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

// OPEN(Q-010): legal-discoverability / "privileged mode" implications of validation
// and storage are a design question, not a validator concern; tracked in
// docs/EVALUATION.md §7 and docs/PRIVACY_AND_THREAT_MODEL.md (T12).
