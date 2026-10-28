// SPDX-License-Identifier: Apache-2.0
//! `praxis-core`: the stable public façade over the trust kernel
//! (`docs/ARCHITECTURE.md` §2-§3). `praxis-cli`, `praxisd`, `praxis-wasm` and
//! `praxis-ffi` depend only on this crate, never on the inner crates directly, so
//! the public API surface stays small and reviewable.
//!
//! M2-05 fills in the first façade flows: `open`/`decide`/`claims`/`amend`/
//! `abandon`, including the "no-apprentice mode" that still commits a prior-model
//! `prediction` so rule C2 (anti-hindsight) is always honored.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
