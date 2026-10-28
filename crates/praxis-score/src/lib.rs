// SPDX-License-Identifier: Apache-2.0
//! Praxis calibration & scoring (`spec/SCORING.md`): proper scoring rules (Brier,
//! log score), skill-vs-reference (BSS), adaptive-bin reliability/ECE, bootstrap
//! CIs, Murphy decomposition, AUC, overconfidence index, and sample-size honesty
//! labels.
//!
//! Pure functions only; **no I/O**, ever (`docs/ARCHITECTURE.md` §3). Must match the
//! TS port to within 1e-9 on golden vectors (`spec/test-vectors/scoring/*`).
//!
//! M3-01 fills this in.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
