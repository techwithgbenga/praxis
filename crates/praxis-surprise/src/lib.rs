// SPDX-License-Identifier: Apache-2.0
//! The Surprise Engine (`docs/SURPRISE_ENGINE.md`): trigger scoring
//! (`S = -ln q(chosen)`, stakes weight `w`, `T = S*w`), gating, budget/timing, and
//! the per-user adaptive threshold. Model-agnostic: takes a committed `Prediction`
//! and stakes, never touches a model directly.
//!
//! Pure and deterministic given inputs and a seeded RNG (fully unit-testable, per
//! the `ElicitationPolicy` trait in `docs/SURPRISE_ENGINE.md` §9).
//!
//! M4-06 fills this in.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

// OPEN(Q-003): optimal interruption policy (value of information vs. fatigue) is an
// open research question (docs/EVALUATION.md §7); this crate implements the v0.1
// heuristic policy, not a claim that it is optimal.
