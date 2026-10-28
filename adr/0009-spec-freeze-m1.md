# ADR-0009: Spec freeze for M1
**Status:** Accepted · **Date:** 2026-10-28

## Context
`docs/IMPLEMENTATION_PLAN.md` M0-07 requires a human maintainer to review
`spec/PROTOCOL.md`, `spec/praxis-v0.1.cddl`, `spec/SCORING.md`, and `spec/POLICY.md`,
open tracking issues for every `OPEN(Q-*)` item in `docs/EVALUATION.md` §7, and
explicitly sign off that spec v0.1-draft is frozen before M1 (trust kernel:
types/crypto/identity/validation/vectors) begins. M0 (Cargo workspace, CI, lint
gates, CDDL smoke-check, mdBook site, SDK/apprentice/desk skeletons) is otherwise
complete as of this commit.

## Decision
Maintainer **techwithgbenga** reviewed the spec set above and signs off: spec
v0.1-draft is frozen for M1. Any change discovered to be necessary during M1
implementation is handled as a spec bug fix via PIP (`spec/pips/`), not a silent
divergence (`AGENTS.md` §0.1).

Tracking issues for `docs/EVALUATION.md` §7's open questions (Q-001 through Q-011)
are opened against the GitHub repository once it exists (this repo was authored
and built offline; see `README.md` "Getting the code on GitHub"). Until then, each
question is cross-referenced in code via `// OPEN(Q-xxx)` comments at the point in
the trust-kernel crates where the question is load-bearing (e.g.
`crates/praxis-crypto/src/lib.rs` for Q-008, `crates/praxis-validate/src/lib.rs`
for Q-010, `crates/praxis-surprise/src/lib.rs` for Q-003), per `AGENTS.md` §0.6.

## Consequences
M1 may begin. Any later spec change requires a PIP and, if it changes signed-object
shapes, a new test-vector generation pass (`docs/IMPLEMENTATION_PLAN.md` M1-08/09)
before the change can land in `main`.
