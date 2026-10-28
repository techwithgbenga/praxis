# ADR-0004: Separate `claims` from `decision` for selective disclosure
**Status:** Accepted · **Date:** 2026-10-28

## Context
Calibration needs only probabilities, resolution criteria, and outcomes. Bundling them with reasoning would force practitioners to reveal sensitive content to prove their track record.

## Decision
`claims` is its own event kind, sealed separately from `decision`. `attest` bundles reveal only claims+outcomes.

## Consequences
Enables privacy-preserving verification and a path to ZK proofs. Slightly more objects per case; clients hide this complexity.
