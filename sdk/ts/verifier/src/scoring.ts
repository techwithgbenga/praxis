// SPDX-License-Identifier: Apache-2.0
//
// Brier score / skill-vs-reference (BSS) / log score (spec/SCORING.md §2-3)
// — there is no `praxis-score` crate to cross-check against yet (it doesn't
// exist before a later milestone); this computes the formulas directly from
// the spec text, independently of how `crates/praxis-validate`'s own
// `gen_vectors/scoring.rs` computed `spec/test-vectors/scoring/basic-001`.

/** `spec/SCORING.md` §4's `ln` clipping bound. */
const LOG_CLIP = 1e-3;

export interface ScoredClaim {
  readonly p: number;
  readonly y: 0 | 1;
}

export function brierScore(claims: readonly ScoredClaim[]): number {
  const sum = claims.reduce((acc, { p, y }) => acc + (p - y) ** 2, 0);
  return sum / claims.length;
}

export function brierAgainstReference(claims: readonly ScoredClaim[], referenceP: number): number {
  const sum = claims.reduce((acc, { y }) => acc + (referenceP - y) ** 2, 0);
  return sum / claims.length;
}

export function skillVsReference(claims: readonly ScoredClaim[], referenceP: number): number {
  return 1 - brierScore(claims) / brierAgainstReference(claims, referenceP);
}

export function logScore(claims: readonly ScoredClaim[]): number {
  const sum = claims.reduce((acc, { p, y }) => {
    const pY = y === 1 ? p : 1 - p;
    const clipped = Math.min(Math.max(pY, LOG_CLIP), 1 - LOG_CLIP);
    return acc - Math.log(clipped);
  }, 0);
  return sum / claims.length;
}
