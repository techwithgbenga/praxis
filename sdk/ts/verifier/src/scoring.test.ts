// SPDX-License-Identifier: Apache-2.0
//
// Cross-checks `spec/test-vectors/scoring/basic-001` (M1-08, hand-worked from
// spec/SCORING.md §9) against this package's independent Brier/BSS/log-score
// implementation (M1-09). Floats, so compared with a tolerance, not exact
// equality (spec/SCORING.md §1: "1e-9" for Rust-vs-TS agreement).

import assert from "node:assert/strict";
import { test } from "node:test";

import { brierScore, logScore, skillVsReference, type ScoredClaim } from "./scoring.js";
import { loadVector } from "./vectors.js";

function approxEqual(actual: number, expected: number, tolerance: number): void {
  assert.ok(
    Math.abs(actual - expected) < tolerance,
    `expected ${String(actual)} to be within ${String(tolerance)} of ${String(expected)}`,
  );
}

test("scoring/basic-001: Brier/BSS/log-score match the hand-worked example", () => {
  const vector = loadVector("scoring/basic-001");
  const input = vector.input as { claims: { p: number; y: number }[]; reference_p: number };
  const expected = vector.expected as { bs: number; bs_ref: number; bss: number; ls: number };

  const claims: ScoredClaim[] = input.claims.map((c) => ({ p: c.p, y: c.y === 1 ? 1 : 0 }));

  approxEqual(brierScore(claims), expected.bs, 1e-9);
  approxEqual(skillVsReference(claims, input.reference_p), expected.bss, 1e-9);
  approxEqual(logScore(claims), expected.ls, 1e-9);
});
