// SPDX-License-Identifier: Apache-2.0
//
// Cross-checks `spec/test-vectors/events/*` (M1-08) against this package's
// independent `CaseLog` (M1-09): the full open->prediction->decision->
// claims->outcome lifecycle, plus one rejection per case-lifecycle rule
// C1-C8.

import assert from "node:assert/strict";
import { test } from "node:test";

import { CaseLog, ValidateError } from "./caselog.js";
import { hexToBytes, loadVector } from "./vectors.js";

interface VectorObject {
  readonly dag_cbor_hex: string;
}

function bytesOf(obj: VectorObject): Uint8Array {
  return hexToBytes(obj.dag_cbor_hex);
}

test("events/valid-001: a full open->prediction->decision->claims->outcome lifecycle is accepted", () => {
  const vector = loadVector("events/valid-001-full-lifecycle");
  const input = vector.input as { objects: VectorObject[] };
  const expected = vector.expected as { valid: boolean; has_decision: boolean; has_outcome: boolean };

  const [open, prediction, decision, claims, outcome] = input.objects;
  assert.ok(open && prediction && decision && claims && outcome, "expected exactly 5 objects");

  const log = CaseLog.open(bytesOf(open));
  log.apply(bytesOf(prediction));
  log.apply(bytesOf(decision));
  log.apply(bytesOf(claims));
  log.apply(bytesOf(outcome));

  assert.equal(expected.valid, true);
  assert.equal(log.hasDecision, expected.has_decision);
  assert.equal(log.hasOutcome, expected.has_outcome);
});

function expectRejectionAfterSetup(id: string): void {
  const vector = loadVector(id);
  const input = vector.input as { setup_objects: VectorObject[]; rejected_object: VectorObject };
  const expected = vector.expected as { error: string };

  const [open, ...rest] = input.setup_objects;
  assert.ok(open, "expected at least the open object in setup_objects");
  const log = CaseLog.open(bytesOf(open));
  for (const obj of rest) {
    log.apply(bytesOf(obj));
  }

  assert.throws(
    () => {
      log.apply(bytesOf(input.rejected_object));
    },
    (err: unknown) => {
      assert.ok(err instanceof ValidateError, `expected a ValidateError, got ${String(err)}`);
      assert.equal(err.code, expected.error);
      return true;
    },
  );
}

test("events/reject-c1: open must not itself carry a case field", () => {
  const vector = loadVector("events/reject-c1-open-with-case-field");
  const input = vector.input as { object: VectorObject };
  const expected = vector.expected as { error: string };
  assert.throws(
    () => {
      CaseLog.open(bytesOf(input.object));
    },
    (err: unknown) => {
      assert.ok(err instanceof ValidateError);
      assert.equal(err.code, expected.error);
      return true;
    },
  );
});

test("events/reject-c2: decision requires a prior prediction", () => {
  expectRejectionAfterSetup("events/reject-c2-decision-without-prediction");
});
test("events/reject-c3: claims must causally follow the decision", () => {
  expectRejectionAfterSetup("events/reject-c3-claims-not-after-decision");
});
test("events/reject-c4: claim ids are unique within a claims object", () => {
  expectRejectionAfterSetup("events/reject-c4-duplicate-claim-id");
});
test("events/reject-c5: amend cannot reuse an existing claim id", () => {
  expectRejectionAfterSetup("events/reject-c5-amend-reuses-claim-id");
});
test("events/reject-c6: outcome must resolve a known claim id", () => {
  expectRejectionAfterSetup("events/reject-c6-outcome-unknown-claim");
});
test("events/reject-c8: abandon after a decision is rejected", () => {
  expectRejectionAfterSetup("events/reject-c8-abandon-after-decision");
});

test("events/accept-c7: retract is a tombstone, not a rejection", () => {
  const vector = loadVector("events/accept-c7-retract-is-tombstone");
  const input = vector.input as { setup_objects: VectorObject[]; object: VectorObject };
  const expected = vector.expected as { valid: boolean; is_retracted: boolean };

  const [open] = input.setup_objects;
  assert.ok(open, "expected the open object in setup_objects");
  const log = CaseLog.open(bytesOf(open));
  log.apply(bytesOf(input.object));

  assert.equal(expected.valid, true);
  assert.equal(log.isRetracted, expected.is_retracted);
});
