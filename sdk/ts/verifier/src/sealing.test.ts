// SPDX-License-Identifier: Apache-2.0
//
// Cross-checks `spec/test-vectors/sealing/*` (M1-08) against this package's
// independent `unseal_body` (M1-09). Only the unseal direction is checked
// (see sealing.ts's module docs): `seal_body` is inherently randomized
// (fresh salt/nonce per call), so there is nothing cross-implementation to
// compare on the seal side beyond what `encodeCanonical`'s own canonical.rs
// vectors already cover.

import assert from "node:assert/strict";
import { test } from "node:test";

import { Cid } from "./cid.js";
import { encodeCanonical, type Value } from "./dagcbor.js";
import { AeadError } from "./aead.js";
import { decodeObjectMap } from "./object.js";
import { CommitMismatchError, unsealBody } from "./sealing.js";
import { hexToBytes, loadVector } from "./vectors.js";

interface SealingInput {
  readonly case_key_hex?: string;
  readonly wrong_case_key_hex?: string;
  readonly kind: string;
  readonly index_in_case: number;
  readonly case_cid_bytes_hex: string;
  readonly author: string;
  readonly sealed_body_dag_cbor_hex: string;
}

function decodeSealedBody(hex: string): Map<string, Value> {
  // `decodeObjectMap` requires a top-level map, which a bare `SealedBody` is
  // too (`{sealed: {...}, commit, ?rcpt}`) — reused here for its map-coercion,
  // not because a `SealedBody` is an `Object` envelope.
  return decodeObjectMap(hexToBytes(hex));
}

test("sealing/seal-001: seal_body then unseal_body recovers the original content", () => {
  const vector = loadVector("sealing/seal-001-roundtrip");
  const input = vector.input as SealingInput;
  const expected = vector.expected as {
    unseal_succeeds: boolean;
    revealed_plain_dag_cbor_hex: string;
    plaintext_bucket_len: number;
  };
  assert.ok(input.case_key_hex, "expected case_key_hex");

  const caseKey = hexToBytes(input.case_key_hex);
  const caseCid = Cid.fromRawBytes(hexToBytes(input.case_cid_bytes_hex));
  const sealedBody = decodeSealedBody(input.sealed_body_dag_cbor_hex);

  const revealed = unsealBody(sealedBody, caseKey, input.kind, input.index_in_case, caseCid, input.author);
  assert.equal(expected.unseal_succeeds, true);
  const gotHex = Buffer.from(encodeCanonical(revealed.plain)).toString("hex");
  assert.equal(gotHex, expected.revealed_plain_dag_cbor_hex);

  const sealed = sealedBody.get("sealed");
  assert.ok(sealed instanceof Map);
  const ct = sealed.get("ct");
  assert.ok(ct instanceof Uint8Array);
  assert.equal(ct.length - 16, expected.plaintext_bucket_len);
});

test("sealing/reject-001: a tampered ciphertext fails AEAD authentication", () => {
  const vector = loadVector("sealing/reject-001-tampered-ciphertext");
  const input = vector.input as SealingInput;
  const expected = vector.expected as { error: string };
  assert.ok(input.case_key_hex, "expected case_key_hex");

  const caseKey = hexToBytes(input.case_key_hex);
  const caseCid = Cid.fromRawBytes(hexToBytes(input.case_cid_bytes_hex));
  const sealedBody = decodeSealedBody(input.sealed_body_dag_cbor_hex);

  assert.throws(
    () => {
      unsealBody(sealedBody, caseKey, input.kind, input.index_in_case, caseCid, input.author);
    },
    (err: unknown) => {
      assert.ok(err instanceof AeadError, `expected AeadError, got ${String(err)}`);
      assert.equal("E_AEAD", expected.error);
      return true;
    },
  );
});

test("sealing/reject-002: a tampered commit is caught by reveal-verify", () => {
  const vector = loadVector("sealing/reject-002-tampered-commit");
  const input = vector.input as SealingInput;
  const expected = vector.expected as { error: string };
  assert.ok(input.case_key_hex, "expected case_key_hex");

  const caseKey = hexToBytes(input.case_key_hex);
  const caseCid = Cid.fromRawBytes(hexToBytes(input.case_cid_bytes_hex));
  const sealedBody = decodeSealedBody(input.sealed_body_dag_cbor_hex);

  assert.throws(
    () => {
      unsealBody(sealedBody, caseKey, input.kind, input.index_in_case, caseCid, input.author);
    },
    (err: unknown) => {
      assert.ok(err instanceof CommitMismatchError, `expected CommitMismatchError, got ${String(err)}`);
      assert.equal("E_COMMIT_MISMATCH", expected.error);
      return true;
    },
  );
});

test("sealing/reject-003: the wrong case key fails AEAD authentication", () => {
  const vector = loadVector("sealing/reject-003-wrong-case-key");
  const input = vector.input as SealingInput;
  const expected = vector.expected as { error: string };
  assert.ok(input.wrong_case_key_hex, "expected wrong_case_key_hex");

  const wrongCaseKey = hexToBytes(input.wrong_case_key_hex);
  const caseCid = Cid.fromRawBytes(hexToBytes(input.case_cid_bytes_hex));
  const sealedBody = decodeSealedBody(input.sealed_body_dag_cbor_hex);

  assert.throws(
    () => {
      unsealBody(sealedBody, wrongCaseKey, input.kind, input.index_in_case, caseCid, input.author);
    },
    (err: unknown) => {
      assert.ok(err instanceof AeadError, `expected AeadError, got ${String(err)}`);
      assert.equal("E_AEAD", expected.error);
      return true;
    },
  );
});
