// SPDX-License-Identifier: Apache-2.0
//
// Cross-checks `spec/test-vectors/canonical/*` (M1-08) against this
// package's independent dag-cbor decode/encode (M1-09). If this disagrees
// with the Rust reference, that's a spec or implementation bug — never
// special-case either side (docs/IMPLEMENTATION_PLAN.md M1-09).

import assert from "node:assert/strict";
import { test } from "node:test";

import { decodeCanonical, DecodeError, encodeCanonical, Value } from "./dagcbor.js";
import { hexToBytes, loadVector } from "./vectors.js";

function jsonToValue(input: unknown): Value {
  if (input === null) return null;
  if (typeof input === "boolean") return input;
  if (typeof input === "number") {
    if (!Number.isInteger(input)) {
      throw new Error(`non-integer number in a canonical vector's plain JSON input: ${String(input)}`);
    }
    return BigInt(input);
  }
  if (typeof input === "string") return input;
  if (Array.isArray(input)) return input.map(jsonToValue);
  if (typeof input === "object") {
    const map = new Map<string, Value>();
    for (const [k, v] of Object.entries(input)) {
      map.set(k, jsonToValue(v));
    }
    return map;
  }
  throw new Error(`cannot convert JSON value to a dag-cbor Value: ${JSON.stringify(input)}`);
}

function hexOf(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

test("canonical/int-001: encodes a negative integer canonically", () => {
  const vector = loadVector("canonical/int-001");
  const expected = vector.expected as { dag_cbor_hex: string };
  const got = encodeCanonical(jsonToValue(vector.input));
  assert.equal(hexOf(got), expected.dag_cbor_hex);
});

test("canonical/text-001: encodes NFC text as a dag-cbor text string", () => {
  const vector = loadVector("canonical/text-001");
  const expected = vector.expected as { dag_cbor_hex: string };
  const got = encodeCanonical(jsonToValue(vector.input));
  assert.equal(hexOf(got), expected.dag_cbor_hex);
});

test("canonical/bytes-001: a byte string is distinct from an array of the same integers", () => {
  const vector = loadVector("canonical/bytes-001");
  const input = vector.input as { kind: string; hex: string };
  const expected = vector.expected as { dag_cbor_hex: string };
  assert.equal(input.kind, "bytes");
  const got = encodeCanonical(hexToBytes(input.hex));
  assert.equal(hexOf(got), expected.dag_cbor_hex);
});

test("canonical/bytes-002: empty array and empty bytes are distinct", () => {
  const vector = loadVector("canonical/bytes-002-empty-array-vs-empty-bytes");
  const expected = vector.expected as {
    empty_array_hex: string;
    empty_bytes_hex: string;
    distinct: boolean;
  };
  const emptyArrayHex = hexOf(encodeCanonical([]));
  const emptyBytesHex = hexOf(encodeCanonical(new Uint8Array(0)));
  assert.equal(emptyArrayHex, expected.empty_array_hex);
  assert.equal(emptyBytesHex, expected.empty_bytes_hex);
  assert.equal(emptyArrayHex !== emptyBytesHex, expected.distinct);

  // And the reverse direction: decoding each hex must produce the *other*
  // runtime shape, not silently alias to one.
  const decodedArray = decodeCanonical(hexToBytes(expected.empty_array_hex));
  const decodedBytes = decodeCanonical(hexToBytes(expected.empty_bytes_hex));
  assert.ok(Array.isArray(decodedArray));
  assert.ok(decodedBytes instanceof Uint8Array);
});

test("canonical/map-001: map keys sort by (length, then bytewise)", () => {
  const vector = loadVector("canonical/map-001-key-order");
  const expected = vector.expected as { dag_cbor_hex: string };
  const got = encodeCanonical(jsonToValue(vector.input));
  assert.equal(hexOf(got), expected.dag_cbor_hex);
});

function expectRejection(id: string): void {
  const vector = loadVector(id);
  const input = vector.input as { dag_cbor_hex: string };
  const expected = vector.expected as { error: string };
  assert.throws(
    () => {
      decodeCanonical(hexToBytes(input.dag_cbor_hex));
    },
    (err: unknown) => {
      assert.ok(err instanceof DecodeError, `expected a DecodeError, got ${String(err)}`);
      assert.equal(err.code, expected.error);
      return true;
    },
  );
}

test("canonical/reject-001: non-minimal integer is rejected", () => {
  expectRejection("canonical/reject-001-non-minimal-int");
});
test("canonical/reject-002: duplicate map key is rejected", () => {
  expectRejection("canonical/reject-002-duplicate-map-key");
});
test("canonical/reject-003: indefinite-length item is rejected", () => {
  expectRejection("canonical/reject-003-indefinite-length");
});
test("canonical/reject-004: a CBOR tag other than 42 is rejected", () => {
  expectRejection("canonical/reject-004-tag-other-than-42");
});
test("canonical/reject-005: a float is rejected", () => {
  expectRejection("canonical/reject-005-float");
});
