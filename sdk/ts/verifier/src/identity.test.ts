// SPDX-License-Identifier: Apache-2.0
//
// Cross-checks `spec/test-vectors/identity/*` (M1-08) against this
// package's independent `IdentityLog` (M1-09).

import assert from "node:assert/strict";
import { test } from "node:test";

import { decodeIdContent, IdentityError, IdentityLog } from "./identity.js";
import { decodeObjectMap, objectPlainContent } from "./object.js";
import { hexToBytes, loadVector } from "./vectors.js";

interface VectorObject {
  readonly kind: string;
  readonly signer: string;
  readonly ts: number;
  readonly dag_cbor_hex: string;
}

function contentOf(bytes: Uint8Array): ReturnType<typeof decodeIdContent> {
  const object = decodeObjectMap(bytes);
  return decodeIdContent(objectPlainContent(object));
}

test("identity/chain-001: genesis -> rotate -> delegate, is_authorized matches PIP-0003", () => {
  const vector = loadVector("identity/chain-001-genesis-rotate-delegate");
  const input = vector.input as { objects: VectorObject[] };
  const expected = vector.expected as {
    queries: { kid: string; ts: number; authorized: boolean }[];
  };

  const [genesisObj, rotateObj, delegateObj] = input.objects;
  assert.ok(genesisObj && rotateObj && delegateObj, "expected exactly 3 objects");

  const genesisBytes = hexToBytes(genesisObj.dag_cbor_hex);
  const log = IdentityLog.genesis(genesisBytes, contentOf(genesisBytes));
  log.apply(hexToBytes(rotateObj.dag_cbor_hex), contentOf(hexToBytes(rotateObj.dag_cbor_hex)));
  log.apply(hexToBytes(delegateObj.dag_cbor_hex), contentOf(hexToBytes(delegateObj.dag_cbor_hex)));

  for (const query of expected.queries) {
    const actual = log.isAuthorized(query.kid, BigInt(query.ts), null);
    assert.equal(actual, query.authorized, `kid=${query.kid} ts=${String(query.ts)}`);
  }
});

test("identity/reject-001: a device key cannot sign id-delegate", () => {
  const vector = loadVector("identity/reject-001-device-key-cannot-delegate");
  const input = vector.input as { setup_objects: VectorObject[]; rejected_object: VectorObject };
  const expected = vector.expected as { error: string };

  const [genesisObj, delegateObj] = input.setup_objects;
  assert.ok(genesisObj && delegateObj, "expected exactly 2 setup objects");

  const genesisBytes = hexToBytes(genesisObj.dag_cbor_hex);
  const log = IdentityLog.genesis(genesisBytes, contentOf(genesisBytes));
  log.apply(hexToBytes(delegateObj.dag_cbor_hex), contentOf(hexToBytes(delegateObj.dag_cbor_hex)));

  const badBytes = hexToBytes(input.rejected_object.dag_cbor_hex);
  assert.throws(
    () => {
      log.apply(badBytes, contentOf(badBytes));
    },
    (err: unknown) => {
      assert.ok(err instanceof IdentityError);
      assert.equal(err.code, expected.error);
      return true;
    },
  );
});
