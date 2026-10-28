// SPDX-License-Identifier: Apache-2.0
//
// `unseal_body` only (spec/PROTOCOL.md §8): every `sealing/*` vector gives an
// already-sealed body and expects either successful unsealing or a specific
// rejection — mirrors crates/praxis-crypto/src/seal.ts's `unseal_body`.
// `seal_body` (padding-bucket selection, salt/nonce generation) is not
// reimplemented here: it is inherently randomized, so a vector can only
// meaningfully check the unseal direction cross-implementation (see
// sdk/ts/verifier/src/sealing.test.ts's module docs).

import { AeadError, aeadOpen, buildAad } from "./aead.js";
import type { Cid } from "./cid.js";
import { verifyCommit } from "./commit.js";
import { decodeCanonical, DecodeError, type Value } from "./dagcbor.js";
import { deriveBodyKey } from "./kdf.js";

function asMap(value: Value | undefined, context: string): Map<string, Value> {
  if (!(value instanceof Map)) {
    throw new DecodeError("E_DECODE", `expected a map for ${context}`);
  }
  return value;
}

function asBytes(value: Value | undefined, context: string): Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new DecodeError("E_DECODE", `expected bytes for ${context}`);
  }
  return value;
}

export class CommitMismatchError extends Error {
  public constructor() {
    super("decrypted plaintext does not match the sealed body's commit");
    this.name = "CommitMismatchError";
  }
}

export interface UnsealedBody {
  readonly plain: Value;
  readonly salt: Uint8Array;
  readonly pad: Uint8Array | null;
}

/** Unseals a `sealed-body` map (`{sealed: {alg, nonce, ct}, commit, ?rcpt}`,
 * spec/PROTOCOL.md §8.1) decoded from dag-cbor: derives the body key (§8.3),
 * AEAD-decrypts, verifies the decrypted plaintext against `commit` (§8.2),
 * then decodes it back to `{plain, salt, ?pad}`.
 *
 * @throws {AeadError} if decryption fails (wrong key, tampered ciphertext).
 * @throws {CommitMismatchError} if the decrypted plaintext does not hash to
 * `commit`. */
export function unsealBody(
  sealedBody: Map<string, Value>,
  caseKey: Uint8Array,
  kind: string,
  indexInCase: number,
  caseCid: Cid,
  author: string,
): UnsealedBody {
  const sealed = asMap(sealedBody.get("sealed"), "sealed-body.sealed");
  const nonce = asBytes(sealed.get("nonce"), "sealed-body.sealed.nonce");
  const ct = asBytes(sealed.get("ct"), "sealed-body.sealed.ct");
  const commit = asBytes(sealedBody.get("commit"), "sealed-body.commit");

  const bodyKey = deriveBodyKey(caseKey, kind, indexInCase);
  const aad = buildAad(kind, caseCid, author);
  let plaintext: Uint8Array;
  try {
    plaintext = aeadOpen(bodyKey, nonce, aad, ct);
  } catch (err) {
    if (err instanceof AeadError) {
      throw err;
    }
    throw new AeadError();
  }
  if (!verifyCommit(commit, plaintext)) {
    throw new CommitMismatchError();
  }

  const plainBody = asMap(decodeCanonical(plaintext), "plain-body");
  const plain = plainBody.get("plain");
  if (plain === undefined) {
    throw new DecodeError("E_DECODE", "plain-body missing `plain`");
  }
  const salt = asBytes(plainBody.get("salt"), "plain-body.salt");
  const padValue = plainBody.get("pad");
  const pad = padValue === undefined ? null : asBytes(padValue, "plain-body.pad");
  return { plain, salt, pad };
}
