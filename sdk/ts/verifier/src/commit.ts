// SPDX-License-Identifier: Apache-2.0
//
// The sealed-body commitment scheme (spec/PROTOCOL.md §8.2):
// `commit = BLAKE3("praxis/v1/commit\x00" || plaintext_bytes)` — mirrors
// crates/praxis-crypto/src/commit.rs.

import { blake3 } from "@noble/hashes/blake3.js";

/** `spec/PROTOCOL.md` §8.2. */
export const COMMIT_DOMAIN = new TextEncoder().encode("praxis/v1/commit\0");

export function computeCommit(plaintextBytes: Uint8Array): Uint8Array {
  const message = new Uint8Array(COMMIT_DOMAIN.length + plaintextBytes.length);
  message.set(COMMIT_DOMAIN, 0);
  message.set(plaintextBytes, COMMIT_DOMAIN.length);
  return blake3(message);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

export function verifyCommit(commit: Uint8Array, plaintextBytes: Uint8Array): boolean {
  return bytesEqual(computeCommit(plaintextBytes), commit);
}
