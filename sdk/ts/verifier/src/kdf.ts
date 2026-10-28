// SPDX-License-Identifier: Apache-2.0
//
// HKDF-SHA256 per-event body key derivation (spec/PROTOCOL.md §8.3; byte
// encodings per spec/pips/0001-sealing-byte-encoding.md) — mirrors
// crates/praxis-crypto/src/kdf.ts's `derive_body_key`.

import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

/** `salt="praxis/v1/bodykey"` (spec/PROTOCOL.md §8.3). */
export const BODYKEY_SALT = new TextEncoder().encode("praxis/v1/bodykey");

/** `HKDF-SHA256(ikm=CK, salt="praxis/v1/bodykey",
 * info=kind||0x00||u32(index_in_case))`, with `kind`'s UTF-8 bytes and a
 * big-endian u32, per PIP-0001. */
export function deriveBodyKey(caseKey: Uint8Array, kind: string, indexInCase: number): Uint8Array {
  const kindBytes = new TextEncoder().encode(kind);
  const info = new Uint8Array(kindBytes.length + 1 + 4);
  info.set(kindBytes, 0);
  info[kindBytes.length] = 0x00;
  new DataView(info.buffer).setUint32(kindBytes.length + 1, indexInCase, false);
  return hkdf(sha256, caseKey, BODYKEY_SALT, info, 32);
}
