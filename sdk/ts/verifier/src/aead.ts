// SPDX-License-Identifier: Apache-2.0
//
// XChaCha20-Poly1305 AEAD (spec/PROTOCOL.md §2, §8.3):
// `ct = XChaCha20-Poly1305(key=bodykey, nonce, aad=kind||case||author, plaintext)`
// — mirrors crates/praxis-crypto/src/aead.rs.

import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";

import type { Cid } from "./cid.js";

/** `aad=kind||case||author` (spec/PROTOCOL.md §8.3, byte encodings per
 * spec/pips/0001-sealing-byte-encoding.md): `kind`'s UTF-8 bytes, the
 * `case` CID's raw multiformats binary encoding, then `author`'s UTF-8
 * bytes. */
export function buildAad(kind: string, caseCid: Cid, author: string): Uint8Array {
  const kindBytes = new TextEncoder().encode(kind);
  const caseBytes = caseCid.toBytes();
  const authorBytes = new TextEncoder().encode(author);
  const aad = new Uint8Array(kindBytes.length + caseBytes.length + authorBytes.length);
  aad.set(kindBytes, 0);
  aad.set(caseBytes, kindBytes.length);
  aad.set(authorBytes, kindBytes.length + caseBytes.length);
  return aad;
}

/** Decryption/authentication failed: wrong key, wrong nonce, wrong AAD, or a
 * tampered ciphertext. */
export class AeadError extends Error {
  public constructor() {
    super("AEAD decryption failed");
    this.name = "AeadError";
  }
}

export function aeadOpen(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  try {
    return xchacha20poly1305(key, nonce, aad).decrypt(ciphertext);
  } catch {
    throw new AeadError();
  }
}
