// SPDX-License-Identifier: Apache-2.0
//
// Ed25519 object-signature verification with the domain-separation prefix
// from spec/PROTOCOL.md §5.2 baked in — mirrors
// crates/praxis-crypto/src/sign.rs's `verify_object` (sign is not needed
// here: every vector supplies an already-signed object; this verifier only
// ever checks signatures, never creates them).

import { ed25519 } from "@noble/curves/ed25519.js";

/** `spec/PROTOCOL.md` §5.2. */
export const OBJECT_SIGN_DOMAIN = new TextEncoder().encode("praxis/v1/object\0");

export function verifyObject(
  publicKey: Uint8Array,
  canonicalBytesWithoutSig: Uint8Array,
  signature: Uint8Array,
): boolean {
  const message = new Uint8Array(OBJECT_SIGN_DOMAIN.length + canonicalBytesWithoutSig.length);
  message.set(OBJECT_SIGN_DOMAIN, 0);
  message.set(canonicalBytesWithoutSig, OBJECT_SIGN_DOMAIN.length);
  return ed25519.verify(signature, message, publicKey);
}
