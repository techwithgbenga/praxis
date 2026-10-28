// SPDX-License-Identifier: Apache-2.0
//
// Independent pure-TS verifier (no WASM, no dependency on praxis-wasm/
// praxis-core): a second, from-scratch implementation of canonical dag-cbor
// decode/encode, CIDv1, Ed25519 verification, the identity log, and the
// case-lifecycle rules, run against spec/test-vectors/** to cross-check the
// Rust reference implementation (docs/IMPLEMENTATION_PLAN.md M1-09). If
// Rust and this disagree on a vector, that is a spec or implementation bug:
// do not special-case either side.

export const VERIFIER_VERSION = "0.1.0";

export * from "./dagcbor.js";
export * from "./cid.js";
export * from "./object.js";
export * from "./sign.js";
export * from "./kdf.js";
export * from "./aead.js";
export * from "./commit.js";
export * from "./sealing.js";
export * from "./identity.js";
export * from "./caselog.js";
export * from "./scoring.js";
