// SPDX-License-Identifier: Apache-2.0
//
// Independent pure-TS verifier (no WASM, no dependency on praxis-wasm/praxis-core):
// deliberately a second implementation of canonical dag-cbor decode, CIDv1, and
// Ed25519 verification, so spec/test-vectors/** has two independent checkers
// (docs/IMPLEMENTATION_PLAN.md M1-09). Grows alongside praxis-types/praxis-crypto
// in M1; starts empty.

export const VERIFIER_VERSION = "0.1.0";
