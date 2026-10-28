// SPDX-License-Identifier: Apache-2.0
//
// Praxis TypeScript SDK (docs/CLI_AND_API.md §4). Typed wrappers over the
// wasm-bindgen build of `praxis-core` (crates/praxis-wasm), plus the pure
// independent verifier in `sdk/ts/verifier` (no WASM) used to cross-check the
// Rust reference implementation against spec/test-vectors/** (M1-09).
//
// TODO(M2+): `Praxis.open()`, `cases.open/decide`, `predict`, `calibration`,
// `consult`, `verifyObject`, `cid`, `scoring.*` per docs/CLI_AND_API.md §4.

export const SDK_VERSION = "0.1.0";
