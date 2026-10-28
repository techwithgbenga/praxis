// SPDX-License-Identifier: Apache-2.0
//! WASM bindings over `praxis-core`, built with `wasm-bindgen` (`docs/TECH_STACK.md`
//! §1). The TS SDK (`sdk/ts`) wraps this with typed convenience APIs; `sdk/ts`
//! additionally ships a pure-TS independent verifier so the two implementations
//! can cross-check each other (ADR intent: guard against spec drift).
//!
//! Empty until `praxis-core` has a surface worth exposing (M2+).
#![forbid(unsafe_code)]
#![deny(missing_docs)]
