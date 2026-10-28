// SPDX-License-Identifier: Apache-2.0
//! Praxis protocol scalar types, the object envelope, and content enums
//! (`spec/PROTOCOL.md`, `spec/praxis-v0.1.cddl`).
//!
//! This crate has no dependency on any other `praxis-*` crate and performs no I/O
//! (docs/ARCHITECTURE.md §3). Everything here is pure data + validation of shapes.
//!
//! M1-01 fills this in: `Ppm`, `Mnat`, `Ts`, `Did`, `Kid` newtypes, the `Object`
//! envelope, and the content enums, each with range-enforcing constructors and
//! serde round-trip tests.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
