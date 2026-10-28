// SPDX-License-Identifier: Apache-2.0
//! The Praxis local store: SQLite (WAL) persistence for the object log, derived
//! tables, blobs, and the keystore interface (`docs/ARCHITECTURE.md` §5).
//!
//! Only this crate (and `praxis-sync`/`praxis-relay` for network) touches
//! disk/network among the trust-kernel crates (`docs/ARCHITECTURE.md` §3 rules).
//!
//! **Event-sourcing invariant** (must hold, tested): dropping all derived tables and
//! replaying `objects` reproduces them byte-identically.
//!
//! M2-01/M2-02/M2-03 fill this in.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
