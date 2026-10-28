// SPDX-License-Identifier: Apache-2.0
//! Praxis protocol identity: the signed `id-genesis` / `id-rotate` / `id-delegate` /
//! `id-revoke` log, and key-validity-at-time resolution (`spec/PROTOCOL.md` §4,
//! `spec/pips/0003-identity-log-semantics.md`).
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod error;
mod log;

pub use error::IdentityError;
pub use log::{IdentityLog, GENESIS_AUTHOR_SENTINEL};
