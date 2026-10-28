// SPDX-License-Identifier: AGPL-3.0-or-later
//! The Praxis relay (`docs/ARCHITECTURE.md` §2): a dumb, untrusted object store
//! that validates envelope/signature/size/rate limits and serves PSP/1 range
//! reconciliation (`spec/PROTOCOL.md` §11). Relays never need keys and never see
//! sealed-body plaintext.
//!
//! Licensed AGPL-3.0-or-later (ADR-0007): this is a *server*, not a library a
//! downstream project links into its own binary, so copyleft here does not
//! encumber client applications.
//!
//! M5-03 fills this in.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

fn main() {
    // TODO(M5-03): axum HTTP+WebSocket server; validate-then-store; rate limits.
}
