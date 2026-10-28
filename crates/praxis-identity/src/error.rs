// SPDX-License-Identifier: Apache-2.0
//! Typed errors for identity-log processing (`AGENTS.md` §3 `DoD`).

use praxis_types::{Kid, Ts};

/// Everything that can go wrong applying an identity object to an [`crate::IdentityLog`].
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// The first object applied to a log must be `id-genesis`; any later
    /// object claiming to be `id-genesis` is also rejected (a log has
    /// exactly one genesis).
    #[error("expected id-genesis as the log's first (and only) genesis event")]
    UnexpectedGenesis,
    /// `id-genesis` must list at least one key.
    #[error("id-genesis must list at least one key")]
    GenesisHasNoKeys,
    /// `id-genesis.author` must be the fixed sentinel
    /// (`spec/pips/0004-genesis-author-sentinel.md`), never a real DID.
    #[error("id-genesis.author must be the fixed sentinel, not a real DID")]
    InvalidGenesisAuthor,
    /// `id-rotate`/`id-delegate` must list exactly the keys this op expects.
    #[error("{0}")]
    InvalidPayload(&'static str),
    /// The object's `kind` and its body's `op` disagree about what this event is.
    #[error("object kind does not match identity content op")]
    KindOpMismatch,
    /// The claimed signer key id is not known to this log (not yet
    /// introduced, or introduced only by a later event).
    #[error("signer key {0:?} is not known to this identity log")]
    UnknownSigner(Kid),
    /// The signer key exists but is not currently authorized for this
    /// operation (wrong role, outside its validity window, or revoked) at
    /// the object's `ts`.
    #[error("key {0:?} is not authorized to sign this operation at ts={1:?}")]
    UnauthorizedSigner(Kid, Ts),
    /// Ed25519 verification of the object's signature failed.
    #[error("signature verification failed: {0}")]
    InvalidSignature(#[from] praxis_crypto::SignError),
    /// Canonical encoding of the object (to recompute the signing bytes) failed.
    #[error("canonical encoding failed: {0}")]
    Codec(#[from] praxis_types::CodecError),
    /// A key id was introduced (by genesis, rotate, or delegate) that
    /// already exists in this log. Key ids are one-time identifiers.
    #[error("key id {0:?} is already present in this identity log")]
    DuplicateKid(Kid),
    /// `id-revoke`'s `revoke.kid` does not name a key this log knows about.
    #[error("id-revoke targets unknown key id {0:?}")]
    UnknownRevokeTarget(Kid),
    /// Objects must be applied to a log in non-decreasing `ts` order (this
    /// crate's own ordering invariant; general causal/`prev` ordering across
    /// an author's whole object graph is `praxis-validate`'s job).
    #[error("object ts {0:?} precedes this log's last-applied event at {1:?}")]
    TsNotMonotonic(Ts, Ts),
}
