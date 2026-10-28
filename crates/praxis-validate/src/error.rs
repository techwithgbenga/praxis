// SPDX-License-Identifier: Apache-2.0
//! Typed validator errors with stable `E_*` codes (`AGENTS.md` §3 `DoD`).
//!
//! The codes themselves are this crate's own namespace: `spec/PROTOCOL.md`
//! §12 describes the validation *algorithm* but does not assign error codes
//! (unlike §11's PSP/1 wire errors, `E_UNAUTHORIZED`/`E_INVALID`/etc., which
//! are a different, sync-protocol-level namespace). [`ValidateError::code`]
//! gives each variant a stable string for logging/metrics that won't shift
//! under refactoring, per `docs/PRIVACY_AND_THREAT_MODEL.md` ("logs may
//! contain object IDs and error codes only" — never plaintext).

use praxis_types::{Cid, Kid, Ts};

/// Everything `validate()` (`spec/PROTOCOL.md` §12) can reject an object for,
/// plus the case-lifecycle rules C1-C8 (§6).
#[derive(Debug, thiserror::Error)]
pub enum ValidateError {
    /// Step 1: not a canonical dag-cbor object (size/limits/float/tag/etc. —
    /// see `praxis_types::CodecError`'s variants for the specific reason).
    #[error("E_DECODE: {0}")]
    Decode(#[from] praxis_types::CodecError),
    /// Step 2: `suite` is not `pxs1` (the only suite this validator implements).
    #[error("E_UNSUPPORTED_SUITE")]
    UnsupportedSuite,
    /// Step 3: the claimed `signer` key id is not known to the identity log.
    #[error("E_UNKNOWN_SIGNER: {0:?}")]
    UnknownSigner(Kid),
    /// Step 3: the signer key is known but not authorized (wrong scope,
    /// outside its validity window, or revoked) for this object's kind at its `ts`.
    #[error("E_UNAUTHORIZED_SIGNER: {0:?} at {1:?}")]
    UnauthorizedSigner(Kid, Ts),
    /// Step 3: Ed25519 verification of `sig` failed.
    #[error("E_INVALID_SIGNATURE: {0}")]
    InvalidSignature(#[from] praxis_crypto::SignError),
    /// Step 4: `ts` is before some known parent's `ts` (`spec/PROTOCOL.md` §5.3).
    #[error("E_TS_NOT_MONOTONIC: object ts {0:?} < parent ts {1:?}")]
    TsNotMonotonic(Ts, Ts),
    /// Step 5/C1: a non-`open` case-event's `case` field does not resolve to
    /// a known, validated `open` object (or is missing entirely).
    #[error("E_UNKNOWN_CASE: {0:?}")]
    UnknownCase(Cid),
    /// Step 5/C1: `open` itself carries a `case` field (it must not: its own
    /// id *is* the case id), or a non-`open` kind is missing one.
    #[error("E_CASE_FIELD_SHAPE")]
    CaseFieldShape,
    /// C1: this case already has an `open`; a second one was presented.
    #[error("E_DUPLICATE_OPEN")]
    DuplicateOpen,
    /// C2: `decision.prev` does not contain a `prediction` object for this case.
    #[error("E_MISSING_PREDICTION")]
    MissingPrediction,
    /// C1: a case event other than `open` arrived before the case has an `open`.
    #[error("E_CASE_NOT_OPEN")]
    CaseNotOpen,
    /// C3: `claims.prev` does not contain this case's `decision` object.
    #[error("E_CLAIMS_NOT_AFTER_DECISION")]
    ClaimsNotAfterDecision,
    /// C3: a second `claims` object was presented for a case (exactly one per case).
    #[error("E_DUPLICATE_CLAIMS")]
    DuplicateClaims,
    /// C3/C4: two claims in the same (or across) `claims` object(s) share an
    /// `id` that is supposed to be unique within the case.
    #[error("E_DUPLICATE_CLAIM_ID: {0:?}")]
    DuplicateClaimId(String),
    /// C5: `amend.late_claims` reuses a claim `id` that already exists in
    /// this case (late claims must be new, never modify existing ones).
    #[error("E_AMEND_REUSES_CLAIM_ID: {0:?}")]
    AmendReusesClaimId(String),
    /// C5: an `amend.late_claims` entry is not flagged `late: true`.
    #[error("E_LATE_CLAIM_NOT_FLAGGED: {0:?}")]
    LateClaimNotFlagged(String),
    /// C6: `outcome.results[].claim` names a claim id this case doesn't have.
    #[error("E_UNKNOWN_CLAIM: {0:?}")]
    UnknownClaim(String),
    /// C8: `abandon` presented for a case that already has a `decision`
    /// (abandon is only for cases that never got decided).
    #[error("E_ABANDON_AFTER_DECISION")]
    AbandonAfterDecision,
    /// C8: `abandon` presented for a case that already has an `outcome`.
    #[error("E_ABANDON_AFTER_OUTCOME")]
    AbandonAfterOutcome,
    /// Step 5: this object's `kind` and its body's logical operation disagree
    /// (e.g. an `IdContent` with `op: Rotate` inside an object whose envelope
    /// `kind` is `IdGenesis`).
    #[error("E_KIND_CONTENT_MISMATCH")]
    KindContentMismatch,
    /// Identity-log processing (`id-genesis`/`id-rotate`/`id-delegate`/`id-revoke`) failed.
    #[error("E_IDENTITY: {0}")]
    Identity(#[from] praxis_identity::IdentityError),
}

impl ValidateError {
    /// The stable `E_*` code for this error, independent of the `Display`
    /// message's exact wording (which may include dynamic detail unsafe to
    /// treat as a stable key).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Decode(_) => "E_DECODE",
            Self::UnsupportedSuite => "E_UNSUPPORTED_SUITE",
            Self::UnknownSigner(_) => "E_UNKNOWN_SIGNER",
            Self::UnauthorizedSigner(_, _) => "E_UNAUTHORIZED_SIGNER",
            Self::InvalidSignature(_) => "E_INVALID_SIGNATURE",
            Self::TsNotMonotonic(_, _) => "E_TS_NOT_MONOTONIC",
            Self::UnknownCase(_) => "E_UNKNOWN_CASE",
            Self::CaseFieldShape => "E_CASE_FIELD_SHAPE",
            Self::DuplicateOpen => "E_DUPLICATE_OPEN",
            Self::MissingPrediction => "E_MISSING_PREDICTION",
            Self::CaseNotOpen => "E_CASE_NOT_OPEN",
            Self::ClaimsNotAfterDecision => "E_CLAIMS_NOT_AFTER_DECISION",
            Self::DuplicateClaims => "E_DUPLICATE_CLAIMS",
            Self::DuplicateClaimId(_) => "E_DUPLICATE_CLAIM_ID",
            Self::AmendReusesClaimId(_) => "E_AMEND_REUSES_CLAIM_ID",
            Self::LateClaimNotFlagged(_) => "E_LATE_CLAIM_NOT_FLAGGED",
            Self::UnknownClaim(_) => "E_UNKNOWN_CLAIM",
            Self::AbandonAfterDecision => "E_ABANDON_AFTER_DECISION",
            Self::AbandonAfterOutcome => "E_ABANDON_AFTER_OUTCOME",
            Self::KindContentMismatch => "E_KIND_CONTENT_MISMATCH",
            Self::Identity(_) => "E_IDENTITY",
        }
    }
}
