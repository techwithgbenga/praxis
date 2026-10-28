// SPDX-License-Identifier: Apache-2.0
//! Praxis protocol scalar types, the object envelope, and content enums
//! (`spec/PROTOCOL.md`, `spec/praxis-v0.1.cddl`).
//!
//! This crate has no dependency on any other `praxis-*` crate and performs no I/O
//! (docs/ARCHITECTURE.md §3). Everything here is pure data + validation of shapes.
//!
//! Scope note (M1-01 vs. M1-02/M1-07): the canonical dag-cbor codec (strict
//! decode, non-canonical rejection, `crit` handling) is M1-02's job, and
//! kind-specific content validation against the identity log / causal history is
//! `praxis-validate`'s (M1-07). This crate only defines the shapes and the
//! range/format constraints that hold regardless of encoding or context.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod bytes_serde;
mod content;
mod envelope;
mod error;
mod scalar;
mod value;

pub use content::{
    AbandonBody, AmendBody, AnchorBody, AnchorMethod, AttestBody, AttestCounts, AttestType,
    AttestedBy, AttestedResolution, Attribution, BudgetState, CanonBody, CelResolution, Claim,
    ClaimOutcome, ClaimResult, ClaimsBody, Content, DecisionBody, DeriveBody, DivergeBody,
    Ed25519Alg, ElicitationBody, EmploymentEvaluationIsAlwaysFalse, Evidence, EvidenceKind,
    GrantBody, GrantScope, IdContent, IdOp, Impact, KeyEntry, KeyRole, Modality, ModelRef,
    OpenBody, OptionProb, OutcomeBody, PredictionBody, Qa, Resolution, RetractBody, RetractReason,
    Reversibility, Revocation, Signal, Situation, Stakes, TimePressure, Trigger, Usage, UsageScope,
    VoidReason,
};
pub use envelope::{
    Body, Cid, CidCodec, FormatVersion, Kind, Object, PlainBody, Recipient, SealAlg, SealedBody,
    SealedPayload,
};
pub use error::{TextViolation, TypeError};
pub use scalar::{Did, Hash32, Kid, LongText, Mnat, Ppm, ShortText, Sig, Suite, Ts};
pub use value::{Decimal, Value};
