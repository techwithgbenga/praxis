// SPDX-License-Identifier: Apache-2.0
//! The kind-specific content bodies from `spec/praxis-v0.1.cddl` §identity/case
//! events/lineage/attestation, and `spec/PROTOCOL.md` §4, §6, §10.
//!
//! Each struct here is concrete and unambiguous, so it round-trips through
//! `serde` on its own with no tagging tricks. [`Content`] ties them together as
//! a plain Rust enum for ergonomic use elsewhere in the workspace; it is
//! deliberately **not** itself `Serialize`/`Deserialize`. Which struct a given
//! object's `body.plain` field should be interpreted as depends on the sibling
//! `kind` field in the envelope (`spec/praxis-v0.1.cddl` `object`), external to
//! the body — that two-stage dispatch (decode the generic envelope, then
//! re-validate `plain` against the shape `kind` implies) is `spec/PROTOCOL.md`
//! §12 steps 1 and 6, owned by the codec (M1-02) and the reference validator
//! (M1-07), not by this crate.

use serde::{Deserialize, Serialize};

use crate::envelope::{Cid, Kind};
use crate::error::TypeError;
use crate::scalar::{Did, Hash32, Kid as KeyId, LongText, Ppm, ShortText, Ts};
use crate::value::Value;

// ============================== Identity ===================================

/// Fixed at `"ed25519"` (`spec/praxis-v0.1.cddl` `key-entry.alg`): the only
/// signature algorithm in suite `pxs1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Ed25519Alg;

impl Serialize for Ed25519Alg {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("ed25519")
    }
}

impl<'de> Deserialize<'de> for Ed25519Alg {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value == "ed25519" {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(format!(
                "unsupported key algorithm {value:?}"
            )))
        }
    }
}

/// `role: "root" / "device" / "recovery"` (`spec/praxis-v0.1.cddl` `key-entry`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyRole {
    /// The identity's root signing key.
    Root,
    /// A device-scoped signing key, authorized by `id-delegate`.
    Device,
    /// A Shamir social-recovery share's key.
    Recovery,
}

/// `key-entry` (`spec/praxis-v0.1.cddl`): one key in an identity log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyEntry {
    /// The key's identifier, scoped to this identity.
    pub kid: KeyId,
    /// Always `"ed25519"` in suite `pxs1`.
    pub alg: Ed25519Alg,
    /// The raw 32-byte Ed25519 public key.
    #[serde(rename = "pub", with = "crate::bytes_serde")]
    pub public_key: [u8; 32],
    /// This key's role.
    pub role: KeyRole,
    /// An X25519 public key for HPKE, if this key is also used for encryption.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::bytes_serde::opt_array"
    )]
    pub enc_pub: Option<[u8; 32]>,
    /// When this key becomes valid.
    pub not_before: Ts,
    /// When this key stops being valid, if bounded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<Ts>,
    /// For device keys: which object kinds this key may sign.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Vec<Kind>>,
}

/// `op: "genesis" / "rotate" / "delegate" / "revoke"` (`spec/praxis-v0.1.cddl` `id-content`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdOp {
    /// `id-genesis`: establishes the identity.
    Genesis,
    /// `id-rotate`: replaces the root key.
    Rotate,
    /// `id-delegate`: authorizes a device key.
    Delegate,
    /// `id-revoke`: revokes a key.
    Revoke,
}

/// `{ kid: kid, effective: ts, ? compromised_since: ts }` (`spec/praxis-v0.1.cddl`
/// `id-content.revoke`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocation {
    /// The key being revoked.
    pub kid: KeyId,
    /// When the revocation takes effect.
    pub effective: Ts,
    /// If the key is known compromised, since when (`spec/PROTOCOL.md` §4.5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compromised_since: Option<Ts>,
}

/// `id-content` (`spec/praxis-v0.1.cddl`): the body of an `id-genesis` /
/// `id-rotate` / `id-delegate` / `id-revoke` object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdContent {
    /// Which identity operation this is.
    pub op: IdOp,
    /// Keys being introduced (genesis/rotate/delegate).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<KeyEntry>>,
    /// The revocation (revoke only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoke: Option<Revocation>,
}

// ============================== Case events ================================

/// `reversibility: "reversible" / "costly" / "irreversible"` (`spec/praxis-v0.1.cddl` `stakes`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Reversibility {
    /// The decision can be undone at negligible cost.
    Reversible,
    /// The decision can be undone, but at real cost.
    Costly,
    /// The decision cannot be undone.
    Irreversible,
}

/// `time_pressure: "none" / "minutes" / "seconds"` (`spec/praxis-v0.1.cddl` `stakes`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TimePressure {
    /// No meaningful time pressure.
    None,
    /// Minutes to decide.
    Minutes,
    /// Seconds to decide.
    Seconds,
}

/// `impact: 1..5` (`spec/praxis-v0.1.cddl` `stakes`): a 1-5 severity rating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Impact(u8);

impl Impact {
    /// Builds an `Impact`, rejecting values outside `1..=5`.
    ///
    /// # Errors
    /// Returns [`TypeError::LengthOutOfRange`] if `value` is not in `1..=5`
    /// (reused here as a generic bounded-integer error; see that variant's docs).
    pub fn new(value: u8) -> Result<Self, TypeError> {
        if (1..=5).contains(&value) {
            Ok(Self(value))
        } else {
            Err(TypeError::LengthOutOfRange {
                field: "stakes.impact",
                len: value as usize,
                min: 1,
                max: 5,
            })
        }
    }

    /// The underlying `1..=5` value.
    #[must_use]
    pub fn get(self) -> u8 {
        self.0
    }
}

impl<'de> Deserialize<'de> for Impact {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u8::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// `stakes` (`spec/praxis-v0.1.cddl`): what's at risk in a decision, and the
/// raw inputs to the Surprise Engine's stakes weight (`docs/SURPRISE_ENGINE.md` §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stakes {
    /// How reversible the decision is.
    pub reversibility: Reversibility,
    /// Severity, 1 (low) to 5 (high).
    pub impact: Impact,
    /// How much time pressure the practitioner was under.
    pub time_pressure: TimePressure,
}

/// `signal` (`spec/praxis-v0.1.cddl`): one named observation about the situation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Signal {
    /// The signal's canonical name (domain-pack vocabulary).
    pub name: ShortText,
    /// The observed value.
    pub value: Value,
    /// The value's unit, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<ShortText>,
    /// When this signal was observed, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed: Option<Ts>,
}

/// `situation` (`spec/praxis-v0.1.cddl`): the decision-time context.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Situation {
    /// A short prose summary.
    pub summary: LongText,
    /// Structured signals noticed at decision time.
    pub signals: Vec<Signal>,
    /// Domain-pack-governed free-form context (`docs/DOMAIN_PACKS.md`).
    pub context: std::collections::BTreeMap<String, Value>,
    /// Attached blobs (screenshots, logs), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachments: Option<Vec<Cid>>,
}

/// A `usage.retrieval` / `usage.training` level (`spec/praxis-v0.1.cddl` `usage`):
/// who may use this case for that purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UsageScope {
    /// Nobody but the owner.
    None,
    /// The owner only (same as `None` for most purposes; kept distinct per CDDL).
    #[serde(rename = "self")]
    Own,
    /// The owner's team.
    Team,
    /// Everyone in the case's lineage.
    Lineage,
    /// Anyone.
    Public,
}

/// `usage` (`spec/praxis-v0.1.cddl`): portable, machine-checkable usage terms
/// attached to a case at `open` (`spec/PROTOCOL.md` §10.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    /// Who may retrieve this case (e.g. for `Consult`).
    pub retrieval: UsageScope,
    /// Who may train on this case.
    pub training: UsageScope,
    /// Whether this case's claims may contribute to a published calibration disclosure.
    pub calibration_publication: bool,
    /// Always `false`: no policy may permit employment evaluation
    /// (`spec/PROTOCOL.md` §10.5; `ETHICS.md` §2).
    pub employment_evaluation: EmploymentEvaluationIsAlwaysFalse,
    /// When this grant of usage expires, if bounded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<Ts>,
}

/// A type whose only valid value is `false`, enforced on deserialize
/// (`spec/praxis-v0.1.cddl` `usage.employment_evaluation: false`;
/// `spec/PROTOCOL.md` §10.5: "a **fixed-false** field: no policy may set it to true").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EmploymentEvaluationIsAlwaysFalse;

impl Serialize for EmploymentEvaluationIsAlwaysFalse {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bool(false)
    }
}

impl<'de> Deserialize<'de> for EmploymentEvaluationIsAlwaysFalse {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = bool::deserialize(deserializer)?;
        if value {
            Err(serde::de::Error::custom(
                "usage.employment_evaluation must be false (spec/PROTOCOL.md §10.5)",
            ))
        } else {
            Ok(Self)
        }
    }
}

/// `open-body` (`spec/praxis-v0.1.cddl`): opens a new case.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenBody {
    /// `pack-id@semver` (`docs/DOMAIN_PACKS.md`).
    pub domain: ShortText,
    /// The decision-time situation.
    pub situation: Situation,
    /// What's at stake.
    pub stakes: Stakes,
    /// Usage terms for this case.
    pub usage: Usage,
    /// Free-form tags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<ShortText>>,
}

/// `model-ref` (`spec/praxis-v0.1.cddl`): a pinned, auditable reference to the
/// model that produced a prediction (`docs/APPRENTICE.md` §7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelRef {
    /// A human-readable model identifier.
    pub id: ShortText,
    /// A digest pinning the exact model weights/version in use.
    pub digest: Hash32,
    /// The lineage/canon build this model was produced from, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<Cid>,
}

/// `option-prob` (`spec/praxis-v0.1.cddl`): one option's probability in a predicted
/// distribution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptionProb {
    /// The option's identifier (from the domain pack's option set).
    pub option: ShortTextRef,
    /// Its probability, in parts-per-million.
    pub p: Ppm,
}

/// A short-text-like string used for identifiers that are repeated often in an
/// object (e.g. an `option` chosen from a fixed, pack-defined set). Alias kept
/// distinct from [`ShortText`] only at the type level for documentation; same
/// validation.
pub type ShortTextRef = ShortText;

/// `prediction-body` (`spec/praxis-v0.1.cddl`): the apprentice's committed
/// distribution over options, before the decision (`spec/PROTOCOL.md` C2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PredictionBody {
    /// Which model produced this prediction.
    pub model: ModelRef,
    /// The predicted distribution; `spec/PROTOCOL.md` §6.6 calls this a
    /// distribution over the pack's option set. Summing to exactly `1_000_000`
    /// ppm is a validator rule (`praxis-validate`), not enforced by this shape.
    pub options: Vec<OptionProb>,
    /// References to supporting cases/reasoning, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale_refs: Option<Vec<Cid>>,
}

/// `decision-body` (`spec/praxis-v0.1.cddl`): the practitioner's recorded choice.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionBody {
    /// Every option the practitioner considered.
    pub options_considered: Vec<ShortText>,
    /// The option actually chosen.
    pub chosen: ShortText,
    /// Free-text reasoning, if given at decision time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<LongText>,
    /// Stated confidence in the choice, if given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Ppm>,
}

/// `cel-resolution` (`spec/praxis-v0.1.cddl`): a machine-checkable resolution criterion.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CelResolution {
    /// The CEL expression (`spec/POLICY.md` §4).
    pub expr: LongText,
    /// Named observation inputs the expression reads.
    pub inputs: Vec<ShortText>,
}

/// `attested-resolution` (`spec/praxis-v0.1.cddl`): a human-attested resolution criterion.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttestedResolution {
    /// Who attests the result.
    pub by: AttestedBy,
    /// The rubric, fixed at claim time (prevents goalpost-shifting).
    pub rubric: LongText,
}

/// `by: "self" / "peer" / "registry"` (`spec/praxis-v0.1.cddl` `attested-resolution`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttestedBy {
    /// The practitioner attests their own outcome.
    #[serde(rename = "self")]
    SelfAttested,
    /// A peer attests the outcome.
    Peer,
    /// A registry service attests the outcome.
    Registry,
}

/// `resolution = cel-resolution / attested-resolution` (`spec/praxis-v0.1.cddl`).
///
/// Internally tagged on `kind` (`"cel"` / `"attested"`): safe to derive, unlike
/// [`Content`], because the discriminant is a field *inside* this same
/// structure, not an external sibling field serde would have to be told about
/// separately.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Resolution {
    /// `{ kind: "cel", ... }`.
    Cel(CelResolution),
    /// `{ kind: "attested", ... }`.
    Attested(AttestedResolution),
}

/// `claim` (`spec/praxis-v0.1.cddl`): one pre-registered, resolvable statement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Claim {
    /// Stable within the case.
    pub id: ShortText,
    /// The claim's statement, in prose.
    pub statement: LongText,
    /// Stated probability, in parts-per-million.
    pub p: Ppm,
    /// How this claim resolves.
    pub resolve: Resolution,
    /// Resolve-by time.
    pub horizon: Ts,
    /// Whether the domain pack marks this a "core" claim for scoring purposes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub core: Option<bool>,
    /// Set only in `amend`: a late-added claim, excluded from scoring
    /// (`spec/PROTOCOL.md` C5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub late: Option<bool>,
}

/// `claims-body` (`spec/praxis-v0.1.cddl`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimsBody {
    /// The claims registered at decision time. Immutable after save
    /// (`spec/PROTOCOL.md` C3) — enforcing that is a validator rule, not this shape's job.
    pub claims: Vec<Claim>,
}

/// `qa` (`spec/praxis-v0.1.cddl`): one elicitation question/answer pair.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Qa {
    /// The question asked.
    pub q: LongText,
    /// Structured choices offered, if any (`docs/SURPRISE_ENGINE.md` §6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub choices: Option<Vec<ShortText>>,
    /// The answer given (free text, or the chosen option's label).
    pub a: LongText,
    /// Index into `choices` the practitioner picked, if a structured choice was made.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub choice_index: Option<u32>,
    /// How long the practitioner took to answer, in milliseconds.
    pub latency_ms: u32,
    /// Whether this question was declined (`docs/SURPRISE_ENGINE.md` §8: never
    /// re-asked, never penalized).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declined: Option<bool>,
}

/// `modality: "text" / "voice"` (`spec/praxis-v0.1.cddl` `elicitation-body`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Modality {
    /// Typed free text.
    Text,
    /// Local speech-to-text.
    Voice,
}

/// `{ used_today: uint, cap_today: uint }` (`spec/praxis-v0.1.cddl`
/// `elicitation-body.trigger.budget_state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetState {
    /// Elicitations already asked today.
    pub used_today: u32,
    /// The daily cap in effect (`docs/SURPRISE_ENGINE.md` §3).
    pub cap_today: u32,
}

/// `elicitation-body.trigger` (`spec/praxis-v0.1.cddl`): why this question was asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trigger {
    /// Surprise `S = -ln q(chosen)`, in milli-nats.
    pub surprise_mnat: crate::scalar::Mnat,
    /// The stakes weight `w`, in parts-per-million.
    pub stakes_weight: Ppm,
    /// The elicitation budget state at trigger time.
    pub budget_state: BudgetState,
}

/// `elicitation-body` (`spec/praxis-v0.1.cddl`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ElicitationBody {
    /// Why this question was asked.
    pub trigger: Trigger,
    /// The question(s) and answer(s).
    pub qa: Vec<Qa>,
    /// How the answer was captured.
    pub modality: Modality,
    /// The question-template id, for the Reasoning-Utility bandit
    /// (`docs/SURPRISE_ENGINE.md` §7).
    pub template: ShortText,
}

/// `evidence.kind: "observation" / "link" / "note" / "blob"` (`spec/praxis-v0.1.cddl`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EvidenceKind {
    /// A frozen observation snapshot.
    Observation,
    /// A link to external evidence.
    Link,
    /// A free-text note.
    Note,
    /// A blob attachment.
    Blob,
}

/// `evidence` (`spec/praxis-v0.1.cddl`): one piece of evidence for a claim resolution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    /// What kind of evidence this is.
    pub kind: EvidenceKind,
    /// A content reference (observation snapshot or blob), if applicable.
    /// Named `cid_ref` here because `ref` is a Rust keyword; the CDDL field name is `ref`.
    #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
    pub cid_ref: Option<Cid>,
    /// An external URI, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    /// A free-text note, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<LongText>,
    /// When this evidence was captured/observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<Ts>,
}

/// `result: "true" / "false" / "void"` (`spec/praxis-v0.1.cddl` `claim-result`):
/// a **string** literal result, not a JSON boolean (the CDDL quotes it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClaimOutcome {
    /// The claim held.
    True,
    /// The claim did not hold.
    False,
    /// The claim could not be evaluated (see [`VoidReason`]).
    Void,
}

/// `attributed: "auto" / "peer" / "self"` (`spec/praxis-v0.1.cddl` `claim-result`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Attribution {
    /// Resolved automatically (CEL against frozen observations).
    Auto,
    /// Resolved by a peer's attestation.
    Peer,
    /// Resolved by the practitioner's own attestation.
    #[serde(rename = "self")]
    SelfAttributed,
}

/// `void_reason` (`spec/praxis-v0.1.cddl` `claim-result`): why a claim resolved
/// `void` rather than `true`/`false` (`spec/PROTOCOL.md` C6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoidReason {
    /// The premise the claim depended on never held.
    PremiseInvalid,
    /// The action the claim was conditioned on was never taken.
    ActionNotTaken,
    /// The claim could not be observed either way.
    Unobservable,
    /// A later event superseded the claim.
    Superseded,
}

/// `claim-result` (`spec/praxis-v0.1.cddl`): the resolution of one claim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimResult {
    /// The claim id being resolved.
    pub claim: ShortText,
    /// The result.
    pub result: ClaimOutcome,
    /// Who/what attributed this result.
    pub attributed: Attribution,
    /// Supporting evidence.
    pub evidence: Vec<Evidence>,
    /// Required when `result == Void`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub void_reason: Option<VoidReason>,
}

/// `outcome-body` (`spec/praxis-v0.1.cddl`): closes a case by resolving its claims.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OutcomeBody {
    /// Each claim's result.
    pub results: Vec<ClaimResult>,
    /// Known confounders, recorded for the causality caveat (`spec/SCORING.md` §8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confounders: Option<Vec<ShortText>>,
    /// Free-text narrative.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub narrative: Option<LongText>,
}

/// `amend-body` (`spec/praxis-v0.1.cddl`): commentary, typo fixes, or late claims.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AmendBody {
    /// The object being amended.
    pub target: Cid,
    /// The amendment's note.
    pub note: LongText,
    /// Late-added claims, if any (flagged `late: true`, excluded from scoring).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub late_claims: Option<Vec<Claim>>,
}

/// `retract-body.reason` (`spec/praxis-v0.1.cddl`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetractReason {
    /// The author withdraws consent for further use of the case.
    ConsentWithdrawn,
    /// The case was recorded in error.
    Error,
    /// Some other reason (see the accompanying note).
    Other,
}

/// `retract-body` (`spec/praxis-v0.1.cddl`): a tombstone withdrawing consent for
/// further use of a case (`spec/PROTOCOL.md` C7). Does not delete bytes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetractBody {
    /// Why the case is being retracted.
    pub reason: RetractReason,
    /// An optional free-text note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<LongText>,
}

/// `abandon-body` (`spec/praxis-v0.1.cddl`): closes an unresolved case
/// (`spec/PROTOCOL.md` C8).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AbandonBody {
    /// Why the case was abandoned.
    pub reason: ShortText,
}

// ============================== Lineage ====================================

/// `grant-body.scope` (`spec/praxis-v0.1.cddl`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GrantScope {
    /// Specific cases granted, if scoped by case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cases: Option<Vec<Cid>>,
    /// A domain granted wholesale, if scoped by domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<ShortText>,
    /// A filter expression further restricting the grant, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<LongText>,
}

/// `grant-body` (`spec/praxis-v0.1.cddl`): shares access to one or more cases.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GrantBody {
    /// Who is being granted access.
    pub grantee: Did,
    /// What is being granted.
    pub scope: GrantScope,
    /// HPKE-wrapped keys for the grantee.
    pub wrapped: Vec<crate::envelope::Recipient>,
    /// The usage terms this grant conveys.
    pub terms: Usage,
    /// When the grant expires, if bounded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<Ts>,
}

/// `derive-body` (`spec/praxis-v0.1.cddl`): "B declares it learned from A in
/// domain D" (`spec/PROTOCOL.md` §10.2). Not an endorsement of A's correctness.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeriveBody {
    /// The practitioner learned from.
    pub from: Did,
    /// The domain this derivation applies to.
    pub domain: ShortText,
    /// The grant this derivation relies on, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<Cid>,
    /// Free-text note.
    pub note: LongText,
}

/// `diverge-body` (`spec/praxis-v0.1.cddl`): the fork primitive — "B decided
/// differently from A on situation S" (`spec/PROTOCOL.md` §10.3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DivergeBody {
    /// The case being diverged from.
    pub theirs: Cid,
    /// The diverging case.
    pub mine: Cid,
    /// The stated reasoning for diverging.
    pub reasoning: LongText,
    /// Which dimension of the decision diverged, if categorized.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dimension: Option<ShortText>,
}

/// `canon-body` (`spec/praxis-v0.1.cddl`): a curated, versioned, dissent-preserving
/// manifest of cases (`spec/PROTOCOL.md` §10.4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CanonBody {
    /// The canon's stable identifier.
    pub id: ShortText,
    /// Display name.
    pub name: ShortText,
    /// The domain this canon covers.
    pub domain: ShortText,
    /// Who may curate this canon's membership.
    pub editors: Vec<Did>,
    /// Free-text description of the inclusion policy.
    pub inclusion_policy: LongText,
    /// A Merkle root committing this version's member case IDs.
    pub members_root: Hash32,
    /// Number of members in this version.
    pub count: u32,
    /// This version's sequence number.
    pub version: u32,
    /// The previous version, if any (versioned like a branch).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_version: Option<Cid>,
}

// ============================== Attestation ================================

/// `anchor-body.method` (`spec/praxis-v0.1.cddl`): irregular wire strings, so
/// each variant is renamed explicitly rather than relying on a `rename_all` rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnchorMethod {
    /// A relay's signed "first seen" receipt: weak-trust, cheap, offline-friendly.
    #[serde(rename = "relay-receipt")]
    RelayReceipt,
    /// An RFC 3161 timestamp authority token.
    #[serde(rename = "rfc3161")]
    Rfc3161,
    /// An `OpenTimestamps` proof.
    #[serde(rename = "opentimestamps")]
    Opentimestamps,
}

/// `anchor-body` (`spec/praxis-v0.1.cddl`): evidence an object existed by a given
/// time (`spec/PROTOCOL.md` §7).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnchorBody {
    /// The objects being anchored.
    pub targets: Vec<Cid>,
    /// How they were anchored.
    pub method: AnchorMethod,
    /// The anchoring proof (format depends on `method`).
    #[serde(with = "serde_bytes")]
    pub proof: Vec<u8>,
    /// The Merkle root over `targets`, if batch-anchored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<Hash32>,
}

/// `attest-body.type` (`spec/praxis-v0.1.cddl`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttestType {
    /// A calibration disclosure (`spec/PROTOCOL.md` §9).
    Calibration,
    /// A model/index build manifest (`spec/PROTOCOL.md` §10.6).
    BuildManifest,
    /// Any other signed aggregate statement.
    Custom,
}

/// `attest-body.counts` (`spec/praxis-v0.1.cddl`): the selective-reporting
/// accounting every disclosure must carry (`spec/PROTOCOL.md` §9.3, `spec/SCORING.md` §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestCounts {
    /// Cases opened in scope.
    pub n_opened: u32,
    /// Claims scored.
    pub n_scored: u32,
    /// Claims resolved void.
    pub n_void: u32,
    /// Cases abandoned.
    pub n_abandoned: u32,
    /// Cases retracted.
    pub n_retracted: u32,
    /// Scored claims that are unanchored.
    pub n_unanchored: u32,
}

/// `attest-body` (`spec/praxis-v0.1.cddl`): a signed statement of aggregate facts
/// over a committed set of objects (`spec/PROTOCOL.md` §9).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttestBody {
    /// What kind of attestation this is.
    #[serde(rename = "type")]
    pub attest_type: AttestType,
    /// A Merkle root committing the set `S` of claims/outcome object IDs this
    /// attestation is over.
    pub set_root: Hash32,
    /// The anti-cherry-picking counts.
    pub counts: AttestCounts,
    /// Fixed-point statistics per `spec/SCORING.md` (e.g. `bs_ppm`, `ece_ppm`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats: Option<std::collections::BTreeMap<String, i64>>,
    /// The domain this attestation covers, if domain-scoped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<ShortText>,
    /// For build manifests: the case IDs included in the build.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub included: Option<Vec<Cid>>,
    /// For build manifests: which policies were checked before inclusion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policies_checked: Option<Vec<ShortText>>,
}

// ============================== Content union ==============================

/// The union of every kind-specific content body (`spec/praxis-v0.1.cddl` `content`).
///
/// See the module docs for why this is not `Serialize`/`Deserialize`: use
/// [`Content::kind`] together with the sibling `Kind` on an [`crate::Object`] to
/// know which variant is expected, and construct/match the specific struct
/// directly via ordinary (de)serialization of that struct alone.
#[derive(Debug, Clone, PartialEq)]
pub enum Content {
    /// `id-genesis` / `id-rotate` / `id-delegate` / `id-revoke`.
    Id(IdContent),
    /// `open`.
    Open(OpenBody),
    /// `prediction`.
    Prediction(PredictionBody),
    /// `decision`.
    Decision(DecisionBody),
    /// `claims`.
    Claims(ClaimsBody),
    /// `elicitation`.
    Elicitation(ElicitationBody),
    /// `outcome`.
    Outcome(OutcomeBody),
    /// `amend`.
    Amend(AmendBody),
    /// `retract`.
    Retract(RetractBody),
    /// `abandon`.
    Abandon(AbandonBody),
    /// `grant`.
    Grant(GrantBody),
    /// `derive`.
    Derive(DeriveBody),
    /// `diverge`.
    Diverge(DivergeBody),
    /// `canon`.
    Canon(CanonBody),
    /// `anchor`.
    Anchor(AnchorBody),
    /// `attest`.
    Attest(AttestBody),
}

impl Content {
    /// The envelope [`Kind`] this content corresponds to.
    #[must_use]
    pub fn kind(&self) -> Kind {
        match self {
            // `IdContent.op` determines the specific identity kind.
            Self::Id(id) => match id.op {
                IdOp::Genesis => Kind::IdGenesis,
                IdOp::Rotate => Kind::IdRotate,
                IdOp::Delegate => Kind::IdDelegate,
                IdOp::Revoke => Kind::IdRevoke,
            },
            Self::Open(_) => Kind::Open,
            Self::Prediction(_) => Kind::Prediction,
            Self::Decision(_) => Kind::Decision,
            Self::Claims(_) => Kind::Claims,
            Self::Elicitation(_) => Kind::Elicitation,
            Self::Outcome(_) => Kind::Outcome,
            Self::Amend(_) => Kind::Amend,
            Self::Retract(_) => Kind::Retract,
            Self::Abandon(_) => Kind::Abandon,
            Self::Grant(_) => Kind::Grant,
            Self::Derive(_) => Kind::Derive,
            Self::Diverge(_) => Kind::Diverge,
            Self::Canon(_) => Kind::Canon,
            Self::Anchor(_) => Kind::Anchor,
            Self::Attest(_) => Kind::Attest,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::envelope::CidCodec;

    fn roundtrip<T>(value: &T)
    where
        T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug,
    {
        let json = serde_json::to_string(value).expect("serialize");
        let back: T = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(value, &back, "round-trip via {json:?} changed the value");
    }

    fn short(s: &str) -> ShortText {
        ShortText::new(s).unwrap()
    }

    fn long(s: &str) -> LongText {
        LongText::new(s).unwrap()
    }

    #[test]
    fn ed25519_alg_roundtrips_and_rejects_other() {
        roundtrip(&Ed25519Alg);
        assert!(serde_json::from_str::<Ed25519Alg>("\"secp256k1\"").is_err());
    }

    #[test]
    fn employment_evaluation_rejects_true() {
        roundtrip(&EmploymentEvaluationIsAlwaysFalse);
        assert_eq!(
            serde_json::to_string(&EmploymentEvaluationIsAlwaysFalse).unwrap(),
            "false"
        );
        let err = serde_json::from_str::<EmploymentEvaluationIsAlwaysFalse>("true").unwrap_err();
        assert!(err.to_string().contains("employment_evaluation"));
    }

    #[test]
    fn impact_enforces_1_to_5() {
        assert!(Impact::new(0).is_err());
        assert!(Impact::new(1).is_ok());
        assert!(Impact::new(5).is_ok());
        assert!(Impact::new(6).is_err());
        roundtrip(&Impact::new(3).unwrap());
    }

    #[test]
    fn id_content_genesis_roundtrips_and_maps_to_kind() {
        let content = IdContent {
            op: IdOp::Genesis,
            keys: Some(vec![KeyEntry {
                kid: crate::scalar::Kid::new("root-1").unwrap(),
                alg: Ed25519Alg,
                public_key: [1u8; 32],
                role: KeyRole::Root,
                enc_pub: Some([2u8; 32]),
                not_before: Ts::from_millis(0),
                not_after: None,
                scope: None,
            }]),
            revoke: None,
        };
        roundtrip(&content);
        let json = serde_json::to_string(&content).unwrap();
        assert!(
            json.contains("\"pub\""),
            "public_key must serialize under the CDDL name `pub`"
        );
        assert_eq!(Content::Id(content).kind(), Kind::IdGenesis);
    }

    #[test]
    fn id_content_revoke_roundtrips() {
        let content = IdContent {
            op: IdOp::Revoke,
            keys: None,
            revoke: Some(Revocation {
                kid: crate::scalar::Kid::new("device-1").unwrap(),
                effective: Ts::from_millis(1000),
                compromised_since: Some(Ts::from_millis(500)),
            }),
        };
        roundtrip(&content);
        assert_eq!(Content::Id(content).kind(), Kind::IdRevoke);
    }

    fn sample_usage() -> Usage {
        Usage {
            retrieval: UsageScope::Own,
            training: UsageScope::None,
            calibration_publication: false,
            employment_evaluation: EmploymentEvaluationIsAlwaysFalse,
            expires: None,
        }
    }

    #[test]
    fn usage_scope_self_renames_correctly() {
        assert_eq!(serde_json::to_string(&UsageScope::Own).unwrap(), "\"self\"");
        roundtrip(&sample_usage());
    }

    #[test]
    fn open_body_roundtrips() {
        let body = OpenBody {
            domain: short("incident-response@0.1"),
            situation: Situation {
                summary: long("replica lag 40s, no alert fired"),
                signals: vec![Signal {
                    name: short("replica_lag_s"),
                    value: Value::Int(40),
                    unit: Some(short("seconds")),
                    observed: Some(Ts::from_millis(1000)),
                }],
                context: BTreeMap::new(),
                attachments: None,
            },
            stakes: Stakes {
                reversibility: Reversibility::Costly,
                impact: Impact::new(3).unwrap(),
                time_pressure: TimePressure::Minutes,
            },
            usage: sample_usage(),
            tags: Some(vec![short("database")]),
        };
        roundtrip(&body);
    }

    #[test]
    fn prediction_body_roundtrips() {
        let body = PredictionBody {
            model: ModelRef {
                id: short("apprentice-v0"),
                digest: Hash32::new([1u8; 32]),
                build: None,
            },
            options: vec![
                OptionProb {
                    option: short("wait"),
                    p: Ppm::new(520_000).unwrap(),
                },
                OptionProb {
                    option: short("failover"),
                    p: Ppm::new(480_000).unwrap(),
                },
            ],
            rationale_refs: None,
        };
        roundtrip(&body);
    }

    #[test]
    fn decision_body_roundtrips() {
        let body = DecisionBody {
            options_considered: vec![short("wait"), short("failover")],
            chosen: short("wait"),
            reasoning: Some(long("lag matches the nightly backup window")),
            confidence: Some(Ppm::new(700_000).unwrap()),
        };
        roundtrip(&body);
    }

    #[test]
    fn resolution_variants_are_internally_tagged_correctly() {
        let cel = Resolution::Cel(CelResolution {
            expr: long("obs.replica_lag_s.max(t_open, t_open + duration('30m')) < 5"),
            inputs: vec![short("replica_lag_s")],
        });
        let json = serde_json::to_string(&cel).unwrap();
        assert!(json.contains("\"kind\":\"cel\""));
        roundtrip(&cel);

        let attested = Resolution::Attested(AttestedResolution {
            by: AttestedBy::SelfAttested,
            rubric: long("practitioner confirms recovery in the incident channel"),
        });
        let json2 = serde_json::to_string(&attested).unwrap();
        assert!(json2.contains("\"kind\":\"attested\""));
        assert!(json2.contains("\"by\":\"self\""));
        roundtrip(&attested);
    }

    #[test]
    fn claims_body_roundtrips() {
        let body = ClaimsBody {
            claims: vec![Claim {
                id: short("c1"),
                statement: long("self-resolves within 30m"),
                p: Ppm::new(700_000).unwrap(),
                resolve: Resolution::Cel(CelResolution {
                    expr: long("obs.replica_lag_s.max(t_action, t_action + duration('30m')) < 5"),
                    inputs: vec![short("replica_lag_s")],
                }),
                horizon: Ts::from_millis(2000),
                core: Some(true),
                late: None,
            }],
        };
        roundtrip(&body);
    }

    #[test]
    fn elicitation_body_roundtrips() {
        let body = ElicitationBody {
            trigger: Trigger {
                surprise_mnat: crate::scalar::Mnat::new(1500),
                stakes_weight: Ppm::new(400_000).unwrap(),
                budget_state: BudgetState {
                    used_today: 1,
                    cap_today: 3,
                },
            },
            qa: vec![Qa {
                q: long("what did you notice?"),
                choices: Some(vec![short("backup window"), short("something else")]),
                a: long("backup window"),
                choice_index: Some(0),
                latency_ms: 4200,
                declined: Some(false),
            }],
            modality: Modality::Text,
            template: short("observation-first-v1"),
        };
        roundtrip(&body);
    }

    #[test]
    fn outcome_body_with_void_result_roundtrips() {
        let body = OutcomeBody {
            results: vec![ClaimResult {
                claim: short("c1"),
                result: ClaimOutcome::Void,
                attributed: Attribution::Auto,
                evidence: vec![Evidence {
                    kind: EvidenceKind::Observation,
                    cid_ref: None,
                    uri: None,
                    note: Some(long("replica was decommissioned before horizon")),
                    at: Some(Ts::from_millis(3000)),
                }],
                void_reason: Some(VoidReason::Unobservable),
            }],
            confounders: Some(vec![short("maintenance window")]),
            narrative: None,
        };
        let json = serde_json::to_string(&body).unwrap();
        assert!(json.contains("\"result\":\"void\""));
        roundtrip(&body);
    }

    #[test]
    fn evidence_ref_field_uses_cddl_name() {
        let ev = Evidence {
            kind: EvidenceKind::Blob,
            cid_ref: Some(Cid::new(CidCodec::Raw, Hash32::new([9u8; 32]))),
            uri: None,
            note: None,
            at: None,
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"ref\":"));
        roundtrip(&ev);
    }

    #[test]
    fn amend_retract_abandon_roundtrip() {
        roundtrip(&AmendBody {
            target: Cid::new(CidCodec::DagCbor, Hash32::new([1u8; 32])),
            note: long("fixed a typo in the summary"),
            late_claims: None,
        });
        roundtrip(&RetractBody {
            reason: RetractReason::ConsentWithdrawn,
            note: None,
        });
        roundtrip(&AbandonBody {
            reason: short("superseded by a later incident"),
        });
    }

    #[test]
    fn grant_derive_diverge_roundtrip() {
        let did_a = Did::new("did:praxis:".to_string() + &"a".repeat(20)).unwrap();
        let did_b = Did::new("did:praxis:".to_string() + &"b".repeat(20)).unwrap();

        roundtrip(&GrantBody {
            grantee: did_b.clone(),
            scope: GrantScope {
                cases: None,
                domain: Some(short("incident-response@0.1")),
                filter: None,
            },
            wrapped: vec![crate::envelope::Recipient {
                kid: crate::scalar::Kid::new("device-2").unwrap(),
                enc: vec![1, 2],
                wrapped: vec![3, 4, 5],
            }],
            terms: sample_usage(),
            expires: None,
        });

        roundtrip(&DeriveBody {
            from: did_a.clone(),
            domain: short("incident-response@0.1"),
            grant: None,
            note: long("learned failover judgment from this lineage"),
        });

        roundtrip(&DivergeBody {
            theirs: Cid::new(CidCodec::DagCbor, Hash32::new([1u8; 32])),
            mine: Cid::new(CidCodec::DagCbor, Hash32::new([2u8; 32])),
            reasoning: long("chose to failover immediately given customer impact"),
            dimension: Some(short("risk tolerance")),
        });
    }

    #[test]
    fn canon_body_roundtrips() {
        let did = Did::new("did:praxis:".to_string() + &"c".repeat(20)).unwrap();
        roundtrip(&CanonBody {
            id: short("postgres-ops"),
            name: short("Postgres Operations"),
            domain: short("incident-response"),
            editors: vec![did],
            inclusion_policy: long("editor-reviewed, requires closed outcome"),
            members_root: Hash32::new([7u8; 32]),
            count: 212,
            version: 3,
            prev_version: Some(Cid::new(CidCodec::DagCbor, Hash32::new([6u8; 32]))),
        });
    }

    #[test]
    fn anchor_body_roundtrips() {
        roundtrip(&AnchorBody {
            targets: vec![Cid::new(CidCodec::DagCbor, Hash32::new([1u8; 32]))],
            method: AnchorMethod::RelayReceipt,
            proof: vec![1, 2, 3],
            root: Some(Hash32::new([4u8; 32])),
        });
        let json = serde_json::to_string(&AnchorMethod::Rfc3161).unwrap();
        assert_eq!(json, "\"rfc3161\"");
    }

    #[test]
    fn attest_body_roundtrips() {
        let mut stats = BTreeMap::new();
        stats.insert("bs_ppm".to_string(), 158_000);
        let body = AttestBody {
            attest_type: AttestType::Calibration,
            set_root: Hash32::new([1u8; 32]),
            counts: AttestCounts {
                n_opened: 50,
                n_scored: 40,
                n_void: 2,
                n_abandoned: 3,
                n_retracted: 1,
                n_unanchored: 5,
            },
            stats: Some(stats),
            domain: Some(short("incident-response@0.1")),
            included: None,
            policies_checked: None,
        };
        let json = serde_json::to_string(&body).unwrap();
        assert!(json.contains("\"type\":\"calibration\""));
        roundtrip(&body);

        assert_eq!(
            serde_json::to_string(&AttestType::BuildManifest).unwrap(),
            "\"build-manifest\""
        );
    }
}
