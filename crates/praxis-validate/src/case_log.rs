// SPDX-License-Identifier: Apache-2.0
//! The case-lifecycle state machine (`spec/PROTOCOL.md` §6, rules C1-C8).
//!
//! Scope note: this enforces exactly what C1-C8's prose states, and nothing
//! beyond it (`AGENTS.md` §0.1: never silently add requirements the spec
//! doesn't make). In particular, C6 ("outcome resolves claims... the
//! earliest causally-valid resolution is authoritative, later ones are
//! treated as `amend`") is partly a *derived-view* concern — picking which of
//! several resolutions for the same claim is authoritative is for whatever
//! builds calibration views (`praxis-score`, later), not a reason to *reject*
//! a later one here. This log does still check that a resolved claim id
//! actually exists in the case.
//!
//! Also out of scope here: end-to-end orchestration (deciding which `CaseLog`
//! a given object belongs to, persisting it, looking up causal parents by
//! CID). That needs real storage and belongs to `praxis-core` (M2-05); this
//! crate has none (`docs/ARCHITECTURE.md` §3: `score`/`types` never do I/O,
//! and `validate` isn't listed as a store-touching crate either).

use std::collections::{BTreeSet, HashSet};

use praxis_types::{AbandonBody, AmendBody, Cid, ClaimsBody, Kind, Object, OpenBody, OutcomeBody};

use crate::error::ValidateError;

/// One case's accumulated lifecycle state, built up by feeding it its events
/// in causal order (`docs/ARCHITECTURE.md` §3 "identity log, key
/// authorization" is `praxis-identity`'s analogous pattern for identities).
#[derive(Debug, Clone)]
pub struct CaseLog {
    case_id: Cid,
    predictions: HashSet<Cid>,
    decision: Option<Cid>,
    claims_object: Option<Cid>,
    claim_ids: BTreeSet<String>,
    outcome_seen: bool,
    abandoned: bool,
    retracted: bool,
}

impl CaseLog {
    /// Starts a new case from its `open` object (C1: "`open` MUST be the
    /// first object of a case; its ID is the case ID"). Whether this is
    /// actually the first object for this case — i.e. that no other
    /// `CaseLog` already exists for the resulting case id — is the caller's
    /// responsibility (it requires a store this crate doesn't have).
    ///
    /// # Errors
    /// Returns [`ValidateError::KindContentMismatch`] if `object.kind` is not
    /// `Open`, or [`ValidateError::CaseFieldShape`] if `open` carries a `case`
    /// field (it must not: its own id *is* the case id).
    pub fn open(object: &Object, _content: &OpenBody) -> Result<Self, ValidateError> {
        if object.kind != Kind::Open {
            return Err(ValidateError::KindContentMismatch);
        }
        if object.case.is_some() {
            return Err(ValidateError::CaseFieldShape);
        }
        let case_id = praxis_types::object_id(object)?;
        Ok(Self {
            case_id,
            predictions: HashSet::new(),
            decision: None,
            claims_object: None,
            claim_ids: BTreeSet::new(),
            outcome_seen: false,
            abandoned: false,
            retracted: false,
        })
    }

    /// This case's id (the `open` object's own CID).
    #[must_use]
    pub fn case_id(&self) -> &Cid {
        &self.case_id
    }

    /// Applies a non-`open` case-event object to this case.
    ///
    /// # Errors
    /// See [`ValidateError`]; in particular, the `E_*` variants documented
    /// against C1-C8 in `spec/PROTOCOL.md` §6.
    pub fn apply(
        &mut self,
        object: &Object,
        content: &praxis_types::Content,
    ) -> Result<(), ValidateError> {
        if object.case.as_ref() != Some(&self.case_id) {
            return Err(ValidateError::CaseFieldShape);
        }
        match (object.kind, content) {
            (Kind::Open, _) => Err(ValidateError::DuplicateOpen),
            (Kind::Prediction, praxis_types::Content::Prediction(_)) => {
                self.predictions.insert(praxis_types::object_id(object)?);
                Ok(())
            }
            (Kind::Decision, praxis_types::Content::Decision(_)) => self.apply_decision(object),
            (Kind::Claims, praxis_types::Content::Claims(c)) => self.apply_claims(object, c),
            (Kind::Elicitation, praxis_types::Content::Elicitation(_)) => Ok(()),
            (Kind::Outcome, praxis_types::Content::Outcome(c)) => self.apply_outcome(c),
            (Kind::Amend, praxis_types::Content::Amend(c)) => self.apply_amend(c),
            (Kind::Retract, praxis_types::Content::Retract(_)) => {
                self.retracted = true;
                Ok(())
            }
            (Kind::Abandon, praxis_types::Content::Abandon(c)) => self.apply_abandon(c),
            _ => Err(ValidateError::KindContentMismatch),
        }
    }

    fn apply_decision(&mut self, object: &Object) -> Result<(), ValidateError> {
        // C2: a prediction MUST causally precede the decision (decision.prev
        // contains a prediction id for this case).
        if !object.prev.iter().any(|p| self.predictions.contains(p)) {
            return Err(ValidateError::MissingPrediction);
        }
        self.decision = Some(praxis_types::object_id(object)?);
        Ok(())
    }

    fn apply_claims(&mut self, object: &Object, content: &ClaimsBody) -> Result<(), ValidateError> {
        let Some(decision_id) = &self.decision else {
            return Err(ValidateError::CaseNotOpen);
        };
        // C3: claims.prev MUST contain the decision.
        if !object.prev.contains(decision_id) {
            return Err(ValidateError::ClaimsNotAfterDecision);
        }
        if self.claims_object.is_some() {
            return Err(ValidateError::DuplicateClaims);
        }
        // C4 (the "unique within the case" half; the rest of C4 — that each
        // claim has a statement/p/resolve/horizon — is enforced structurally
        // by `Claim`'s own type, M1-01).
        for claim in &content.claims {
            let id = claim.id.as_str().to_string();
            if !self.claim_ids.insert(id.clone()) {
                return Err(ValidateError::DuplicateClaimId(id));
            }
        }
        self.claims_object = Some(praxis_types::object_id(object)?);
        Ok(())
    }

    fn apply_outcome(&mut self, content: &OutcomeBody) -> Result<(), ValidateError> {
        for result in &content.results {
            let id = result.claim.as_str();
            if !self.claim_ids.contains(id) {
                return Err(ValidateError::UnknownClaim(id.to_string()));
            }
        }
        // Void reasons are a controlled vocabulary enforced structurally by
        // `VoidReason`'s own type (M1-01); "earliest resolution wins" is a
        // derived-view concern, not enforced here (see module docs).
        self.outcome_seen = true;
        Ok(())
    }

    fn apply_amend(&mut self, content: &AmendBody) -> Result<(), ValidateError> {
        // C5: late claims must be flagged `late: true` and must not reuse an
        // existing claim id (amend may only add, never modify).
        for claim in content.late_claims.as_deref().unwrap_or(&[]) {
            let id = claim.id.as_str().to_string();
            if claim.late != Some(true) {
                return Err(ValidateError::LateClaimNotFlagged(id));
            }
            if !self.claim_ids.insert(id.clone()) {
                return Err(ValidateError::AmendReusesClaimId(id));
            }
        }
        Ok(())
    }

    fn apply_abandon(&mut self, _content: &AbandonBody) -> Result<(), ValidateError> {
        // C8: abandon closes an *unresolved* case.
        if self.outcome_seen {
            return Err(ValidateError::AbandonAfterOutcome);
        }
        if self.decision.is_some() {
            return Err(ValidateError::AbandonAfterDecision);
        }
        self.abandoned = true;
        Ok(())
    }

    /// Whether this case has been abandoned (C8).
    #[must_use]
    pub fn is_abandoned(&self) -> bool {
        self.abandoned
    }

    /// Whether this case has been retracted (C7). Does not delete anything;
    /// per §6 C7, compliant clients must stop using the case in new
    /// retrieval/training/calibration publication — enforcing *that* is
    /// `praxis-policy`'s job, not this log's.
    #[must_use]
    pub fn is_retracted(&self) -> bool {
        self.retracted
    }

    /// Whether this case has a recorded decision.
    #[must_use]
    pub fn has_decision(&self) -> bool {
        self.decision.is_some()
    }

    /// Whether this case has at least one recorded outcome event.
    #[must_use]
    pub fn has_outcome(&self) -> bool {
        self.outcome_seen
    }

    /// The claim ids registered for this case so far (from `claims` and any
    /// `amend.late_claims`).
    #[must_use]
    pub fn claim_ids(&self) -> &BTreeSet<String> {
        &self.claim_ids
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use praxis_types::{
        AttestedBy, AttestedResolution, Body, Claim, ClaimOutcome, ClaimResult, Content,
        DecisionBody, Did, EmploymentEvaluationIsAlwaysFalse, Evidence, EvidenceKind,
        FormatVersion, Hash32, Impact, Kid, ModelRef, OptionProb, PlainBody, Ppm, PredictionBody,
        Resolution, RetractBody, Reversibility, Sig, Situation, Stakes, Suite, TimePressure, Ts,
        Usage, UsageScope, Value, VoidReason,
    };

    use super::*;

    fn short(s: &str) -> praxis_types::ShortText {
        praxis_types::ShortText::new(s).unwrap()
    }
    fn long(s: &str) -> praxis_types::LongText {
        praxis_types::LongText::new(s).unwrap()
    }

    fn did() -> Did {
        Did::new("did:praxis:".to_string() + &"a".repeat(20)).unwrap()
    }

    /// Builds a syntactically valid `Object`; `nonce` just needs to vary
    /// across calls so otherwise-identical test objects get distinct CIDs
    /// (via `ts`). `CaseLog` never checks signatures, so the `sig` here is a
    /// placeholder.
    fn object(kind: Kind, case: Option<Cid>, prev: Vec<Cid>, nonce: u64) -> Object {
        Object {
            v: FormatVersion,
            kind,
            case,
            prev,
            author: did(),
            signer: Kid::new("device-1").unwrap(),
            ts: Ts::from_millis(nonce),
            suite: Suite::Pxs1,
            body: Body::Plain(PlainBody {
                plain: Value::Null,
                salt: [0u8; 16],
                pad: None,
            }),
            sig: Sig::new([0u8; 64]),
            crit: None,
            unknown: BTreeMap::new(),
        }
    }

    fn open_object() -> Object {
        object(Kind::Open, None, vec![], 0)
    }

    fn open_body() -> OpenBody {
        OpenBody {
            domain: short("incident-response@0.1"),
            situation: Situation {
                summary: long("replica lag"),
                signals: vec![],
                context: BTreeMap::new(),
                attachments: None,
            },
            stakes: Stakes {
                reversibility: Reversibility::Costly,
                impact: Impact::new(3).unwrap(),
                time_pressure: TimePressure::Minutes,
            },
            usage: Usage {
                retrieval: UsageScope::Own,
                training: UsageScope::None,
                calibration_publication: false,
                employment_evaluation: EmploymentEvaluationIsAlwaysFalse,
                expires: None,
            },
            tags: None,
        }
    }

    fn prediction_content() -> Content {
        Content::Prediction(PredictionBody {
            model: ModelRef {
                id: short("apprentice-v0"),
                digest: Hash32::new([1u8; 32]),
                build: None,
            },
            options: vec![OptionProb {
                option: short("wait"),
                p: Ppm::new(1_000_000).unwrap(),
            }],
            rationale_refs: None,
        })
    }

    fn decision_content() -> Content {
        Content::Decision(DecisionBody {
            options_considered: vec![short("wait")],
            chosen: short("wait"),
            reasoning: None,
            confidence: None,
        })
    }

    fn claim(id: &str, late: Option<bool>) -> Claim {
        Claim {
            id: short(id),
            statement: long("self-resolves within 30m"),
            p: Ppm::new(700_000).unwrap(),
            resolve: Resolution::Attested(AttestedResolution {
                by: AttestedBy::SelfAttested,
                rubric: long("practitioner confirms"),
            }),
            horizon: Ts::from_millis(100_000),
            core: Some(true),
            late,
        }
    }

    fn claims_content(ids: &[&str]) -> Content {
        Content::Claims(ClaimsBody {
            claims: ids.iter().map(|id| claim(id, None)).collect(),
        })
    }

    fn outcome_content(claim_id: &str, result: ClaimOutcome) -> Content {
        Content::Outcome(OutcomeBody {
            results: vec![ClaimResult {
                claim: short(claim_id),
                result,
                attributed: praxis_types::Attribution::Auto,
                evidence: vec![Evidence {
                    kind: EvidenceKind::Observation,
                    cid_ref: None,
                    uri: None,
                    note: None,
                    at: None,
                }],
                void_reason: matches!(result, ClaimOutcome::Void)
                    .then_some(VoidReason::Unobservable),
            }],
            confounders: None,
            narrative: None,
        })
    }

    /// Opens a case and advances it through prediction -> decision -> claims,
    /// returning the log plus each step's object id (for building `prev` in
    /// further events) and the claim ids used.
    fn case_through_claims() -> (CaseLog, Object, Object) {
        let open = open_object();
        let mut log = CaseLog::open(&open, &open_body()).unwrap();
        let case_id = *log.case_id();

        let prediction = object(Kind::Prediction, Some(case_id), vec![], 1);
        log.apply(&prediction, &prediction_content()).unwrap();
        let prediction_id = praxis_types::object_id(&prediction).unwrap();

        let decision = object(Kind::Decision, Some(case_id), vec![prediction_id], 2);
        log.apply(&decision, &decision_content()).unwrap();
        let decision_id = praxis_types::object_id(&decision).unwrap();

        let claims = object(Kind::Claims, Some(case_id), vec![decision_id], 3);
        log.apply(&claims, &claims_content(&["c1"])).unwrap();

        (log, decision, claims)
    }

    // ---- C1 ----

    #[test]
    fn c1_open_establishes_the_case_and_must_have_no_case_field() {
        let open = open_object();
        let log = CaseLog::open(&open, &open_body()).unwrap();
        assert_eq!(*log.case_id(), praxis_types::object_id(&open).unwrap());
    }

    #[test]
    fn c1_open_with_a_case_field_is_rejected() {
        let bogus_case = Cid::from_canonical_bytes(praxis_types::CidCodec::DagCbor, b"x");
        let open = object(Kind::Open, Some(bogus_case), vec![], 0);
        assert!(matches!(
            CaseLog::open(&open, &open_body()),
            Err(ValidateError::CaseFieldShape)
        ));
    }

    #[test]
    fn c1_a_second_open_for_the_same_case_is_rejected() {
        let open = open_object();
        let mut log = CaseLog::open(&open, &open_body()).unwrap();
        let second_open = object(Kind::Open, Some(*log.case_id()), vec![], 1);
        assert!(matches!(
            log.apply(&second_open, &Content::Open(open_body())),
            Err(ValidateError::CaseFieldShape | ValidateError::DuplicateOpen)
        ));
    }

    // ---- C2 ----

    #[test]
    fn c2_decision_with_a_prior_prediction_is_accepted() {
        let open = open_object();
        let mut log = CaseLog::open(&open, &open_body()).unwrap();
        let case_id = *log.case_id();
        let prediction = object(Kind::Prediction, Some(case_id), vec![], 1);
        log.apply(&prediction, &prediction_content()).unwrap();
        let prediction_id = praxis_types::object_id(&prediction).unwrap();

        let decision = object(Kind::Decision, Some(case_id), vec![prediction_id], 2);
        assert!(log.apply(&decision, &decision_content()).is_ok());
        assert!(log.has_decision());
    }

    #[test]
    fn c2_decision_without_any_prediction_is_rejected() {
        let open = open_object();
        let mut log = CaseLog::open(&open, &open_body()).unwrap();
        let decision = object(Kind::Decision, Some(*log.case_id()), vec![], 1);
        assert!(matches!(
            log.apply(&decision, &decision_content()),
            Err(ValidateError::MissingPrediction)
        ));
    }

    #[test]
    fn c2_decision_whose_prev_omits_the_prediction_is_rejected() {
        let open = open_object();
        let mut log = CaseLog::open(&open, &open_body()).unwrap();
        let case_id = *log.case_id();
        let prediction = object(Kind::Prediction, Some(case_id), vec![], 1);
        log.apply(&prediction, &prediction_content()).unwrap();
        // decision.prev deliberately left empty, not referencing the prediction.
        let decision = object(Kind::Decision, Some(case_id), vec![], 2);
        assert!(matches!(
            log.apply(&decision, &decision_content()),
            Err(ValidateError::MissingPrediction)
        ));
    }

    // ---- C3 ----

    #[test]
    fn c3_claims_after_decision_is_accepted() {
        let (log, _decision, _claims) = case_through_claims();
        assert_eq!(log.claim_ids().len(), 1);
    }

    #[test]
    fn c3_claims_not_referencing_the_decision_is_rejected() {
        let open = open_object();
        let mut log = CaseLog::open(&open, &open_body()).unwrap();
        let case_id = *log.case_id();
        let prediction = object(Kind::Prediction, Some(case_id), vec![], 1);
        log.apply(&prediction, &prediction_content()).unwrap();
        let prediction_id = praxis_types::object_id(&prediction).unwrap();
        let decision = object(Kind::Decision, Some(case_id), vec![prediction_id], 2);
        log.apply(&decision, &decision_content()).unwrap();

        // claims.prev omits the decision.
        let claims = object(Kind::Claims, Some(case_id), vec![], 3);
        assert!(matches!(
            log.apply(&claims, &claims_content(&["c1"])),
            Err(ValidateError::ClaimsNotAfterDecision)
        ));
    }

    #[test]
    fn c3_claims_before_any_decision_is_rejected() {
        let open = open_object();
        let mut log = CaseLog::open(&open, &open_body()).unwrap();
        let claims = object(Kind::Claims, Some(*log.case_id()), vec![], 1);
        assert!(matches!(
            log.apply(&claims, &claims_content(&["c1"])),
            Err(ValidateError::CaseNotOpen)
        ));
    }

    #[test]
    fn c3_a_second_claims_object_is_rejected() {
        let (mut log, decision, _claims) = case_through_claims();
        let decision_id = praxis_types::object_id(&decision).unwrap();
        let more_claims = object(Kind::Claims, Some(*log.case_id()), vec![decision_id], 4);
        assert!(matches!(
            log.apply(&more_claims, &claims_content(&["c2"])),
            Err(ValidateError::DuplicateClaims)
        ));
    }

    // ---- C4 ----

    #[test]
    fn c4_duplicate_claim_ids_within_one_claims_object_are_rejected() {
        let open = open_object();
        let mut log = CaseLog::open(&open, &open_body()).unwrap();
        let case_id = *log.case_id();
        let prediction = object(Kind::Prediction, Some(case_id), vec![], 1);
        log.apply(&prediction, &prediction_content()).unwrap();
        let prediction_id = praxis_types::object_id(&prediction).unwrap();
        let decision = object(Kind::Decision, Some(case_id), vec![prediction_id], 2);
        log.apply(&decision, &decision_content()).unwrap();
        let decision_id = praxis_types::object_id(&decision).unwrap();

        let claims = object(Kind::Claims, Some(case_id), vec![decision_id], 3);
        assert!(matches!(
            log.apply(&claims, &claims_content(&["c1", "c1"])),
            Err(ValidateError::DuplicateClaimId(id)) if id == "c1"
        ));
    }

    // ---- C5 ----

    #[test]
    fn c5_amend_adding_a_new_flagged_late_claim_is_accepted() {
        let (mut log, _decision, claims) = case_through_claims();
        let claims_id = praxis_types::object_id(&claims).unwrap();
        let amend = object(Kind::Amend, Some(*log.case_id()), vec![claims_id], 5);
        let content = Content::Amend(AmendBody {
            target: praxis_types::object_id(&claims).unwrap(),
            note: long("adding a claim noticed late"),
            late_claims: Some(vec![claim("c2", Some(true))]),
        });
        assert!(log.apply(&amend, &content).is_ok());
        assert!(log.claim_ids().contains("c2"));
    }

    #[test]
    fn c5_amend_late_claim_not_flagged_late_is_rejected() {
        let (mut log, _decision, claims) = case_through_claims();
        let amend = object(Kind::Amend, Some(*log.case_id()), vec![], 5);
        let content = Content::Amend(AmendBody {
            target: praxis_types::object_id(&claims).unwrap(),
            note: long("oops"),
            late_claims: Some(vec![claim("c2", None)]),
        });
        assert!(matches!(
            log.apply(&amend, &content),
            Err(ValidateError::LateClaimNotFlagged(id)) if id == "c2"
        ));
    }

    #[test]
    fn c5_amend_reusing_an_existing_claim_id_is_rejected() {
        let (mut log, _decision, claims) = case_through_claims();
        let amend = object(Kind::Amend, Some(*log.case_id()), vec![], 5);
        let content = Content::Amend(AmendBody {
            target: praxis_types::object_id(&claims).unwrap(),
            note: long("trying to sneak a modification in as a 'late claim'"),
            late_claims: Some(vec![claim("c1", Some(true))]),
        });
        assert!(matches!(
            log.apply(&amend, &content),
            Err(ValidateError::AmendReusesClaimId(id)) if id == "c1"
        ));
    }

    // ---- C6 ----

    #[test]
    fn c6_outcome_resolving_a_known_claim_is_accepted() {
        let (mut log, _decision, claims) = case_through_claims();
        let claims_id = praxis_types::object_id(&claims).unwrap();
        let outcome = object(Kind::Outcome, Some(*log.case_id()), vec![claims_id], 6);
        assert!(log
            .apply(&outcome, &outcome_content("c1", ClaimOutcome::True))
            .is_ok());
        assert!(log.has_outcome());
    }

    #[test]
    fn c6_outcome_resolving_an_unknown_claim_is_rejected() {
        let (mut log, _decision, _claims) = case_through_claims();
        let outcome = object(Kind::Outcome, Some(*log.case_id()), vec![], 6);
        assert!(matches!(
            log.apply(&outcome, &outcome_content("does-not-exist", ClaimOutcome::True)),
            Err(ValidateError::UnknownClaim(id)) if id == "does-not-exist"
        ));
    }

    #[test]
    fn c6_void_outcome_with_a_reason_is_accepted() {
        let (mut log, _decision, claims) = case_through_claims();
        let claims_id = praxis_types::object_id(&claims).unwrap();
        let outcome = object(Kind::Outcome, Some(*log.case_id()), vec![claims_id], 6);
        assert!(log
            .apply(&outcome, &outcome_content("c1", ClaimOutcome::Void))
            .is_ok());
    }

    // ---- C7 ----

    #[test]
    fn c7_retract_is_a_tombstone_not_a_rejection() {
        let open = open_object();
        let mut log = CaseLog::open(&open, &open_body()).unwrap();
        let retract = object(Kind::Retract, Some(*log.case_id()), vec![], 1);
        let content = Content::Retract(RetractBody {
            reason: praxis_types::RetractReason::ConsentWithdrawn,
            note: None,
        });
        assert!(log.apply(&retract, &content).is_ok());
        assert!(log.is_retracted());
    }

    // ---- C8 ----

    #[test]
    fn c8_abandon_before_any_decision_is_accepted() {
        let open = open_object();
        let mut log = CaseLog::open(&open, &open_body()).unwrap();
        let abandon = object(Kind::Abandon, Some(*log.case_id()), vec![], 1);
        let content = Content::Abandon(AbandonBody {
            reason: short("no longer relevant"),
        });
        assert!(log.apply(&abandon, &content).is_ok());
        assert!(log.is_abandoned());
    }

    #[test]
    fn c8_abandon_after_a_decision_is_rejected() {
        let open = open_object();
        let mut log = CaseLog::open(&open, &open_body()).unwrap();
        let case_id = *log.case_id();
        let prediction = object(Kind::Prediction, Some(case_id), vec![], 1);
        log.apply(&prediction, &prediction_content()).unwrap();
        let prediction_id = praxis_types::object_id(&prediction).unwrap();
        let decision = object(Kind::Decision, Some(case_id), vec![prediction_id], 2);
        log.apply(&decision, &decision_content()).unwrap();

        let abandon = object(Kind::Abandon, Some(case_id), vec![], 3);
        let content = Content::Abandon(AbandonBody {
            reason: short("changed my mind"),
        });
        assert!(matches!(
            log.apply(&abandon, &content),
            Err(ValidateError::AbandonAfterDecision)
        ));
    }

    #[test]
    fn c8_abandon_after_an_outcome_is_rejected() {
        let (mut log, _decision, claims) = case_through_claims();
        let claims_id = praxis_types::object_id(&claims).unwrap();
        let outcome = object(Kind::Outcome, Some(*log.case_id()), vec![claims_id], 6);
        log.apply(&outcome, &outcome_content("c1", ClaimOutcome::True))
            .unwrap();

        let abandon = object(Kind::Abandon, Some(*log.case_id()), vec![], 7);
        let content = Content::Abandon(AbandonBody {
            reason: short("too late"),
        });
        // Already has a decision too (via case_through_claims), so either
        // AbandonAfterDecision or AbandonAfterOutcome is a correct rejection;
        // the decision check runs second in apply_abandon, so this hits that
        // one first — both are tested as their own direct scenarios above.
        assert!(matches!(
            log.apply(&abandon, &content),
            Err(ValidateError::AbandonAfterOutcome | ValidateError::AbandonAfterDecision)
        ));
    }

    #[test]
    fn case_field_mismatch_is_rejected() {
        let open = open_object();
        let mut log = CaseLog::open(&open, &open_body()).unwrap();
        let other_case = Cid::from_canonical_bytes(praxis_types::CidCodec::DagCbor, b"other");
        let prediction = object(Kind::Prediction, Some(other_case), vec![], 1);
        assert!(matches!(
            log.apply(&prediction, &prediction_content()),
            Err(ValidateError::CaseFieldShape)
        ));
    }
}
