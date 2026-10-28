// SPDX-License-Identifier: Apache-2.0
//! `events/*`: full case lifecycles and C1-C8 violations
//! (`spec/PROTOCOL.md` §6). One vector per rule, each with a signed object
//! chain (`TEST_ONLY_*` keys) and the expected `praxis-validate` error code —
//! mirrors `praxis-validate`'s own `case_log.rs` scenario tests, externalized
//! for `sdk/ts/verifier` (M1-09).

use std::collections::BTreeMap;

use praxis_crypto::SecretKey;
use praxis_types::{
    AbandonBody, AmendBody, AttestedBy, AttestedResolution, Body, Cid, CidCodec, Claim,
    ClaimOutcome, ClaimResult, ClaimsBody, Content, DecisionBody, Did, Evidence, EvidenceKind,
    FormatVersion, Hash32, Impact, Kid, ModelRef, OpenBody, OptionProb, PlainBody, Ppm,
    PredictionBody, Resolution, RetractBody, RetractReason, Reversibility, Sig, Situation, Stakes,
    Suite, TimePressure, Ts, Usage, UsageScope, Value,
};
use praxis_validate::{CaseLog, ValidateError};
use serde_json::json;

use crate::vector::{hex, write_vector};

fn test_only_key(seed_byte: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed_byte; 32]).unwrap()
}

fn did() -> Did {
    Did::new("did:praxis:".to_string() + &"a".repeat(20)).unwrap()
}

fn short(s: &str) -> praxis_types::ShortText {
    praxis_types::ShortText::new(s).unwrap()
}
fn long(s: &str) -> praxis_types::LongText {
    praxis_types::LongText::new(s).unwrap()
}

fn signed(
    kind: praxis_types::Kind,
    case: Option<Cid>,
    prev: Vec<Cid>,
    content: &Content,
    ts: u64,
    secret: &SecretKey,
) -> praxis_types::Object {
    let value = content_to_value(content);
    let mut obj = praxis_types::Object {
        v: FormatVersion,
        kind,
        case,
        prev,
        author: did(),
        signer: Kid::new("device-1").unwrap(),
        ts: Ts::from_millis(ts),
        suite: Suite::Pxs1,
        body: Body::Plain(PlainBody {
            plain: value,
            salt: [0u8; 16],
            pad: None,
        }),
        sig: Sig::new([0u8; 64]),
        crit: None,
        unknown: BTreeMap::new(),
    };
    let bytes = obj.canonical_signing_bytes().unwrap();
    obj.sig = Sig::new(praxis_crypto::sign_object(secret, &bytes));
    obj
}

/// Round-trips any typed content through canonical bytes into the generic
/// `Value` an object's `body.plain` actually holds (mirrors how a real
/// object is built: see `praxis_validate::content_dispatch`'s module docs
/// for why this is the correct direction to convert in).
fn content_to_value(content: &Content) -> Value {
    let bytes = match content {
        Content::Open(c) => praxis_types::encode_canonical(c),
        Content::Prediction(c) => praxis_types::encode_canonical(c),
        Content::Decision(c) => praxis_types::encode_canonical(c),
        Content::Claims(c) => praxis_types::encode_canonical(c),
        Content::Outcome(c) => praxis_types::encode_canonical(c),
        Content::Amend(c) => praxis_types::encode_canonical(c),
        Content::Retract(c) => praxis_types::encode_canonical(c),
        Content::Abandon(c) => praxis_types::encode_canonical(c),
        _ => unreachable!("events.rs only builds case-event content"),
    }
    .unwrap();
    praxis_types::decode_canonical(&bytes).unwrap()
}

fn object_json(object: &praxis_types::Object) -> serde_json::Value {
    let bytes = praxis_types::encode_object(object).unwrap();
    json!({
        "kind": format!("{:?}", object.kind),
        "ts": object.ts.as_millis(),
        "dag_cbor_hex": hex(&bytes),
    })
}

fn open_body() -> OpenBody {
    OpenBody {
        domain: short("incident-response@0.1"),
        situation: Situation {
            summary: long("replica lag 40s"),
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
            employment_evaluation: praxis_types::EmploymentEvaluationIsAlwaysFalse,
            expires: None,
        },
        tags: None,
    }
}

fn prediction_body() -> PredictionBody {
    PredictionBody {
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
    }
}

fn decision_body() -> DecisionBody {
    DecisionBody {
        options_considered: vec![short("wait")],
        chosen: short("wait"),
        reasoning: None,
        confidence: None,
    }
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

pub fn generate() {
    crate::vector::clean_category("events");
    valid_full_lifecycle();
    reject_c1_open_with_case_field();
    reject_c2_decision_without_prediction();
    reject_c3_claims_not_after_decision();
    reject_c4_duplicate_claim_id();
    reject_c5_amend_reuses_claim_id();
    reject_c6_outcome_unknown_claim();
    accept_c7_retract_is_tombstone();
    reject_c8_abandon_after_decision();
}

fn valid_full_lifecycle() {
    let key = test_only_key(10);
    let open = signed(
        praxis_types::Kind::Open,
        None,
        vec![],
        &Content::Open(open_body()),
        0,
        &key,
    );
    let open_id = praxis_types::object_id(&open).unwrap();
    let mut log = CaseLog::open(&open, &open_body()).unwrap();

    let prediction = signed(
        praxis_types::Kind::Prediction,
        Some(open_id),
        vec![],
        &Content::Prediction(prediction_body()),
        1,
        &key,
    );
    log.apply(&prediction, &Content::Prediction(prediction_body()))
        .unwrap();
    let prediction_id = praxis_types::object_id(&prediction).unwrap();

    let decision = signed(
        praxis_types::Kind::Decision,
        Some(open_id),
        vec![prediction_id],
        &Content::Decision(decision_body()),
        2,
        &key,
    );
    log.apply(&decision, &Content::Decision(decision_body()))
        .unwrap();
    let decision_id = praxis_types::object_id(&decision).unwrap();

    let claims_body = ClaimsBody {
        claims: vec![claim("c1", None)],
    };
    let claims = signed(
        praxis_types::Kind::Claims,
        Some(open_id),
        vec![decision_id],
        &Content::Claims(claims_body.clone()),
        3,
        &key,
    );
    log.apply(&claims, &Content::Claims(claims_body)).unwrap();
    let claims_id = praxis_types::object_id(&claims).unwrap();

    let outcome_body = praxis_types::OutcomeBody {
        results: vec![ClaimResult {
            claim: short("c1"),
            result: ClaimOutcome::True,
            attributed: praxis_types::Attribution::Auto,
            evidence: vec![Evidence {
                kind: EvidenceKind::Observation,
                cid_ref: None,
                uri: None,
                note: None,
                at: None,
            }],
            void_reason: None,
        }],
        confounders: None,
        narrative: None,
    };
    let outcome = signed(
        praxis_types::Kind::Outcome,
        Some(open_id),
        vec![claims_id],
        &Content::Outcome(outcome_body.clone()),
        4,
        &key,
    );
    log.apply(&outcome, &Content::Outcome(outcome_body))
        .unwrap();

    write_vector(
        "events/valid-001-full-lifecycle",
        "PROTOCOL.md#6",
        "A complete, valid case lifecycle: open -> prediction -> decision -> claims -> outcome.",
        &json!({
            "objects": [
                object_json(&open),
                object_json(&prediction),
                object_json(&decision),
                object_json(&claims),
                object_json(&outcome),
            ],
        }),
        &json!({ "valid": true, "has_decision": log.has_decision(), "has_outcome": log.has_outcome() }),
    );
}

fn reject_c1_open_with_case_field() {
    let key = test_only_key(11);
    let bogus_case = Cid::from_canonical_bytes(CidCodec::DagCbor, b"bogus");
    let open = signed(
        praxis_types::Kind::Open,
        Some(bogus_case),
        vec![],
        &Content::Open(open_body()),
        0,
        &key,
    );
    let err = CaseLog::open(&open, &open_body()).unwrap_err();
    assert!(matches!(err, ValidateError::CaseFieldShape));

    write_vector(
        "events/reject-c1-open-with-case-field",
        "PROTOCOL.md#6 (C1)",
        "`open` MUST be the first object of a case; its own id IS the case id, so it must \
         not itself carry a `case` field.",
        &json!({ "object": object_json(&open) }),
        &json!({ "error": err.code() }),
    );
}

fn reject_c2_decision_without_prediction() {
    let key = test_only_key(12);
    let open = signed(
        praxis_types::Kind::Open,
        None,
        vec![],
        &Content::Open(open_body()),
        0,
        &key,
    );
    let open_id = praxis_types::object_id(&open).unwrap();
    let mut log = CaseLog::open(&open, &open_body()).unwrap();

    let decision = signed(
        praxis_types::Kind::Decision,
        Some(open_id),
        vec![],
        &Content::Decision(decision_body()),
        1,
        &key,
    );
    let err = log
        .apply(&decision, &Content::Decision(decision_body()))
        .unwrap_err();
    assert!(matches!(err, ValidateError::MissingPrediction));

    write_vector(
        "events/reject-c2-decision-without-prediction",
        "PROTOCOL.md#6 (C2)",
        "The anti-hindsight rule: a `prediction` MUST causally precede the `decision` it \
         concerns. A decision with no prior prediction in its `prev` is rejected.",
        &json!({ "setup_objects": [object_json(&open)], "rejected_object": object_json(&decision) }),
        &json!({ "error": err.code() }),
    );
}

fn reject_c3_claims_not_after_decision() {
    let key = test_only_key(13);
    let open = signed(
        praxis_types::Kind::Open,
        None,
        vec![],
        &Content::Open(open_body()),
        0,
        &key,
    );
    let open_id = praxis_types::object_id(&open).unwrap();
    let mut log = CaseLog::open(&open, &open_body()).unwrap();

    let prediction = signed(
        praxis_types::Kind::Prediction,
        Some(open_id),
        vec![],
        &Content::Prediction(prediction_body()),
        1,
        &key,
    );
    log.apply(&prediction, &Content::Prediction(prediction_body()))
        .unwrap();
    let prediction_id = praxis_types::object_id(&prediction).unwrap();

    let decision = signed(
        praxis_types::Kind::Decision,
        Some(open_id),
        vec![prediction_id],
        &Content::Decision(decision_body()),
        2,
        &key,
    );
    log.apply(&decision, &Content::Decision(decision_body()))
        .unwrap();

    let claims_body = ClaimsBody {
        claims: vec![claim("c1", None)],
    };
    // claims.prev deliberately omits the decision.
    let claims = signed(
        praxis_types::Kind::Claims,
        Some(open_id),
        vec![],
        &Content::Claims(claims_body.clone()),
        3,
        &key,
    );
    let err = log
        .apply(&claims, &Content::Claims(claims_body))
        .unwrap_err();
    assert!(matches!(err, ValidateError::ClaimsNotAfterDecision));

    write_vector(
        "events/reject-c3-claims-not-after-decision",
        "PROTOCOL.md#6 (C3)",
        "`claims` MUST causally follow `decision` (claims.prev contains the decision's id). \
         Claims whose prev omits the decision are rejected.",
        &json!({
            "setup_objects": [object_json(&open), object_json(&prediction), object_json(&decision)],
            "rejected_object": object_json(&claims),
        }),
        &json!({ "error": err.code() }),
    );
}

fn reject_c4_duplicate_claim_id() {
    let key = test_only_key(14);
    let open = signed(
        praxis_types::Kind::Open,
        None,
        vec![],
        &Content::Open(open_body()),
        0,
        &key,
    );
    let open_id = praxis_types::object_id(&open).unwrap();
    let mut log = CaseLog::open(&open, &open_body()).unwrap();

    let prediction = signed(
        praxis_types::Kind::Prediction,
        Some(open_id),
        vec![],
        &Content::Prediction(prediction_body()),
        1,
        &key,
    );
    log.apply(&prediction, &Content::Prediction(prediction_body()))
        .unwrap();
    let prediction_id = praxis_types::object_id(&prediction).unwrap();

    let decision = signed(
        praxis_types::Kind::Decision,
        Some(open_id),
        vec![prediction_id],
        &Content::Decision(decision_body()),
        2,
        &key,
    );
    log.apply(&decision, &Content::Decision(decision_body()))
        .unwrap();
    let decision_id = praxis_types::object_id(&decision).unwrap();

    let claims_body = ClaimsBody {
        claims: vec![claim("c1", None), claim("c1", None)],
    };
    let claims = signed(
        praxis_types::Kind::Claims,
        Some(open_id),
        vec![decision_id],
        &Content::Claims(claims_body.clone()),
        3,
        &key,
    );
    let err = log
        .apply(&claims, &Content::Claims(claims_body))
        .unwrap_err();
    assert!(matches!(err, ValidateError::DuplicateClaimId(ref id) if id == "c1"));

    write_vector(
        "events/reject-c4-duplicate-claim-id",
        "PROTOCOL.md#6 (C4)",
        "Each claim has a stable id, unique within the case. A `claims` object listing the \
         same id twice is rejected.",
        &json!({
            "setup_objects": [object_json(&open), object_json(&prediction), object_json(&decision)],
            "rejected_object": object_json(&claims),
        }),
        &json!({ "error": err.code() }),
    );
}

fn reject_c5_amend_reuses_claim_id() {
    let key = test_only_key(15);
    let open = signed(
        praxis_types::Kind::Open,
        None,
        vec![],
        &Content::Open(open_body()),
        0,
        &key,
    );
    let open_id = praxis_types::object_id(&open).unwrap();
    let mut log = CaseLog::open(&open, &open_body()).unwrap();

    let prediction = signed(
        praxis_types::Kind::Prediction,
        Some(open_id),
        vec![],
        &Content::Prediction(prediction_body()),
        1,
        &key,
    );
    log.apply(&prediction, &Content::Prediction(prediction_body()))
        .unwrap();
    let prediction_id = praxis_types::object_id(&prediction).unwrap();
    let decision = signed(
        praxis_types::Kind::Decision,
        Some(open_id),
        vec![prediction_id],
        &Content::Decision(decision_body()),
        2,
        &key,
    );
    log.apply(&decision, &Content::Decision(decision_body()))
        .unwrap();
    let decision_id = praxis_types::object_id(&decision).unwrap();
    let claims_body = ClaimsBody {
        claims: vec![claim("c1", None)],
    };
    let claims = signed(
        praxis_types::Kind::Claims,
        Some(open_id),
        vec![decision_id],
        &Content::Claims(claims_body.clone()),
        3,
        &key,
    );
    log.apply(&claims, &Content::Claims(claims_body)).unwrap();

    let amend_body = AmendBody {
        target: praxis_types::object_id(&claims).unwrap(),
        note: long("trying to sneak a modification in as a 'late claim'"),
        late_claims: Some(vec![claim("c1", Some(true))]),
    };
    let amend = signed(
        praxis_types::Kind::Amend,
        Some(open_id),
        vec![],
        &Content::Amend(amend_body.clone()),
        4,
        &key,
    );
    let err = log.apply(&amend, &Content::Amend(amend_body)).unwrap_err();
    assert!(matches!(err, ValidateError::AmendReusesClaimId(ref id) if id == "c1"));

    write_vector(
        "events/reject-c5-amend-reuses-claim-id",
        "PROTOCOL.md#6 (C5)",
        "`amend` may add late claims but MUST NOT modify an existing claim's p/resolve/\
         horizon. An amend reusing an already-registered claim id is rejected (the only \
         way to enforce 'never modify' without inspecting every field is to forbid reuse \
         of the id at all).",
        &json!({
            "setup_objects": [
                object_json(&open), object_json(&prediction), object_json(&decision), object_json(&claims)
            ],
            "rejected_object": object_json(&amend),
        }),
        &json!({ "error": err.code() }),
    );
}

fn reject_c6_outcome_unknown_claim() {
    let key = test_only_key(16);
    let open = signed(
        praxis_types::Kind::Open,
        None,
        vec![],
        &Content::Open(open_body()),
        0,
        &key,
    );
    let open_id = praxis_types::object_id(&open).unwrap();
    let mut log = CaseLog::open(&open, &open_body()).unwrap();
    let prediction = signed(
        praxis_types::Kind::Prediction,
        Some(open_id),
        vec![],
        &Content::Prediction(prediction_body()),
        1,
        &key,
    );
    log.apply(&prediction, &Content::Prediction(prediction_body()))
        .unwrap();
    let prediction_id = praxis_types::object_id(&prediction).unwrap();
    let decision = signed(
        praxis_types::Kind::Decision,
        Some(open_id),
        vec![prediction_id],
        &Content::Decision(decision_body()),
        2,
        &key,
    );
    log.apply(&decision, &Content::Decision(decision_body()))
        .unwrap();

    let outcome_body = praxis_types::OutcomeBody {
        results: vec![ClaimResult {
            claim: short("does-not-exist"),
            result: ClaimOutcome::True,
            attributed: praxis_types::Attribution::Auto,
            evidence: vec![],
            void_reason: None,
        }],
        confounders: None,
        narrative: None,
    };
    let outcome = signed(
        praxis_types::Kind::Outcome,
        Some(open_id),
        vec![],
        &Content::Outcome(outcome_body.clone()),
        3,
        &key,
    );
    let err = log
        .apply(&outcome, &Content::Outcome(outcome_body))
        .unwrap_err();
    assert!(matches!(err, ValidateError::UnknownClaim(ref id) if id == "does-not-exist"));

    write_vector(
        "events/reject-c6-outcome-unknown-claim",
        "PROTOCOL.md#6 (C6)",
        "`outcome` resolves claims that must actually exist in the case. An outcome \
         referencing an unregistered claim id is rejected.",
        &json!({
            "setup_objects": [object_json(&open), object_json(&prediction), object_json(&decision)],
            "rejected_object": object_json(&outcome),
        }),
        &json!({ "error": err.code() }),
    );
}

fn accept_c7_retract_is_tombstone() {
    let key = test_only_key(17);
    let open = signed(
        praxis_types::Kind::Open,
        None,
        vec![],
        &Content::Open(open_body()),
        0,
        &key,
    );
    let open_id = praxis_types::object_id(&open).unwrap();
    let mut log = CaseLog::open(&open, &open_body()).unwrap();

    let retract_body = RetractBody {
        reason: RetractReason::ConsentWithdrawn,
        note: None,
    };
    let retract = signed(
        praxis_types::Kind::Retract,
        Some(open_id),
        vec![],
        &Content::Retract(retract_body.clone()),
        1,
        &key,
    );
    log.apply(&retract, &Content::Retract(retract_body))
        .unwrap();

    write_vector(
        "events/accept-c7-retract-is-tombstone",
        "PROTOCOL.md#6 (C7)",
        "`retract` is a tombstone, not a rejection: it is accepted and marks the case as \
         retracted (compliant clients must then stop using it in new retrieval/training/\
         calibration — a policy-layer concern, not something the validator itself enforces).",
        &json!({ "setup_objects": [object_json(&open)], "object": object_json(&retract) }),
        &json!({ "valid": true, "is_retracted": log.is_retracted() }),
    );
}

fn reject_c8_abandon_after_decision() {
    let key = test_only_key(18);
    let open = signed(
        praxis_types::Kind::Open,
        None,
        vec![],
        &Content::Open(open_body()),
        0,
        &key,
    );
    let open_id = praxis_types::object_id(&open).unwrap();
    let mut log = CaseLog::open(&open, &open_body()).unwrap();
    let prediction = signed(
        praxis_types::Kind::Prediction,
        Some(open_id),
        vec![],
        &Content::Prediction(prediction_body()),
        1,
        &key,
    );
    log.apply(&prediction, &Content::Prediction(prediction_body()))
        .unwrap();
    let prediction_id = praxis_types::object_id(&prediction).unwrap();
    let decision = signed(
        praxis_types::Kind::Decision,
        Some(open_id),
        vec![prediction_id],
        &Content::Decision(decision_body()),
        2,
        &key,
    );
    log.apply(&decision, &Content::Decision(decision_body()))
        .unwrap();

    let abandon_body = AbandonBody {
        reason: short("changed my mind"),
    };
    let abandon = signed(
        praxis_types::Kind::Abandon,
        Some(open_id),
        vec![],
        &Content::Abandon(abandon_body.clone()),
        3,
        &key,
    );
    let err = log
        .apply(&abandon, &Content::Abandon(abandon_body))
        .unwrap_err();
    assert!(matches!(err, ValidateError::AbandonAfterDecision));

    write_vector(
        "events/reject-c8-abandon-after-decision",
        "PROTOCOL.md#6 (C8)",
        "`abandon` closes an *unresolved* case. A case that already has a `decision` is not \
         unresolved, so abandoning it afterward is rejected.",
        &json!({
            "setup_objects": [object_json(&open), object_json(&prediction), object_json(&decision)],
            "rejected_object": object_json(&abandon),
        }),
        &json!({ "error": err.code() }),
    );
}
