// SPDX-License-Identifier: Apache-2.0
//! Kind-dispatched content parsing (`spec/PROTOCOL.md` §12 step 6: "If
//! `plain`: validate content against CDDL"): turns a generic [`Value`] (what
//! the envelope decode gives you, per `praxis_types::Body::Plain`'s own
//! scope note) into the specific typed [`Content`] struct the sibling `kind`
//! field says it should be.
//!
//! Implemented as `Value -> canonical bytes -> specific struct`, reusing
//! `encode_canonical`/`decode_canonical` (M1-05) rather than a hand-rolled
//! generic-value-as-deserializer: it's two extra allocations on a path that
//! is not hot (one object at a time, not a tight loop), in exchange for zero
//! new serde plumbing.

use praxis_types::{
    AbandonBody, AnchorBody, AttestBody, CanonBody, Content, DecisionBody, DeriveBody, DivergeBody,
    ElicitationBody, GrantBody, IdContent, Kind, OpenBody, OutcomeBody, PredictionBody,
    RetractBody, Value,
};

use crate::error::ValidateError;

/// Parses `value` into the [`Content`] variant `kind` implies.
///
/// # Errors
/// Returns [`ValidateError::Decode`] if `value`'s canonical encoding does not
/// match the shape `kind` requires (e.g. a `decision` object whose body is
/// missing `chosen`).
pub fn parse_content(kind: Kind, value: &Value) -> Result<Content, ValidateError> {
    let bytes = praxis_types::encode_canonical(value)?;
    Ok(match kind {
        Kind::IdGenesis | Kind::IdRotate | Kind::IdDelegate | Kind::IdRevoke => {
            Content::Id(praxis_types::decode_canonical::<IdContent>(&bytes)?)
        }
        Kind::Open => Content::Open(praxis_types::decode_canonical::<OpenBody>(&bytes)?),
        Kind::Prediction => {
            Content::Prediction(praxis_types::decode_canonical::<PredictionBody>(&bytes)?)
        }
        Kind::Decision => {
            Content::Decision(praxis_types::decode_canonical::<DecisionBody>(&bytes)?)
        }
        Kind::Claims => Content::Claims(
            praxis_types::decode_canonical::<praxis_types::ClaimsBody>(&bytes)?,
        ),
        Kind::Elicitation => {
            Content::Elicitation(praxis_types::decode_canonical::<ElicitationBody>(&bytes)?)
        }
        Kind::Outcome => Content::Outcome(praxis_types::decode_canonical::<OutcomeBody>(&bytes)?),
        Kind::Amend => Content::Amend(praxis_types::decode_canonical::<praxis_types::AmendBody>(
            &bytes,
        )?),
        Kind::Retract => Content::Retract(praxis_types::decode_canonical::<RetractBody>(&bytes)?),
        Kind::Abandon => Content::Abandon(praxis_types::decode_canonical::<AbandonBody>(&bytes)?),
        Kind::Grant => Content::Grant(praxis_types::decode_canonical::<GrantBody>(&bytes)?),
        Kind::Derive => Content::Derive(praxis_types::decode_canonical::<DeriveBody>(&bytes)?),
        Kind::Diverge => Content::Diverge(praxis_types::decode_canonical::<DivergeBody>(&bytes)?),
        Kind::Canon => Content::Canon(praxis_types::decode_canonical::<CanonBody>(&bytes)?),
        Kind::Anchor => Content::Anchor(praxis_types::decode_canonical::<AnchorBody>(&bytes)?),
        Kind::Attest => Content::Attest(praxis_types::decode_canonical::<AttestBody>(&bytes)?),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use praxis_types::{Impact, Reversibility, Situation, Stakes, TimePressure, Usage, UsageScope};

    use super::*;

    fn short(s: &str) -> praxis_types::ShortText {
        praxis_types::ShortText::new(s).unwrap()
    }
    fn long(s: &str) -> praxis_types::LongText {
        praxis_types::LongText::new(s).unwrap()
    }

    #[test]
    fn parses_open_body_from_a_generic_value() {
        let open = OpenBody {
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
        };
        // Round-trip through Value the way a decoded Object actually would:
        // encode the typed struct, then decode it generically as `Value`.
        let bytes = praxis_types::encode_canonical(&open).unwrap();
        let value: Value = praxis_types::decode_canonical(&bytes).unwrap();

        let parsed = parse_content(Kind::Open, &value).unwrap();
        assert_eq!(parsed, Content::Open(open));
        assert_eq!(parsed.kind(), Kind::Open);
    }

    #[test]
    fn rejects_content_that_does_not_match_the_claimed_kind() {
        let abandon = AbandonBody {
            reason: short("superseded"),
        };
        let bytes = praxis_types::encode_canonical(&abandon).unwrap();
        let value: Value = praxis_types::decode_canonical(&bytes).unwrap();

        // Claiming this is a `decision` body (which requires `chosen` and
        // `options_considered`, neither present here) must fail to parse.
        assert!(parse_content(Kind::Decision, &value).is_err());
    }
}
