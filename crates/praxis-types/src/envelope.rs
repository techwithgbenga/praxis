// SPDX-License-Identifier: Apache-2.0
//! The object envelope (`spec/PROTOCOL.md` §5, `spec/praxis-v0.1.cddl`): every
//! signed/hashed Praxis object shares this shape.

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::scalar::{Did, Hash32, Kid, Suite, Ts};
use crate::value::Value;

/// `v: 1` (`spec/praxis-v0.1.cddl`): the envelope format version. Fixed at `1` for
/// spec v0.1; any other value is rejected on deserialize rather than silently
/// accepted, since a future breaking format version is negotiated in `HELLO`
/// (`spec/PROTOCOL.md` §13), not auto-detected from this field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FormatVersion;

impl Serialize for FormatVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(1)
    }
}

impl<'de> Deserialize<'de> for FormatVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u8::deserialize(deserializer)?;
        if value == 1 {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(format!(
                "unsupported envelope version {value}"
            )))
        }
    }
}

/// Which multicodec a [`Cid`] addresses (`spec/PROTOCOL.md` §2): `dag-cbor` for
/// every signed object, `raw` for blobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CidCodec {
    /// Multicodec `0x71`: a canonical dag-cbor-encoded object.
    DagCbor,
    /// Multicodec `0x55`: a raw blob.
    Raw,
}

/// `cid = #6.42(bstr)` (`spec/praxis-v0.1.cddl`): a `CIDv1`, always BLAKE3-256
/// (`spec/PROTOCOL.md` §2).
///
/// Scope note: this models a CID as `{codec, digest}` rather than its exact
/// multiformats binary encoding (varint-prefixed multicodec + multihash). That
/// binary form, and computing a `Cid` from an object's canonical bytes, is
/// `praxis-types`' M1-03 task ("`CIDv1` (dag-cbor, blake3-256)"); this shape is
/// what the rest of the envelope needs in the meantime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Cid {
    /// The multicodec this CID addresses.
    pub codec: CidCodec,
    /// The BLAKE3-256 digest.
    pub digest: Hash32,
}

impl Cid {
    /// Builds a `Cid` from its codec and digest.
    #[must_use]
    pub fn new(codec: CidCodec, digest: Hash32) -> Self {
        Self { codec, digest }
    }
}

/// Every object kind in the protocol (`spec/praxis-v0.1.cddl` `kind`), flattened
/// from its four families (identity / case / lineage / attestation —
/// `spec/PROTOCOL.md` §1) into one enum. Each variant's wire form is its exact
/// CDDL string literal (e.g. `IdGenesis` <-> `"id-genesis"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    // Identity
    /// `id-genesis`
    IdGenesis,
    /// `id-rotate`
    IdRotate,
    /// `id-delegate`
    IdDelegate,
    /// `id-revoke`
    IdRevoke,
    // Case events
    /// `open`
    Open,
    /// `prediction`
    Prediction,
    /// `decision`
    Decision,
    /// `claims`
    Claims,
    /// `elicitation`
    Elicitation,
    /// `outcome`
    Outcome,
    /// `amend`
    Amend,
    /// `retract`
    Retract,
    /// `abandon`
    Abandon,
    // Lineage
    /// `grant`
    Grant,
    /// `derive`
    Derive,
    /// `diverge`
    Diverge,
    /// `canon`
    Canon,
    // Attestation
    /// `anchor`
    Anchor,
    /// `attest`
    Attest,
}

/// `recipient = { kid: kid, enc: bstr, wrapped: bstr }` (`spec/PROTOCOL.md` §8.4):
/// an HPKE-wrapped body key (or case key) for one recipient device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recipient {
    /// The recipient's key identifier.
    pub kid: Kid,
    /// The HPKE encapsulated key.
    #[serde(with = "serde_bytes")]
    pub enc: Vec<u8>,
    /// The HPKE-sealed body key (or case key `CK`).
    #[serde(with = "serde_bytes")]
    pub wrapped: Vec<u8>,
}

/// `plain-body = { plain: content, salt: bstr .size 16, ? pad: bstr }`
/// (`spec/PROTOCOL.md` §8.1).
///
/// `plain` is the generic [`Value`] shape here, not yet the kind-specific
/// content struct: per `spec/PROTOCOL.md` §12, decoding the envelope (steps 1-4)
/// and validating kind-specific content against the CDDL (step 6) are separate
/// stages. `praxis_types::content` provides the typed structs and the
/// kind-dispatched conversion from `Value`; `praxis-validate` (M1-07) is what
/// actually runs that conversion during validation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlainBody {
    /// The content, generically typed (see above).
    pub plain: Value,
    /// 16 random bytes, hiding low-entropy content from guessing (only relevant
    /// once a body is sealed and later revealed; present on every plain body too
    /// so a later `seal` of equivalent content is not distinguishable from one
    /// that started sealed).
    #[serde(with = "crate::bytes_serde")]
    pub salt: [u8; 16],
    /// Optional padding bytes (unused for plain bodies today; reserved by the CDDL).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::bytes_serde::opt_bytes"
    )]
    pub pad: Option<Vec<u8>>,
}

/// `sealed = { alg: "xc20p", nonce: bstr .size 24, ct: bstr }` (`spec/PROTOCOL.md` §8.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedPayload {
    /// Fixed at `"xc20p"` (XChaCha20-Poly1305) for suite `pxs1`.
    pub alg: SealAlg,
    /// A 24-byte `XChaCha20` nonce.
    #[serde(with = "crate::bytes_serde")]
    pub nonce: [u8; 24],
    /// The AEAD ciphertext (includes the Poly1305 tag).
    #[serde(with = "serde_bytes")]
    pub ct: Vec<u8>,
}

/// The sealed-body AEAD algorithm. Only `xc20p` exists in suite `pxs1`
/// (`spec/PROTOCOL.md` §2); modeled as a single-variant enum, like [`crate::Suite`],
/// so a future suite's different algorithm is a compile-time-visible match arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SealAlg {
    /// XChaCha20-Poly1305 (24-byte nonce).
    #[serde(rename = "xc20p")]
    Xc20p,
}

/// `sealed-body = { sealed: {...}, commit: hash32, ? rcpt: [* recipient] }`
/// (`spec/PROTOCOL.md` §8.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedBody {
    /// The AEAD-sealed payload.
    pub sealed: SealedPayload,
    /// `BLAKE3("praxis/v1/commit\x00" || plaintext_bytes)` (`spec/PROTOCOL.md` §8.2).
    pub commit: Hash32,
    /// Recipients this body's key has been wrapped to, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rcpt: Option<Vec<Recipient>>,
}

/// `body = plain-body / sealed-body` (`spec/PROTOCOL.md` §8.1).
///
/// Untagged is safe here (unlike `content`, see `praxis_types::content`): the two
/// variants are distinguished by disjoint required keys (`plain` vs `sealed`), so
/// there is no shape ambiguity for serde to resolve incorrectly.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Body {
    /// An unencrypted body.
    Plain(PlainBody),
    /// An encrypted body; content validation happens only after a reveal.
    Sealed(SealedBody),
}

/// The object envelope itself (`spec/PROTOCOL.md` §5, `spec/praxis-v0.1.cddl` `object`).
///
/// `sig` covers the canonical encoding of this struct *without* the `sig` field
/// itself (`spec/PROTOCOL.md` §5.2); computing and verifying that signature is
/// `praxis-crypto`'s job, not this crate's — this type only carries the bytes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Object {
    /// Format version; always `1` for spec v0.1.
    pub v: FormatVersion,
    /// The object's kind.
    pub kind: Kind,
    /// The case this object belongs to (omitted on `open`, whose own ID *is* the case ID).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case: Option<Cid>,
    /// Causal parents: object IDs the author had seen and builds on.
    pub prev: Vec<Cid>,
    /// The authoring practitioner's (or agent's) DID.
    pub author: Did,
    /// The key, within the author's identity log, that produced `sig`.
    pub signer: Kid,
    /// Self-asserted creation time (`spec/PROTOCOL.md` §4.5: a claim, strengthened by anchors).
    pub ts: Ts,
    /// The cipher suite in use.
    pub suite: Suite,
    /// The (plain or sealed) body.
    pub body: Body,
    /// The Ed25519 signature over this object's canonical bytes, minus this field.
    pub sig: crate::scalar::Sig,
    /// Field names a validator MUST understand or reject the object (`spec/PROTOCOL.md` §3.4).
    ///
    /// Non-emptiness (`[+ tstr]`) is not enforced at this layer; see `praxis-validate`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crit: Option<Vec<String>>,
    /// Every other field present on the wire, preserved verbatim across
    /// decode-then-encode (`spec/PROTOCOL.md` §3.4) and covered by the signature.
    #[serde(flatten)]
    pub unknown: BTreeMap<String, Value>,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::scalar::{Did, Kid, Sig};

    fn test_did() -> Did {
        Did::new("did:praxis:".to_string() + &"a".repeat(20)).unwrap()
    }

    fn plain_object() -> Object {
        Object {
            v: FormatVersion,
            kind: Kind::Open,
            case: None,
            prev: vec![Cid::new(CidCodec::DagCbor, Hash32::new([1u8; 32]))],
            author: test_did(),
            signer: Kid::new("device-1").unwrap(),
            ts: Ts::from_millis(1_793_000_000_000),
            suite: Suite::Pxs1,
            body: Body::Plain(PlainBody {
                plain: Value::Map(BTreeMap::new()),
                salt: [2u8; 16],
                pad: None,
            }),
            sig: Sig::new([3u8; 64]),
            crit: None,
            unknown: BTreeMap::new(),
        }
    }

    fn roundtrip(obj: &Object) -> Object {
        let json = serde_json::to_string(obj).expect("serialize");
        let back: Object = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(obj, &back, "round-trip via {json} changed the value");
        back
    }

    #[test]
    fn plain_object_roundtrips() {
        roundtrip(&plain_object());
    }

    #[test]
    fn sealed_object_roundtrips() {
        let mut obj = plain_object();
        obj.kind = Kind::Decision;
        obj.body = Body::Sealed(SealedBody {
            sealed: SealedPayload {
                alg: SealAlg::Xc20p,
                nonce: [4u8; 24],
                ct: vec![5, 6, 7],
            },
            commit: Hash32::new([8u8; 32]),
            rcpt: Some(vec![Recipient {
                kid: Kid::new("device-2").unwrap(),
                enc: vec![9, 9],
                wrapped: vec![10, 10, 10],
            }]),
        });
        roundtrip(&obj);
    }

    #[test]
    fn unknown_fields_are_preserved_across_roundtrip() {
        let mut obj = plain_object();
        obj.unknown
            .insert("future_field".to_string(), Value::Int(42));
        let back = roundtrip(&obj);
        assert_eq!(back.unknown.get("future_field"), Some(&Value::Int(42)));
    }

    #[test]
    fn crit_is_preserved_when_present_and_omitted_when_absent() {
        let mut obj = plain_object();
        obj.crit = Some(vec!["future_field".to_string()]);
        let json = serde_json::to_string(&obj).unwrap();
        assert!(json.contains("\"crit\""));
        roundtrip(&obj);

        let mut obj2 = plain_object();
        obj2.crit = None;
        let json2 = serde_json::to_string(&obj2).unwrap();
        assert!(!json2.contains("\"crit\""));
    }

    #[test]
    fn version_other_than_1_is_rejected() {
        let mut obj = plain_object();
        let mut json: serde_json::Value = serde_json::to_value(&obj).unwrap();
        // Force `v` to 2 to simulate a future-format object this validator must reject.
        json["v"] = serde_json::json!(2);
        let err = serde_json::from_value::<Object>(json).unwrap_err();
        assert!(err.to_string().contains("unsupported envelope version"));
        let _ = &mut obj; // keep `obj` used for clarity of intent above
    }

    #[test]
    fn kind_wire_strings_match_cddl_literals() {
        assert_eq!(
            serde_json::to_string(&Kind::IdGenesis).unwrap(),
            "\"id-genesis\""
        );
        assert_eq!(
            serde_json::to_string(&Kind::Elicitation).unwrap(),
            "\"elicitation\""
        );
        assert_eq!(
            serde_json::to_string(&Kind::Diverge).unwrap(),
            "\"diverge\""
        );
    }
}
