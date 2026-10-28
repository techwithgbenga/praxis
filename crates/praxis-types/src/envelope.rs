// SPDX-License-Identifier: Apache-2.0
//! The object envelope (`spec/PROTOCOL.md` §5, `spec/praxis-v0.1.cddl`): every
//! signed/hashed Praxis object shares this shape.

use std::collections::BTreeMap;

use ipld_core::cid::multihash::Multihash;
use ipld_core::cid::{Cid as RawCid, Version as CidVersion};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::scalar::{Did, Hash32, Kid, Suite, Ts};
use crate::value::Value;

/// Multicodec `0x71`: dag-cbor (`spec/PROTOCOL.md` §2).
const MULTICODEC_DAG_CBOR: u64 = 0x71;
/// Multicodec `0x55`: raw bytes (`spec/PROTOCOL.md` §2).
const MULTICODEC_RAW: u64 = 0x55;
/// Multihash function code `0x1e`: BLAKE3 (`spec/PROTOCOL.md` §2).
const MULTIHASH_BLAKE3: u64 = 0x1e;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CidCodec {
    /// Multicodec `0x71`: a canonical dag-cbor-encoded object.
    DagCbor,
    /// Multicodec `0x55`: a raw blob.
    Raw,
}

impl CidCodec {
    fn to_multicodec(self) -> u64 {
        match self {
            Self::DagCbor => MULTICODEC_DAG_CBOR,
            Self::Raw => MULTICODEC_RAW,
        }
    }

    fn from_multicodec(code: u64) -> Option<Self> {
        match code {
            MULTICODEC_DAG_CBOR => Some(Self::DagCbor),
            MULTICODEC_RAW => Some(Self::Raw),
            _ => None,
        }
    }
}

/// `cid = #6.42(bstr)` (`spec/praxis-v0.1.cddl`): a `CIDv1`, restricted to the
/// exact multicodec/multihash combinations this protocol uses
/// (`spec/PROTOCOL.md` §2: dag-cbor or raw, always BLAKE3-256). Wraps
/// [`ipld_core::cid::Cid`] (which already round-trips correctly through CBOR
/// tag 42 — see `spec/PROTOCOL.md` §3.1) rather than re-implementing
/// multiformats binary encoding.
///
/// `Deserialize` re-validates every constraint CDDL leaves to prose: version
/// must be 1, the multicodec must be `dag-cbor`/`raw`, the multihash function
/// must be BLAKE3, and the digest must be exactly 32 bytes. An
/// `ipld_core::cid::Cid` that merely parses as *some* valid CID is not enough.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cid(RawCid);

impl Cid {
    /// Builds a `Cid` from its codec and a 32-byte BLAKE3-256 digest.
    ///
    /// # Panics
    /// Never, in practice: `Hash32` is always exactly 32 bytes, which always
    /// fits the 64-byte multihash buffer.
    #[must_use]
    pub fn new(codec: CidCodec, digest: Hash32) -> Self {
        let mh = Multihash::<64>::wrap(MULTIHASH_BLAKE3, digest.as_bytes().as_slice())
            .expect("a 32-byte digest always fits a 64-byte multihash buffer");
        Self(RawCid::new_v1(codec.to_multicodec(), mh))
    }

    /// Computes the `Cid` of some already-canonically-encoded bytes
    /// (`spec/PROTOCOL.md` §5.1: "Object ID = CID of the entire canonical
    /// encoding"; §8.6 for blobs, which use `CidCodec::Raw`). `bytes` is
    /// *not* re-canonicalized here — pass it through [`crate::encode_object`]
    /// (or an equivalent canonical encoding) first.
    #[must_use]
    pub fn from_canonical_bytes(codec: CidCodec, bytes: &[u8]) -> Self {
        let digest: [u8; 32] = *blake3::hash(bytes).as_bytes();
        Self::new(codec, Hash32::new(digest))
    }

    /// This CID's multicodec.
    ///
    /// # Panics
    /// Never: every `Cid` is constructed via [`Cid::new`] or decoded via
    /// `Deserialize` (which rejects unsupported multicodecs), so one is always present.
    #[must_use]
    pub fn codec(&self) -> CidCodec {
        CidCodec::from_multicodec(self.0.codec())
            .expect("only constructible, or decodable, with a supported multicodec")
    }

    /// This CID's 32-byte BLAKE3-256 digest.
    ///
    /// # Panics
    /// Never: every `Cid` is constructed via [`Cid::new`] (always 32 bytes) or
    /// decoded via `Deserialize` (which rejects any other digest length).
    #[must_use]
    pub fn digest(&self) -> Hash32 {
        let bytes: [u8; 32] = self
            .0
            .hash()
            .digest()
            .try_into()
            .expect("only constructible, or decodable, with a 32-byte digest");
        Hash32::new(bytes)
    }
}

impl Serialize for Cid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Cid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawCid::deserialize(deserializer)?;
        if raw.version() != CidVersion::V1 {
            return Err(serde::de::Error::custom("cid must be CIDv1"));
        }
        if CidCodec::from_multicodec(raw.codec()).is_none() {
            return Err(serde::de::Error::custom(format!(
                "unsupported CID multicodec {:#x} (expected dag-cbor 0x71 or raw 0x55)",
                raw.codec()
            )));
        }
        let hash = raw.hash();
        if hash.code() != MULTIHASH_BLAKE3 {
            return Err(serde::de::Error::custom(format!(
                "unsupported CID multihash code {:#x} (expected BLAKE3 0x1e)",
                hash.code()
            )));
        }
        if hash.digest().len() != 32 {
            return Err(serde::de::Error::custom(
                "CID digest must be exactly 32 bytes",
            ));
        }
        Ok(Self(raw))
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

    /// Official BLAKE3 test vectors (`BLAKE3-team/BLAKE3`,
    /// `test_vectors/test_vectors.json`, `hash` mode, first 32 bytes of the
    /// extended output — downloaded and parsed with a script, not retyped by
    /// hand, to avoid a transcription error in the hex). Per that file's
    /// `_comment`: the input of length `n` is the 251-byte sequence
    /// `0, 1, 2, ..., 250, 0, 1, ...` truncated to `n` bytes.
    #[test]
    fn cid_from_canonical_bytes_matches_official_blake3_vectors() {
        fn input_of_len(n: usize) -> Vec<u8> {
            (0..n).map(|i| u8::try_from(i % 251).unwrap()).collect()
        }

        let cases: &[(usize, &str)] = &[
            (
                0,
                "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
            ),
            (
                1,
                "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
            ),
            (
                1024,
                "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
            ),
            (
                1025,
                "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
            ),
        ];

        for (len, expected_hex) in cases {
            let input = input_of_len(*len);
            let cid = Cid::from_canonical_bytes(CidCodec::Raw, &input);
            let expected: Vec<u8> = (0..expected_hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&expected_hex[i..i + 2], 16).unwrap())
                .collect();
            assert_eq!(
                cid.digest().as_bytes().as_slice(),
                expected.as_slice(),
                "mismatch for input_len={len}"
            );
        }
    }

    #[test]
    fn cid_from_canonical_bytes_is_deterministic_and_codec_sensitive() {
        let a = Cid::from_canonical_bytes(CidCodec::DagCbor, b"hello");
        let b = Cid::from_canonical_bytes(CidCodec::DagCbor, b"hello");
        assert_eq!(a, b);
        assert_eq!(a.codec(), CidCodec::DagCbor);

        let raw = Cid::from_canonical_bytes(CidCodec::Raw, b"hello");
        assert_eq!(
            raw.digest(),
            a.digest(),
            "same bytes, same digest regardless of codec"
        );
        assert_eq!(raw.codec(), CidCodec::Raw);
        assert_ne!(
            a, raw,
            "codec is part of CID identity even with an equal digest"
        );

        let different = Cid::from_canonical_bytes(CidCodec::DagCbor, b"goodbye");
        assert_ne!(a, different);
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
