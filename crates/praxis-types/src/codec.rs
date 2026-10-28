// SPDX-License-Identifier: Apache-2.0
//! The canonical dag-cbor codec (`spec/PROTOCOL.md` §3, §5.2).
//!
//! `serde_ipld_dagcbor` already decodes strictly (rejects non-minimal integers,
//! duplicate/unordered map keys, indefinite-length items, and any CBOR tag
//! other than 42) and always encodes canonically (map keys sorted by length
//! then bytewise, regardless of the source collection's own order). This
//! module adds the three things that library doesn't know about: this
//! protocol's own size/depth/array-length limits (§3.5), the float ban
//! (§3.2) at the generic-value level, and the normative belt-and-suspenders
//! "recomputed canonical bytes must equal the received bytes" check (§5.2),
//! which should always be redundant with the strict decode but is required
//! regardless, in case a future dependency version is ever slightly more lenient.

use ipld_core::ipld::Ipld;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::envelope::Object;

/// `spec/PROTOCOL.md` §3.5: encoded object size limit.
pub const MAX_OBJECT_BYTES: usize = 256 * 1024;
/// `spec/PROTOCOL.md` §3.5: array item limit.
pub const MAX_ARRAY_ITEMS: usize = 1024;
/// `spec/PROTOCOL.md` §3.5: nesting depth limit.
pub const MAX_NESTING_DEPTH: usize = 16;

/// Everything that can go wrong decoding or encoding an [`Object`].
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    /// `spec/PROTOCOL.md` §3.5: object exceeds 256 KiB encoded.
    #[error(
        "object is {0} bytes, exceeding the {MAX_OBJECT_BYTES}-byte limit (spec/PROTOCOL.md §3.5)"
    )]
    TooLarge(usize),
    /// dag-cbor decode failed (malformed, non-canonical, or wrong shape).
    #[error("dag-cbor decode failed: {0}")]
    Decode(String),
    /// dag-cbor encode failed (should not normally happen for well-formed values).
    #[error("dag-cbor encode failed: {0}")]
    Encode(String),
    /// `spec/PROTOCOL.md` §5.2: the input bytes were not the canonical
    /// encoding of the value they decode to.
    #[error("non-canonical encoding: input bytes did not match their own canonical re-encoding (spec/PROTOCOL.md §5.2)")]
    NonCanonical,
    /// `spec/PROTOCOL.md` §3.2: no floating-point values anywhere.
    #[error("floating-point value present, which spec/PROTOCOL.md §3.2 forbids")]
    FloatNotAllowed,
    /// `spec/PROTOCOL.md` §3.5: nesting depth limit exceeded.
    #[error("nesting depth {0} exceeds the limit of {MAX_NESTING_DEPTH} (spec/PROTOCOL.md §3.5)")]
    TooDeep(usize),
    /// `spec/PROTOCOL.md` §3.5: array item limit exceeded.
    #[error(
        "array has {0} items, exceeding the limit of {MAX_ARRAY_ITEMS} (spec/PROTOCOL.md §3.5)"
    )]
    ArrayTooLong(usize),
    /// An `Object.unknown` entry uses the same name as one of the envelope's
    /// own named fields. Encoding this would silently produce a dag-cbor map
    /// with that key twice — invalid CBOR, not just non-canonical — so this is
    /// caught here rather than left to corrupt the output.
    #[error("unknown field name {0:?} collides with a reserved envelope field name")]
    ReservedFieldName(String),
}

impl CodecError {
    /// The stable `E_*` code for this error (`AGENTS.md` §3 `DoD`), independent
    /// of the `Display` message's exact wording — e.g. [`Self::Decode`] wraps
    /// an opaque, library-specific message that varies across dag-cbor
    /// implementations and is not itself a stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::TooLarge(_) => "E_TOO_LARGE",
            Self::Decode(_) => "E_DECODE",
            Self::Encode(_) => "E_ENCODE",
            Self::NonCanonical => "E_NONCANONICAL",
            Self::FloatNotAllowed => "E_FLOAT_NOT_ALLOWED",
            Self::TooDeep(_) => "E_TOO_DEEP",
            Self::ArrayTooLong(_) => "E_ARRAY_TOO_LONG",
            Self::ReservedFieldName(_) => "E_RESERVED_FIELD_NAME",
        }
    }
}

/// The envelope's own field names (`spec/praxis-v0.1.cddl` `object`).
/// `Object.unknown` MUST NOT contain any of these: a decoded object never can
/// (serde's `flatten` routes a given key to either a named field or the
/// catch-all map, never both), but a hand-built `Object` could, and encoding
/// one would produce a dag-cbor map with a duplicate key.
const RESERVED_FIELD_NAMES: [&str; 11] = [
    "v", "kind", "case", "prev", "author", "signer", "ts", "suite", "body", "sig", "crit",
];

fn check_limits(value: &Ipld, depth: usize) -> Result<(), CodecError> {
    if depth > MAX_NESTING_DEPTH {
        return Err(CodecError::TooDeep(depth));
    }
    match value {
        Ipld::Float(_) => Err(CodecError::FloatNotAllowed),
        Ipld::List(items) => {
            if items.len() > MAX_ARRAY_ITEMS {
                return Err(CodecError::ArrayTooLong(items.len()));
            }
            items
                .iter()
                .try_for_each(|item| check_limits(item, depth + 1))
        }
        Ipld::Map(entries) => entries
            .values()
            .try_for_each(|v| check_limits(v, depth + 1)),
        Ipld::Null
        | Ipld::Bool(_)
        | Ipld::Integer(_)
        | Ipld::String(_)
        | Ipld::Bytes(_)
        | Ipld::Link(_) => Ok(()),
    }
}

/// Decodes and fully validates *any* type `T` from its canonical dag-cbor
/// bytes: non-minimal integers, unordered/duplicate map keys,
/// indefinite-length items, any tag other than 42 (all already caught by the
/// strict underlying decoder, re-verified here per §5.2), floats anywhere in
/// the structure, nesting deeper than 16, and arrays longer than 1024 items.
///
/// This is the general-purpose half of [`decode_object`], which additionally
/// enforces [`MAX_OBJECT_BYTES`] (a whole-`Object`-specific limit, not
/// meaningful for an arbitrary substructure — e.g. a sealed body's plaintext,
/// `praxis-crypto`'s use case for this).
///
/// # Errors
/// See [`CodecError`].
pub fn decode_canonical<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CodecError> {
    let generic: Ipld =
        serde_ipld_dagcbor::from_slice(bytes).map_err(|e| CodecError::Decode(e.to_string()))?;
    check_limits(&generic, 0)?;

    let reencoded =
        serde_ipld_dagcbor::to_vec(&generic).map_err(|e| CodecError::Encode(e.to_string()))?;
    if reencoded != bytes {
        return Err(CodecError::NonCanonical);
    }

    serde_ipld_dagcbor::from_slice(bytes).map_err(|e| CodecError::Decode(e.to_string()))
}

/// Encodes any `T` to its canonical dag-cbor bytes. See [`decode_canonical`]
/// for why this is split out from [`encode_object`].
///
/// # Errors
/// See [`CodecError::Encode`].
pub fn encode_canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, CodecError> {
    serde_ipld_dagcbor::to_vec(value).map_err(|e| CodecError::Encode(e.to_string()))
}

/// Decodes and fully validates an [`Object`] from its canonical dag-cbor bytes.
///
/// Rejects everything [`decode_canonical`] does, plus oversized input, and
/// any field-level shape/range violation enforced by the `Object`/content
/// types themselves (`spec/PROTOCOL.md` §3, M1-01).
///
/// Does **not** check signatures, identity-log validity, or case-lifecycle
/// rules (C1-C8) — that is `praxis-validate`'s job (M1-07), one layer up.
///
/// # Errors
/// See [`CodecError`].
pub fn decode_object(bytes: &[u8]) -> Result<Object, CodecError> {
    if bytes.len() > MAX_OBJECT_BYTES {
        return Err(CodecError::TooLarge(bytes.len()));
    }
    decode_canonical(bytes)
}

/// Encodes an [`Object`] to its canonical dag-cbor bytes.
///
/// Does not enforce [`MAX_OBJECT_BYTES`] etc. on the way out: those are
/// decode-side (untrusted-input) limits. A caller building an oversized
/// object has a bug to fix, not an error to handle.
///
/// # Errors
/// See [`CodecError::Encode`] and [`CodecError::ReservedFieldName`].
pub fn encode_object(object: &Object) -> Result<Vec<u8>, CodecError> {
    if let Some(name) = object
        .unknown
        .keys()
        .find(|k| RESERVED_FIELD_NAMES.contains(&k.as_str()))
    {
        return Err(CodecError::ReservedFieldName(name.clone()));
    }
    encode_canonical(object)
}

/// Computes an object's own ID: the `Cid` of its entire canonical encoding,
/// *including* `sig` (`spec/PROTOCOL.md` §5.1). Ed25519 is deterministic, so
/// this is stable for a given signed object.
///
/// # Errors
/// See [`encode_object`].
pub fn object_id(object: &Object) -> Result<crate::envelope::Cid, CodecError> {
    let bytes = encode_object(object)?;
    Ok(crate::envelope::Cid::from_canonical_bytes(
        crate::envelope::CidCodec::DagCbor,
        &bytes,
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use proptest::prelude::*;

    use super::*;
    use crate::envelope::{Body, Cid, CidCodec, FormatVersion, Kind, PlainBody};
    use crate::scalar::{Did, Hash32, Kid as KeyId, Sig, Suite, Ts};
    use crate::value::Value;

    fn sample_object(unknown: BTreeMap<String, Value>) -> Object {
        Object {
            v: FormatVersion,
            kind: Kind::Open,
            case: None,
            prev: vec![Cid::new(CidCodec::DagCbor, Hash32::new([1u8; 32]))],
            author: Did::new("did:praxis:".to_string() + &"a".repeat(20)).unwrap(),
            signer: KeyId::new("device-1").unwrap(),
            ts: Ts::from_millis(1_793_000_000_000),
            suite: Suite::Pxs1,
            body: Body::Plain(PlainBody {
                plain: Value::Map(BTreeMap::new()),
                salt: [2u8; 16],
                pad: None,
            }),
            sig: Sig::new([3u8; 64]),
            crit: None,
            unknown,
        }
    }

    #[test]
    fn roundtrips_through_canonical_bytes() {
        let obj = sample_object(BTreeMap::new());
        let bytes = encode_object(&obj).unwrap();
        let back = decode_object(&bytes).unwrap();
        assert_eq!(obj, back);
    }

    #[test]
    fn encoding_is_deterministic() {
        let obj = sample_object(BTreeMap::new());
        assert_eq!(encode_object(&obj).unwrap(), encode_object(&obj).unwrap());
    }

    #[test]
    fn object_id_is_the_cid_of_its_own_canonical_bytes() {
        let obj = sample_object(BTreeMap::new());
        let bytes = encode_object(&obj).unwrap();
        let expected = Cid::from_canonical_bytes(CidCodec::DagCbor, &bytes);
        assert_eq!(object_id(&obj).unwrap(), expected);
    }

    #[test]
    fn map_keys_are_sorted_by_length_then_bytewise_not_lexicographically() {
        // "aa" < "z" lexicographically, but "z" (length 1) must sort first in
        // canonical dag-cbor, which sorts by length before bytes.
        let mut unknown = BTreeMap::new();
        unknown.insert("z".to_string(), Value::Int(1));
        unknown.insert("aa".to_string(), Value::Int(2));
        let bytes = encode_object(&sample_object(unknown)).unwrap();
        let pos_z = bytes
            .windows(2)
            .position(|w| w == [0x61, 0x7a])
            .expect("key \"z\" present");
        let pos_aa = bytes
            .windows(3)
            .position(|w| w == [0x62, 0x61, 0x61])
            .expect("key \"aa\" present");
        assert!(
            pos_z < pos_aa,
            "\"z\" (shorter) must be encoded before \"aa\" (longer)"
        );
    }

    #[test]
    fn decode_canonical_works_on_an_arbitrary_substructure() {
        let body = PlainBody {
            plain: Value::Int(42),
            salt: [9u8; 16],
            pad: None,
        };
        let bytes = encode_canonical(&body).unwrap();
        let back: PlainBody = decode_canonical(&bytes).unwrap();
        assert_eq!(body, back);
    }

    #[test]
    fn decode_canonical_still_rejects_non_canonical_input() {
        // Non-minimal integer, same as `rejects_non_minimal_integers` below,
        // but through the generic entry point `decode_object` delegates to.
        let bytes: Vec<u8> = vec![0x1a, 0x00, 0x00, 0x00, 0x01];
        assert!(matches!(
            decode_canonical::<u32>(&bytes),
            Err(CodecError::Decode(_))
        ));
    }

    #[test]
    fn rejects_oversized_input() {
        let huge = vec![0u8; MAX_OBJECT_BYTES + 1];
        assert!(matches!(decode_object(&huge), Err(CodecError::TooLarge(_))));
    }

    #[test]
    fn rejects_duplicate_map_keys() {
        // map(2) { "a": 1, "a": 2 } — 0xa2 0x61 0x61 0x01 0x61 0x61 0x02
        let bytes: Vec<u8> = vec![0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02];
        assert!(matches!(decode_object(&bytes), Err(CodecError::Decode(_))));
    }

    #[test]
    fn rejects_non_minimal_integers() {
        // uint 1 encoded as a 4-byte form instead of the 1-byte shortest form.
        let bytes: Vec<u8> = vec![0x1a, 0x00, 0x00, 0x00, 0x01];
        assert!(matches!(decode_object(&bytes), Err(CodecError::Decode(_))));
    }

    #[test]
    fn rejects_indefinite_length_items() {
        // indefinite-length array containing [1, 2]: 0x9f 01 02 ff
        let bytes: Vec<u8> = vec![0x9f, 0x01, 0x02, 0xff];
        assert!(matches!(decode_object(&bytes), Err(CodecError::Decode(_))));
    }

    #[test]
    fn rejects_tags_other_than_42() {
        // tag(0) wrapping tstr "z": 0xc0 0x61 0x7a
        let bytes: Vec<u8> = vec![0xc0, 0x61, 0x7a];
        assert!(matches!(decode_object(&bytes), Err(CodecError::Decode(_))));
    }

    #[test]
    fn rejects_floats() {
        // `Value` has no float variant (by design), so to actually put a float
        // on the wire for `decode_object` to reject, build and encode a raw
        // `Ipld` document directly rather than going through our own types.
        let ipld = Ipld::Map(BTreeMap::from([("x".to_string(), Ipld::Float(1.5))]));
        let bytes = serde_ipld_dagcbor::to_vec(&ipld).unwrap();
        assert!(matches!(
            decode_object(&bytes),
            Err(CodecError::FloatNotAllowed)
        ));
    }

    #[test]
    fn rejects_arrays_over_the_item_limit() {
        let ipld = Ipld::List(
            (0..=MAX_ARRAY_ITEMS)
                .map(|i| Ipld::Integer(i as i128))
                .collect(),
        );
        let bytes = serde_ipld_dagcbor::to_vec(&ipld).unwrap();
        assert!(matches!(
            decode_object(&bytes),
            Err(CodecError::ArrayTooLong(_))
        ));
    }

    #[test]
    fn rejects_nesting_deeper_than_the_limit() {
        let mut ipld = Ipld::Null;
        for _ in 0..=MAX_NESTING_DEPTH + 1 {
            ipld = Ipld::List(vec![ipld]);
        }
        let bytes = serde_ipld_dagcbor::to_vec(&ipld).unwrap();
        assert!(matches!(decode_object(&bytes), Err(CodecError::TooDeep(_))));
    }

    fn arb_short_key() -> impl Strategy<Value = String> {
        // Excludes the envelope's reserved field names: a collision there is a
        // real but separate bug, covered by its own test below, not part of
        // the "well-formed input round-trips" property this one checks.
        "[a-z]{1,6}".prop_filter("must not be a reserved envelope field name", |k| {
            !RESERVED_FIELD_NAMES.contains(&k.as_str())
        })
    }

    #[test]
    fn encode_rejects_unknown_field_colliding_with_reserved_name() {
        let mut unknown = BTreeMap::new();
        unknown.insert("v".to_string(), Value::Null);
        let obj = sample_object(unknown);
        assert!(
            matches!(encode_object(&obj), Err(CodecError::ReservedFieldName(name)) if name == "v")
        );
    }

    fn arb_value() -> impl Strategy<Value = Value> {
        prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::Bool),
            any::<i32>().prop_map(|i| Value::Int(i64::from(i))),
            "[a-zA-Z0-9 ]{0,16}".prop_map(Value::Text),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn encode_decode_is_identity_for_arbitrary_unknown_fields(
            entries in prop::collection::btree_map(arb_short_key(), arb_value(), 0..8)
        ) {
            let obj = sample_object(entries);
            let bytes = encode_object(&obj).unwrap();
            let back = decode_object(&bytes).unwrap();
            prop_assert_eq!(&obj, &back);
            // Canonical encoding is a pure function of content, independent of
            // the BTreeMap's construction order (it only ever has one order anyway).
            prop_assert_eq!(encode_object(&obj).unwrap(), encode_object(&back).unwrap());
        }
    }
}
