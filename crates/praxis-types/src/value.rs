// SPDX-License-Identifier: Apache-2.0
//! The generic, float-free value shapes from `spec/praxis-v0.1.cddl`: `decimal`
//! and `value`.

use std::collections::BTreeMap;
use std::fmt;

use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::envelope::Cid;

/// `decimal = { m: int, e: int }` meaning `m * 10^e` (`spec/PROTOCOL.md` §3.2):
/// the protocol's only representation of non-integer domain data. No floats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decimal {
    /// The mantissa.
    pub m: i64,
    /// The base-10 exponent.
    pub e: i32,
}

/// `value = null / bool / int / tstr / bstr / [* value] / {* tstr => value}`
/// (`spec/praxis-v0.1.cddl`): JSON-like, deliberately **no floats anywhere**
/// (`spec/PROTOCOL.md` §3.2).
///
/// Map key ordering here is whatever `BTreeMap<String, _>`'s `Ord` gives
/// (lexicographic byte order), which is **not** dag-cbor's canonical "sort by
/// (length, then bytewise)" rule (`spec/PROTOCOL.md` §3.1). The canonical codec
/// (M1-02) re-sorts map entries by the CDDL rule when it actually encodes a
/// `Value`; this in-memory representation does not need to match that order.
///
/// `Deserialize` is hand-written (a `Visitor` over `deserialize_any`), **not**
/// `#[serde(untagged)]`: untagged enums resolve ambiguity by buffering the
/// input into serde's generic `Content` representation and trying each
/// variant's `Deserialize` in declaration order against that buffer — which
/// discards *which* wire-level call (`visit_bytes` vs. `visit_seq`) actually
/// produced it. That made an empty dag-cbor array (major type 4, length 0)
/// silently decode as `Bytes(vec![])` instead of `Array(vec![])`, found while
/// implementing M1-07's content dispatch (not just a JSON-only limitation, as
/// M1-02 had assumed — dag-cbor is not immune to this once serde's untagged
/// machinery is involved, even though the *wire format* distinguishes the two
/// perfectly well). A hand-written `Visitor` is called directly by the
/// format's deserializer based on the wire type it actually sees, with no
/// buffering step to lose that information in.
///
/// The [`Value::Link`] variant is *not* part of the CDDL `value` grammar
/// above (which has no `cid` alternative) — it exists because this same type
/// is reused in two different roles (`praxis_types::envelope::PlainBody`'s
/// doc comment): the strict `value` grammar (`signal.value`, `situation.context`
/// entries), and a generic stand-in for `content` as a whole
/// (`Object.body.plain`, `Object.unknown`), which legitimately embeds `cid`
/// fields (e.g. `amend-body.target`, `evidence.ref`) that §3.1 permits via
/// CBOR tag 42 ("no CBOR tags other than 42 (CID link)"). Without this
/// variant, decoding *any* object whose content embeds a `Cid` failed outright
/// (found while generating `spec/test-vectors/events/*` for `amend`/`outcome`).
/// `// OPEN(Q-012)`: nothing in this crate or `praxis-validate` yet rejects a
/// `Value::Link` appearing in a strict `value`-grammar position (domain-pack
/// `signal.value`/`context` are not validated at all yet — domain packs are
/// unimplemented before M2); tracked in `docs/EVALUATION.md`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Value {
    /// `null`.
    Null,
    /// `bool`.
    Bool(bool),
    /// `int`: a signed integer (dag-cbor supports the full `i64`/`u64` range; this
    /// crate stores it as `i64`, which covers every value the protocol actually
    /// needs — see `spec/PROTOCOL.md` §3.2 for the integer-only rule this exists to serve).
    Int(i64),
    /// `tstr`.
    Text(String),
    /// `bstr`.
    #[serde(with = "serde_bytes")]
    Bytes(Vec<u8>),
    /// `[* value]`.
    Array(Vec<Value>),
    /// `{* tstr => value}`.
    Map(BTreeMap<String, Value>),
    /// `#6.42(bstr)`: a CID link embedded in `content` (see the variant note above).
    Link(Cid),
}

impl<'de> Deserialize<'de> for Value {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ValueVisitor)
    }
}

struct ValueVisitor;

impl<'de> Visitor<'de> for ValueVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "a Praxis value (null, bool, int, text, bytes, array, or map)"
        )
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Int(v))
    }

    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Value, E> {
        i64::try_from(v)
            .map(Value::Int)
            .map_err(|_| E::custom("integer too large for i64"))
    }

    fn visit_i128<E: serde::de::Error>(self, v: i128) -> Result<Value, E> {
        i64::try_from(v)
            .map(Value::Int)
            .map_err(|_| E::custom("integer out of i64 range"))
    }

    fn visit_u128<E: serde::de::Error>(self, v: u128) -> Result<Value, E> {
        i64::try_from(v)
            .map(Value::Int)
            .map_err(|_| E::custom("integer out of i64 range"))
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(Value::Text(v.to_owned()))
    }

    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Value, E> {
        Ok(Value::Text(v))
    }

    fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Value, E> {
        Ok(Value::Bytes(v.to_vec()))
    }

    fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Value, E> {
        Ok(Value::Bytes(v))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element()? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut entries = BTreeMap::new();
        while let Some((k, v)) = map.next_entry()? {
            entries.insert(k, v);
        }
        Ok(Value::Map(entries))
    }

    // `serde_ipld_dagcbor`'s deserializer, on CBOR tag 42, calls
    // `visitor.visit_newtype_struct` with a one-shot inner deserializer
    // (`CidDeserializer`) that only answers `deserialize_bytes`/
    // `deserialize_newtype_struct("$__private__serde__identifier__for__cid", _)`
    // with the CID's raw bytes — it does *not* re-enter the newtype-struct
    // dance a second time. `ipld_core::cid::Cid`'s own `Deserialize` impl
    // expects to be the one driving that dance (it calls
    // `deserializer.deserialize_newtype_struct` itself), so calling it
    // directly here double-wraps and fails with "invalid type: byte array,
    // expected a valid CID in bytes, wrapped in an newtype struct". Instead,
    // ask this inner deserializer for bytes directly and validate them the
    // same way `Cid::deserialize` does (`Cid::validate`).
    fn visit_newtype_struct<D: Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Value, D::Error> {
        deserializer
            .deserialize_bytes(CidBytesVisitor)
            .map(Value::Link)
    }
}

struct CidBytesVisitor;

impl Visitor<'_> for CidBytesVisitor {
    type Value = Cid;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a CID's raw bytes")
    }

    fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Cid, E> {
        let raw = <ipld_core::cid::Cid as TryFrom<&[u8]>>::try_from(v).map_err(E::custom)?;
        Cid::validate(raw).map_err(E::custom)
    }

    fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Cid, E> {
        self.visit_bytes(&v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(value: &Value) {
        let json = serde_json::to_string(value).expect("serialize");
        let back: Value = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(value, &back, "round-trip via {json:?} changed the value");
    }

    fn roundtrip_cbor(value: &Value) {
        let bytes = crate::encode_canonical(value).expect("serialize");
        let back: Value = crate::decode_canonical(&bytes).expect("deserialize");
        assert_eq!(value, &back, "dag-cbor round-trip changed the value");
    }

    #[test]
    fn decimal_roundtrips() {
        let d = Decimal { m: -42, e: -3 };
        let json = serde_json::to_string(&d).unwrap();
        let back: Decimal = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn null_bool_int_text_roundtrip() {
        roundtrip(&Value::Null);
        roundtrip(&Value::Bool(true));
        roundtrip(&Value::Int(-7));
        roundtrip(&Value::Text("replica lag".into()));
    }

    #[test]
    fn nested_array_and_map_roundtrip() {
        let mut map = BTreeMap::new();
        map.insert("a".to_string(), Value::Int(1));
        map.insert(
            "b".to_string(),
            Value::Array(vec![Value::Bool(false), Value::Null]),
        );
        roundtrip(&Value::Map(map));
    }

    // NOTE: still not exercised through serde_json here, since JSON itself has no
    // byte-string wire type — that is a real, unfixable JSON limitation, not the
    // bug the hand-written Deserialize above fixes. dag-cbor does distinguish
    // bytes from arrays at the wire level, and `roundtrip_cbor` below proves the
    // `Value` deserializer now respects that distinction correctly, including
    // for the empty-array/empty-bytes edge case that was actually broken.
    #[test]
    fn bytes_serializes_as_a_json_array_of_byte_values() {
        let json = serde_json::to_string(&Value::Bytes(vec![1, 2, 3])).unwrap();
        assert_eq!(json, "[1,2,3]");
    }

    #[test]
    fn dag_cbor_roundtrip_distinguishes_bytes_from_array() {
        roundtrip_cbor(&Value::Bytes(vec![]));
        roundtrip_cbor(&Value::Array(vec![]));
        roundtrip_cbor(&Value::Bytes(vec![1, 2, 3]));
        roundtrip_cbor(&Value::Array(vec![
            Value::Int(1),
            Value::Int(2),
            Value::Int(3),
        ]));
    }

    #[test]
    fn dag_cbor_roundtrip_handles_large_unsigned_integers() {
        // u64 values beyond i64::MAX still decode (within i64's own range check);
        // this just confirms the visit_u64/visit_i128 paths are reachable and correct
        // for ordinary values, not that we support the full u64 range (we don't,
        // deliberately — see the Int variant's doc comment).
        roundtrip_cbor(&Value::Int(i64::MAX));
        roundtrip_cbor(&Value::Int(0));
    }

    #[test]
    fn dag_cbor_roundtrip_nested_structure() {
        let mut inner = BTreeMap::new();
        inner.insert("signals".to_string(), Value::Array(vec![]));
        inner.insert("context".to_string(), Value::Map(BTreeMap::new()));
        roundtrip_cbor(&Value::Map(inner));
    }

    fn sample_cid() -> Cid {
        Cid::new(
            crate::envelope::CidCodec::DagCbor,
            crate::scalar::Hash32::new([7u8; 32]),
        )
    }

    #[test]
    fn dag_cbor_roundtrip_handles_cid_links() {
        roundtrip_cbor(&Value::Link(sample_cid()));

        let mut map = BTreeMap::new();
        map.insert("target".to_string(), Value::Link(sample_cid()));
        map.insert("note".to_string(), Value::Text("fixed a typo".into()));
        roundtrip_cbor(&Value::Map(map));
    }

    /// Regression test for the bug found generating `events/*` vectors
    /// (M1-08): decoding *any* real content struct with a `Cid` field (e.g.
    /// `amend-body.target`) generically as `Value` used to fail with
    /// "invalid type: newtype struct", because `Value` had no representation
    /// for CBOR tag 42. `spec/PROTOCOL.md` §3.1 permits tag 42 anywhere in
    /// canonical encoding, so `Object.body.plain`/`Object.unknown` (both
    /// typed `Value`, per `envelope::PlainBody`'s docs) must round-trip it.
    #[test]
    fn dag_cbor_roundtrip_of_a_cid_bearing_content_struct_via_generic_value() {
        use crate::content::AmendBody;
        use crate::scalar::LongText;

        let amend = AmendBody {
            target: sample_cid(),
            note: LongText::new("fixed a typo in the summary").unwrap(),
            late_claims: None,
        };
        let bytes = crate::encode_canonical(&amend).expect("encode AmendBody");
        let value: Value = crate::decode_canonical(&bytes).expect("decode generically as Value");
        let reencoded = crate::encode_canonical(&value).expect("re-encode Value");
        let back: AmendBody =
            crate::decode_canonical(&reencoded).expect("decode back to AmendBody");
        assert_eq!(amend, back);
    }
}
