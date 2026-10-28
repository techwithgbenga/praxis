// SPDX-License-Identifier: Apache-2.0
//! The generic, float-free value shapes from `spec/praxis-v0.1.cddl`: `decimal`
//! and `value`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(value: &Value) {
        let json = serde_json::to_string(value).expect("serialize");
        let back: Value = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(value, &back, "round-trip via {json:?} changed the value");
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

    // NOTE: `Value::Bytes` is deliberately not round-tripped through serde_json
    // here. JSON has no distinct byte-string wire type, so a JSON array of small
    // integers is ambiguous between `Bytes` and `Array(Vec<Value::Int>)`; this
    // `#[serde(untagged)]` enum resolves that ambiguity by variant declaration
    // order, which is not the identity we want to assert. dag-cbor (wired in at
    // M1-02 via serde_ipld_dagcbor) has a distinct wire type for byte strings, so
    // the real round-trip property holds there; that is where this gets tested
    // against spec/test-vectors/**.
    #[test]
    fn bytes_serializes_as_a_json_array_of_byte_values() {
        let json = serde_json::to_string(&Value::Bytes(vec![1, 2, 3])).unwrap();
        assert_eq!(json, "[1,2,3]");
    }
}
