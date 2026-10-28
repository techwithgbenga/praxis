// SPDX-License-Identifier: Apache-2.0
//! `canonical/*`: dag-cbor canonicality rules (`spec/PROTOCOL.md` §3).
//! Mirrors `praxis-types`' `codec.rs` unit tests, which already prove these
//! byte sequences behave as claimed — the vectors just externalize that
//! proof for `sdk/ts/verifier` (M1-09).

use std::collections::BTreeMap;

use praxis_types::Value;
use serde_json::json;

use crate::vector::{expected_error, hex, write_vector};

pub fn generate() {
    crate::vector::clean_category("canonical");

    accepted_int();
    accepted_text();
    accepted_bytes_vs_empty_array();
    accepted_nested_map_key_order();
    rejected_non_minimal_int();
    rejected_duplicate_map_key();
    rejected_indefinite_length();
    rejected_tag_other_than_42();
    rejected_float();
}

fn accepted_int() {
    let value = Value::Int(-7);
    let bytes = praxis_types::encode_canonical(&value).unwrap();
    write_vector(
        "canonical/int-001",
        "PROTOCOL.md#3.2",
        "A negative integer encodes to dag-cbor's shortest-form negative integer encoding.",
        &json!(-7),
        &json!({ "dag_cbor_hex": hex(&bytes) }),
    );
}

fn accepted_text() {
    let value = Value::Text("replica lag".to_string());
    let bytes = praxis_types::encode_canonical(&value).unwrap();
    write_vector(
        "canonical/text-001",
        "PROTOCOL.md#3.3",
        "NFC-normalized UTF-8 text encodes as a dag-cbor text string.",
        &json!("replica lag"),
        &json!({ "dag_cbor_hex": hex(&bytes) }),
    );
}

fn accepted_bytes_vs_empty_array() {
    // The exact case M1-07's content_dispatch work found broken in Value's
    // first (untagged-derive) Deserialize: an empty array must not decode as
    // empty bytes, or vice versa. Two vectors, not one, so the TS verifier
    // has to actually distinguish them rather than happening to pass by luck.
    let bytes_val = Value::Bytes(vec![1, 2, 3]);
    let bytes_enc = praxis_types::encode_canonical(&bytes_val).unwrap();
    write_vector(
        "canonical/bytes-001",
        "PROTOCOL.md#3.1",
        "A byte string (dag-cbor major type 2) is distinct from an array of the same integers.",
        &json!({ "kind": "bytes", "hex": hex(&[1, 2, 3]) }),
        &json!({ "dag_cbor_hex": hex(&bytes_enc) }),
    );

    let empty_array = Value::Array(vec![]);
    let empty_array_enc = praxis_types::encode_canonical(&empty_array).unwrap();
    let empty_bytes = Value::Bytes(vec![]);
    let empty_bytes_enc = praxis_types::encode_canonical(&empty_bytes).unwrap();
    write_vector(
        "canonical/bytes-002-empty-array-vs-empty-bytes",
        "PROTOCOL.md#3.1",
        "An empty array and empty bytes are different dag-cbor values (major type 4 length 0 \
         vs. major type 2 length 0) and must decode back to different Value variants.",
        &json!({
            "empty_array": { "kind": "array", "dag_cbor_hex": hex(&empty_array_enc) },
            "empty_bytes": { "kind": "bytes", "dag_cbor_hex": hex(&empty_bytes_enc) }
        }),
        &json!({
            "empty_array_hex": hex(&empty_array_enc),
            "empty_bytes_hex": hex(&empty_bytes_enc),
            "distinct": empty_array_enc != empty_bytes_enc
        }),
    );
}

fn accepted_nested_map_key_order() {
    // "aa" < "z" lexicographically, but dag-cbor canonical order sorts by
    // (length, then bytewise), so "z" (length 1) must come first on the wire.
    let mut map = BTreeMap::new();
    map.insert("z".to_string(), Value::Int(1));
    map.insert("aa".to_string(), Value::Int(2));
    let value = Value::Map(map);
    let bytes = praxis_types::encode_canonical(&value).unwrap();
    write_vector(
    "canonical/map-001-key-order",
    "PROTOCOL.md#3.1",
    "Map keys are ordered by (length, then bytewise), not lexicographically: \
         the 1-byte key \"z\" is encoded before the 2-byte key \"aa\" even though \"aa\" < \"z\" lexicographically.",
    &json!({ "z": 1, "aa": 2 }),
    &json!({ "dag_cbor_hex": hex(&bytes) }),
);
}

fn rejected_non_minimal_int() {
    // uint 1 encoded with a 4-byte form instead of the 1-byte shortest form.
    let bytes = vec![0x1a, 0x00, 0x00, 0x00, 0x01];
    write_vector(
        "canonical/reject-001-non-minimal-int",
        "PROTOCOL.md#3.1",
        "An integer encoded with more bytes than its shortest-form representation is rejected.",
        &json!({ "dag_cbor_hex": hex(&bytes) }),
        &expected_error("E_DECODE"),
    );
}

fn rejected_duplicate_map_key() {
    // map(2) { "a": 1, "a": 2 }
    let bytes = vec![0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02];
    write_vector(
        "canonical/reject-002-duplicate-map-key",
        "PROTOCOL.md#3.1",
        "A map with the same key appearing twice is rejected.",
        &json!({ "dag_cbor_hex": hex(&bytes) }),
        &expected_error("E_DECODE"),
    );
}

fn rejected_indefinite_length() {
    // Indefinite-length array containing [1, 2]: 0x9f 01 02 0xff.
    let bytes = vec![0x9f, 0x01, 0x02, 0xff];
    write_vector(
        "canonical/reject-003-indefinite-length",
        "PROTOCOL.md#3.1",
        "An indefinite-length array is rejected (dag-cbor requires definite lengths).",
        &json!({ "dag_cbor_hex": hex(&bytes) }),
        &expected_error("E_DECODE"),
    );
}

fn rejected_tag_other_than_42() {
    // tag(0) wrapping tstr "z".
    let bytes = vec![0xc0, 0x61, 0x7a];
    write_vector(
        "canonical/reject-004-tag-other-than-42",
        "PROTOCOL.md#3.1",
        "Any CBOR tag other than 42 (the CID link tag) is rejected.",
        &json!({ "dag_cbor_hex": hex(&bytes) }),
        &expected_error("E_DECODE"),
    );
}

fn rejected_float() {
    use ipld_core::ipld::Ipld;
    let ipld = Ipld::Map(BTreeMap::from([("x".to_string(), Ipld::Float(1.5))]));
    let bytes = serde_ipld_dagcbor::to_vec(&ipld).unwrap();
    write_vector(
        "canonical/reject-005-float",
        "PROTOCOL.md#3.2",
        "No floating-point values are permitted anywhere in a signed/hashed object.",
        &json!({ "dag_cbor_hex": hex(&bytes) }),
        &expected_error("E_FLOAT_NOT_ALLOWED"),
    );
}
