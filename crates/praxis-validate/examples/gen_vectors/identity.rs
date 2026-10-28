// SPDX-License-Identifier: Apache-2.0
//! `identity/*`: genesis/rotate/delegate chains and validity-at-time queries
//! (`spec/PROTOCOL.md` §4).

use praxis_crypto::SecretKey;
use praxis_identity::{IdentityError, IdentityLog, GENESIS_AUTHOR_SENTINEL};
use praxis_types::{
    Body, Ed25519Alg, FormatVersion, IdContent, IdOp, KeyEntry, KeyRole, Kid, Kind, PlainBody, Sig,
    Suite, Ts, Value,
};
use serde_json::json;

use crate::vector::{hex, write_vector};

/// `TEST_ONLY_*` deterministic seeds (`spec/test-vectors/README.md`: "MUST
/// NOT contain real secrets"). A fixed seed, not `SecretKey::generate()`, so
/// regenerating these vectors is reproducible.
fn test_only_key(seed_byte: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed_byte; 32]).unwrap()
}

fn key_entry(kid: &str, role: KeyRole, secret: &SecretKey, not_before: u64) -> KeyEntry {
    KeyEntry {
        kid: Kid::new(kid).unwrap(),
        alg: Ed25519Alg,
        public_key: secret.public_key().to_bytes(),
        role,
        enc_pub: None,
        not_before: Ts::from_millis(not_before),
        not_after: None,
        scope: None,
    }
}

fn signed_object(
    kind: Kind,
    signer_kid: &str,
    author: &str,
    ts: u64,
    secret: &SecretKey,
) -> praxis_types::Object {
    let mut obj = praxis_types::Object {
        v: FormatVersion,
        kind,
        case: None,
        prev: vec![],
        author: praxis_types::Did::new(author).unwrap(),
        signer: Kid::new(signer_kid).unwrap(),
        ts: Ts::from_millis(ts),
        suite: Suite::Pxs1,
        body: Body::Plain(PlainBody {
            plain: Value::Null,
            salt: [0u8; 16],
            pad: None,
        }),
        sig: Sig::new([0u8; 64]),
        crit: None,
        unknown: std::collections::BTreeMap::new(),
    };
    let bytes = obj.canonical_signing_bytes().unwrap();
    obj.sig = Sig::new(praxis_crypto::sign_object(secret, &bytes));
    obj
}

fn object_json(object: &praxis_types::Object) -> serde_json::Value {
    let bytes = praxis_types::encode_object(object).unwrap();
    json!({
        "kind": format!("{:?}", object.kind),
        "signer": object.signer.as_str(),
        "ts": object.ts.as_millis(),
        "dag_cbor_hex": hex(&bytes),
    })
}

pub fn generate() {
    crate::vector::clean_category("identity");
    genesis_rotate_delegate_chain();
    privilege_escalation_rejected();
}

fn genesis_rotate_delegate_chain() {
    let root1 = test_only_key(1);
    let root2 = test_only_key(2);
    let device1 = test_only_key(3);

    let genesis_content = IdContent {
        op: IdOp::Genesis,
        keys: Some(vec![key_entry("root-1", KeyRole::Root, &root1, 0)]),
        revoke: None,
    };
    let genesis_obj = signed_object(
        Kind::IdGenesis,
        "root-1",
        GENESIS_AUTHOR_SENTINEL,
        0,
        &root1,
    );
    let mut log = IdentityLog::genesis(&genesis_obj, &genesis_content).unwrap();
    let did = log.did().clone();

    let rotate_content = IdContent {
        op: IdOp::Rotate,
        keys: Some(vec![key_entry("root-2", KeyRole::Root, &root2, 1000)]),
        revoke: None,
    };
    let rotate_obj = signed_object(Kind::IdRotate, "root-1", did.as_str(), 1000, &root1);
    log.apply(&rotate_obj, &rotate_content).unwrap();

    let delegate_content = IdContent {
        op: IdOp::Delegate,
        keys: Some(vec![key_entry("device-1", KeyRole::Device, &device1, 2000)]),
        revoke: None,
    };
    let delegate_obj = signed_object(Kind::IdDelegate, "root-2", did.as_str(), 2000, &root2);
    log.apply(&delegate_obj, &delegate_content).unwrap();

    let queries = [
        ("root-1", 500u64, true),  // old root, before rotation: authorized
        ("root-1", 1000, false),   // old root, at/after rotation: retired (PIP-0003)
        ("root-2", 1000, true),    // new root, from rotation onward: authorized
        ("root-2", 999, false),    // new root, before it existed: not yet authorized
        ("device-1", 2000, true),  // delegated device key, from delegation onward
        ("device-1", 1999, false), // device key, before it was delegated
    ];
    let expected_queries: Vec<_> = queries
        .iter()
        .map(|(kid, ts, _expected)| {
            json!({
                "kid": kid,
                "ts": ts,
                "authorized": log.is_authorized(&Kid::new(*kid).unwrap(), Ts::from_millis(*ts), None),
            })
        })
        .collect();
    // Sanity-check the generator's own expectations against what it just computed,
    // so a future bug in this script (not the library) can't silently produce a
    // mismatched vector.
    for ((_, _, expected), got) in queries.iter().zip(&expected_queries) {
        assert_eq!(got["authorized"], json!(*expected));
    }

    write_vector(
        "identity/chain-001-genesis-rotate-delegate",
        "PROTOCOL.md#4",
        "A genesis -> rotate -> delegate chain, with is_authorized(kid, ts) queries \
         proving the old root is retired exactly at the rotation's ts (PIP-0003) and the \
         delegated device key is valid only from its own not_before onward.",
        &json!({
            "objects": [
                object_json(&genesis_obj),
                object_json(&rotate_obj),
                object_json(&delegate_obj),
            ],
        }),
        &json!({ "queries": expected_queries }),
    );
}

fn privilege_escalation_rejected() {
    let root = test_only_key(4);
    let device = test_only_key(5);
    let other = test_only_key(6);

    let genesis_content = IdContent {
        op: IdOp::Genesis,
        keys: Some(vec![key_entry("root-1", KeyRole::Root, &root, 0)]),
        revoke: None,
    };
    let genesis_obj = signed_object(Kind::IdGenesis, "root-1", GENESIS_AUTHOR_SENTINEL, 0, &root);
    let mut log = IdentityLog::genesis(&genesis_obj, &genesis_content).unwrap();
    let did = log.did().clone();

    let delegate_content = IdContent {
        op: IdOp::Delegate,
        keys: Some(vec![key_entry("device-1", KeyRole::Device, &device, 100)]),
        revoke: None,
    };
    let delegate_obj = signed_object(Kind::IdDelegate, "root-1", did.as_str(), 100, &root);
    log.apply(&delegate_obj, &delegate_content).unwrap();

    // device-1 (role: device) attempts to delegate a new device key — must be
    // rejected: only root/recovery may sign id-delegate (PIP-0003).
    let bad_content = IdContent {
        op: IdOp::Delegate,
        keys: Some(vec![key_entry("device-2", KeyRole::Device, &other, 200)]),
        revoke: None,
    };
    let bad_obj = signed_object(Kind::IdDelegate, "device-1", did.as_str(), 200, &device);
    let err = log.apply(&bad_obj, &bad_content).unwrap_err();
    assert!(matches!(err, IdentityError::UnauthorizedSigner(_, _)));

    write_vector(
        "identity/reject-001-device-key-cannot-delegate",
        "PROTOCOL.md#4.3",
        "A device-role key attempting to sign id-delegate (minting a new device key) is \
         rejected: only the current root or a recovery key may (PIP-0003). Catches the \
         privilege-escalation hole PIP-0003 closed (a leaked device key must not be able \
         to mint persistent new keys).",
        &json!({
            "setup_objects": [object_json(&genesis_obj), object_json(&delegate_obj)],
            "rejected_object": object_json(&bad_obj),
        }),
        &json!({ "error": err.code() }),
    );
}
