// SPDX-License-Identifier: Apache-2.0
//! `sealing/*`: `seal_body`/`unseal_body` end to end (`spec/PROTOCOL.md` §8) —
//! padding, the commit, the key hierarchy, and the AEAD, mirroring
//! `praxis-crypto`'s own `seal.rs` scenario tests. Externalized for
//! `sdk/ts/verifier` (M1-09), which must derive the same body key/AAD and
//! successfully unseal (and correctly reject tampering) without
//! reimplementing `seal_body`'s own randomized padding/nonce choices —
//! these vectors exercise the *unseal* direction against already-sealed,
//! fixed bodies, the same way `events/*`/`identity/*` exercise validation
//! against already-signed objects rather than the signing process itself.

use praxis_crypto::{seal_body, unseal_body, CaseKey, SealError, PAD_BUCKETS};
use praxis_types::{Cid, CidCodec, Hash32, Value};
use rand::{CryptoRng, RngCore};
use serde_json::json;

use crate::vector::{expected_error, hex, write_vector};

/// `TEST_ONLY` deterministic byte stream for `seal_body`'s `rng` parameter
/// (`spec/test-vectors/README.md`: fixtures must be reproducible, never real
/// secrets). **Not** a CSPRNG: `CryptoRng` is implemented only so this
/// type-checks against `seal_body`'s bound. Never use this outside vector
/// generation.
struct TestOnlyRng(u64);

impl RngCore for TestOnlyRng {
    #[allow(clippy::cast_possible_truncation)] // deterministic test-only byte stream, truncation is fine
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        // SplitMix64.
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut chunks = dest.chunks_exact_mut(8);
        for chunk in &mut chunks {
            chunk.copy_from_slice(&self.next_u64().to_le_bytes());
        }
        let rest = chunks.into_remainder();
        if !rest.is_empty() {
            let tail = self.next_u64().to_le_bytes();
            rest.copy_from_slice(&tail[..rest.len()]);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for TestOnlyRng {}

/// `CaseKey` is deliberately opaque (no byte accessor — it's zeroized on
/// drop and never meant to be extracted in ordinary use), so vector
/// generation keeps the raw `TEST_ONLY` seed bytes alongside the `CaseKey`
/// built from them, rather than reaching into the type.
fn test_only_case_key_bytes(seed_byte: u8) -> [u8; 32] {
    [seed_byte; 32]
}

fn test_only_case_cid() -> Cid {
    Cid::new(CidCodec::DagCbor, Hash32::new([9u8; 32]))
}

fn test_only_author() -> String {
    "did:praxis:".to_string() + &"a".repeat(20)
}

pub fn generate() {
    crate::vector::clean_category("sealing");
    seal_unseal_roundtrip();
    reject_tampered_ciphertext();
    reject_tampered_commit();
    reject_wrong_case_key();
}

fn seal_unseal_roundtrip() {
    let ck_bytes = test_only_case_key_bytes(1);
    let ck = CaseKey::new(ck_bytes);
    let case = test_only_case_cid();
    let author = test_only_author();
    let content = Value::Text("wait 10m, matches nightly backup window".to_string());
    let mut rng = TestOnlyRng(42);

    let sealed = seal_body(&ck, "decision", 0, &case, &author, &content, &mut rng).unwrap();
    let revealed = unseal_body(&sealed, &ck, "decision", 0, &case, &author).unwrap();
    assert_eq!(revealed.plain, content);

    let sealed_bytes = praxis_types::encode_canonical(&sealed).unwrap();
    let plaintext_bucket_len = sealed.sealed.ct.len() - 16; // minus the Poly1305 tag
    assert!(PAD_BUCKETS.contains(&plaintext_bucket_len));

    write_vector(
        "sealing/seal-001-roundtrip",
        "PROTOCOL.md#8",
        "seal_body then unseal_body recovers the original content exactly; the \
         AEAD plaintext (padded PlainBody encoding) lands on one of the fixed \
         padding buckets regardless of the content's own length.",
        &json!({
            "case_key_hex": hex(&ck_bytes),
            "kind": "decision",
            "index_in_case": 0,
            "case_cid_bytes_hex": hex(&case.to_bytes()),
            "author": author,
            "sealed_body_dag_cbor_hex": hex(&sealed_bytes),
        }),
        &json!({
            "unseal_succeeds": true,
            "revealed_plain_dag_cbor_hex": hex(&praxis_types::encode_canonical(&revealed.plain).unwrap()),
            "plaintext_bucket_len": plaintext_bucket_len,
        }),
    );
}

fn reject_tampered_ciphertext() {
    let ck_bytes = test_only_case_key_bytes(2);
    let ck = CaseKey::new(ck_bytes);
    let case = test_only_case_cid();
    let author = test_only_author();
    let content = Value::Text("wait 10m".to_string());
    let mut rng = TestOnlyRng(7);

    let mut sealed = seal_body(&ck, "decision", 0, &case, &author, &content, &mut rng).unwrap();
    sealed.sealed.ct[0] ^= 0x01;
    let err = unseal_body(&sealed, &ck, "decision", 0, &case, &author).unwrap_err();
    assert!(matches!(err, SealError::Aead(_)));

    write_vector(
        "sealing/reject-001-tampered-ciphertext",
        "PROTOCOL.md#8.3",
        "A single-bit flip in the AEAD ciphertext fails authentication: AEAD's \
         own integrity check, not the commit, is what catches this.",
        &json!({
            "case_key_hex": hex(&ck_bytes),
            "kind": "decision",
            "index_in_case": 0,
            "case_cid_bytes_hex": hex(&case.to_bytes()),
            "author": author,
            "sealed_body_dag_cbor_hex": hex(&praxis_types::encode_canonical(&sealed).unwrap()),
        }),
        &expected_error(err.code()),
    );
}

fn reject_tampered_commit() {
    let ck_bytes = test_only_case_key_bytes(3);
    let ck = CaseKey::new(ck_bytes);
    let case = test_only_case_cid();
    let author = test_only_author();
    let content = Value::Text("wait 10m".to_string());
    let mut rng = TestOnlyRng(99);

    let mut sealed = seal_body(&ck, "decision", 0, &case, &author, &content, &mut rng).unwrap();
    // AEAD authentication still passes (commit isn't covered by the AEAD tag);
    // the explicit reveal-verify step must catch the substitution.
    let mut tampered = *sealed.commit.as_bytes();
    tampered[0] ^= 0x01;
    sealed.commit = Hash32::new(tampered);
    let err = unseal_body(&sealed, &ck, "decision", 0, &case, &author).unwrap_err();
    assert!(matches!(err, SealError::CommitMismatch));

    write_vector(
        "sealing/reject-002-tampered-commit",
        "PROTOCOL.md#8.2",
        "A commit substituted after sealing: AEAD decryption still succeeds \
         (commit is not part of the AEAD input), so the explicit \
         reveal-verify step is what must reject this ('anyone can verify').",
        &json!({
            "case_key_hex": hex(&ck_bytes),
            "kind": "decision",
            "index_in_case": 0,
            "case_cid_bytes_hex": hex(&case.to_bytes()),
            "author": author,
            "sealed_body_dag_cbor_hex": hex(&praxis_types::encode_canonical(&sealed).unwrap()),
        }),
        &expected_error(err.code()),
    );
}

fn reject_wrong_case_key() {
    let ck_bytes = test_only_case_key_bytes(4);
    let ck = CaseKey::new(ck_bytes);
    let wrong_ck_bytes = test_only_case_key_bytes(5);
    let wrong_ck = CaseKey::new(wrong_ck_bytes);
    let case = test_only_case_cid();
    let author = test_only_author();
    let content = Value::Text("wait 10m".to_string());
    let mut rng = TestOnlyRng(123);

    let sealed = seal_body(&ck, "decision", 0, &case, &author, &content, &mut rng).unwrap();
    let err = unseal_body(&sealed, &wrong_ck, "decision", 0, &case, &author).unwrap_err();
    assert!(matches!(err, SealError::Aead(_)));

    write_vector(
        "sealing/reject-003-wrong-case-key",
        "PROTOCOL.md#8.3",
        "Unsealing with any case key other than the one the body was sealed \
         under derives a different body key, which fails AEAD authentication.",
        &json!({
            "wrong_case_key_hex": hex(&wrong_ck_bytes),
            "kind": "decision",
            "index_in_case": 0,
            "case_cid_bytes_hex": hex(&case.to_bytes()),
            "author": author,
            "sealed_body_dag_cbor_hex": hex(&praxis_types::encode_canonical(&sealed).unwrap()),
        }),
        &expected_error(err.code()),
    );
}
