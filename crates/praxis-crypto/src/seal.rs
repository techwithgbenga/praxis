// SPDX-License-Identifier: Apache-2.0
//! Sealing a case event's body end to end (`spec/PROTOCOL.md` §8): padding to
//! a size bucket (§8.5), the commit (§8.2), the key hierarchy (§8.3), and the
//! AEAD (§8.3) — composed from the primitives in [`crate::kdf`],
//! [`crate::aead`], and [`crate::commit`].

use praxis_types::{Cid, CodecError, PlainBody, SealAlg, SealedBody, SealedPayload, Value};
use rand::{CryptoRng, RngCore};

use crate::aead::{build_aad, open, seal, AeadError};
use crate::commit::{compute_commit, verify_commit};
use crate::kdf::{derive_body_key, CaseKey};

/// `spec/PROTOCOL.md` §8.5: padding buckets, smallest to largest.
pub const PAD_BUCKETS: [usize; 5] = [1024, 4096, 16384, 65536, 262_144];

/// The minimum possible size added by including a non-absent `pad` field at
/// all: the CBOR key `"pad"` (4 bytes: a 1-byte text-string header for a
/// 3-byte string, plus the 3 bytes) plus the shortest possible `bstr` header
/// (1 byte, for a 0-23 byte string). A bucket within this many bytes of the
/// unpadded size (but not equal to it) is unreachable; see
/// [`choose_target_bucket`].
const MIN_PAD_FIELD_OVERHEAD: usize = 5;

/// Everything that can go wrong sealing or unsealing a body.
#[derive(Debug, thiserror::Error)]
pub enum SealError {
    /// The unpadded plaintext is already larger than the largest padding
    /// bucket (`spec/PROTOCOL.md` §8.5); it belongs in a blob (§8.6) instead.
    #[error("content is too large to pad into any bucket (largest is {0} bytes)")]
    TooLargeToPad(usize),
    /// Canonical encoding/decoding of the inner `{content, salt, pad}`
    /// structure failed.
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// AEAD seal/open failed.
    #[error(transparent)]
    Aead(#[from] AeadError),
    /// The decrypted plaintext does not match the sealed body's `commit`
    /// (`spec/PROTOCOL.md` §8.2) — it was tampered with, or something has
    /// gone very wrong, since AEAD authentication already passed.
    #[error("decrypted plaintext does not match the sealed body's commit")]
    CommitMismatch,
    /// Internal: the padding search did not converge. Indicates a bug in
    /// this module, not bad input (input size is checked against
    /// [`PAD_BUCKETS`] before the search starts).
    #[error("internal error: padding search did not converge")]
    PaddingDidNotConverge,
}

/// Picks the smallest bucket the unpadded plaintext can be padded into
/// exactly: either no padding is needed (`bucket == unpadded_len`), or there
/// must be room for at least [`MIN_PAD_FIELD_OVERHEAD`] bytes once the `pad`
/// field itself is added. Skips any bucket too close above `unpadded_len` to
/// satisfy that (astronomically unlikely to ever matter given the bucket
/// sizes, but wrong to silently ignore).
fn choose_target_bucket(unpadded_len: usize) -> Option<usize> {
    PAD_BUCKETS.into_iter().find(|&bucket| {
        bucket >= unpadded_len
            && (bucket == unpadded_len || bucket - unpadded_len >= MIN_PAD_FIELD_OVERHEAD)
    })
}

/// Builds the canonical `{plain, salt, pad}` bytes (`spec/PROTOCOL.md` §8.2),
/// with `pad` sized so the total is exactly `target` bytes. Converges by
/// re-encoding: the `pad` field's own CBOR length-prefix width only grows at
/// a few fixed thresholds, so a handful of correction rounds always suffice.
fn build_padded_plaintext(
    content: &Value,
    salt: [u8; 16],
    target: usize,
) -> Result<Vec<u8>, SealError> {
    let mut pad_len = 0usize;
    for _ in 0..16 {
        let body = PlainBody {
            plain: content.clone(),
            salt,
            pad: if pad_len == 0 {
                None
            } else {
                Some(vec![0u8; pad_len])
            },
        };
        let bytes = praxis_types::encode_canonical(&body)?;
        let len = bytes.len();
        match len.cmp(&target) {
            std::cmp::Ordering::Equal => return Ok(bytes),
            std::cmp::Ordering::Less => pad_len += target - len,
            std::cmp::Ordering::Greater => pad_len = pad_len.saturating_sub(len - target),
        }
    }
    Err(SealError::PaddingDidNotConverge)
}

/// Seals one case event's content: pads to a bucket (§8.5), computes the
/// commit (§8.2), derives the body key (§8.3), and AEAD-encrypts
/// (§8.3) — producing a [`SealedBody`] ready to put in an object's `body` field.
///
/// `rng` supplies the salt and AEAD nonce; it must be a CSPRNG (e.g.
/// `rand::rngs::OsRng`).
///
/// # Errors
/// Returns [`SealError::TooLargeToPad`] if `content`'s canonical encoding
/// (plus the 16-byte salt) already exceeds the largest padding bucket — such
/// content belongs in a blob (`spec/PROTOCOL.md` §8.6), not a body. See
/// [`SealError`] for the (practically unreachable) other cases.
///
/// # Panics
/// Never: [`PAD_BUCKETS`] is a fixed non-empty array, so `.last()` on it always succeeds.
pub fn seal_body(
    ck: &CaseKey,
    kind: &str,
    index_in_case: u32,
    case: &Cid,
    author: &str,
    content: &Value,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<SealedBody, SealError> {
    let mut salt = [0u8; 16];
    rng.fill_bytes(&mut salt);

    let unpadded = praxis_types::encode_canonical(&PlainBody {
        plain: content.clone(),
        salt,
        pad: None,
    })?;
    let target = choose_target_bucket(unpadded.len()).ok_or(SealError::TooLargeToPad(
        *PAD_BUCKETS.last().expect("non-empty"),
    ))?;
    let plaintext = build_padded_plaintext(content, salt, target)?;

    let commit = compute_commit(&plaintext);
    let body_key = derive_body_key(ck, kind, index_in_case);
    let mut nonce = [0u8; 24];
    rng.fill_bytes(&mut nonce);
    let aad = build_aad(kind, case, author);
    let ct = seal(&body_key, &nonce, &aad, &plaintext);

    Ok(SealedBody {
        sealed: SealedPayload {
            alg: SealAlg::Xc20p,
            nonce,
            ct,
        },
        commit,
        rcpt: None,
    })
}

/// Unseals a [`SealedBody`]: derives the body key (§8.3), AEAD-decrypts,
/// verifies the decrypted plaintext against `commit` (§8.2 — "reveal
/// verify"), then decodes it back to the content and salt. Discards `pad`
/// (`spec/PROTOCOL.md` §8.5: padding has no meaning past this point).
///
/// # Errors
/// Returns [`SealError::Aead`] if decryption fails (wrong key, tampered
/// ciphertext), or [`SealError::CommitMismatch`] if the decrypted plaintext
/// does not hash to `commit` (should be impossible once AEAD authentication
/// has already passed, since both cover the same bytes under a key derived
/// from the same `CK` — a mismatch here means a logic bug, not an attack
/// AEAD didn't already catch, but the check is still made explicitly, per
/// `spec/PROTOCOL.md` §8.2's "anyone can verify").
pub fn unseal_body(
    sealed: &SealedBody,
    ck: &CaseKey,
    kind: &str,
    index_in_case: u32,
    case: &Cid,
    author: &str,
) -> Result<PlainBody, SealError> {
    let body_key = derive_body_key(ck, kind, index_in_case);
    let aad = build_aad(kind, case, author);
    let plaintext = open(&body_key, &sealed.sealed.nonce, &aad, &sealed.sealed.ct)?;
    if !verify_commit(&sealed.commit, &plaintext) {
        return Err(SealError::CommitMismatch);
    }
    Ok(praxis_types::decode_canonical(&plaintext)?)
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;

    use super::*;

    fn test_case_and_author() -> (CaseKey, Cid, String) {
        let ck = CaseKey::new([5u8; 32]);
        let case = Cid::from_canonical_bytes(praxis_types::CidCodec::DagCbor, b"case-bytes");
        let author = "did:praxis:".to_string() + &"a".repeat(20);
        (ck, case, author)
    }

    #[test]
    fn roundtrip_seal_and_unseal() {
        let (ck, case, author) = test_case_and_author();
        let content = Value::Text("wait 10m".to_string());
        let sealed = seal_body(&ck, "decision", 0, &case, &author, &content, &mut OsRng).unwrap();
        let revealed = unseal_body(&sealed, &ck, "decision", 0, &case, &author).unwrap();
        assert_eq!(revealed.plain, content);
    }

    #[test]
    fn unseal_fails_with_wrong_case_key() {
        let (ck, case, author) = test_case_and_author();
        let other_ck = CaseKey::new([6u8; 32]);
        let content = Value::Text("wait 10m".to_string());
        let sealed = seal_body(&ck, "decision", 0, &case, &author, &content, &mut OsRng).unwrap();
        assert!(unseal_body(&sealed, &other_ck, "decision", 0, &case, &author).is_err());
    }

    #[test]
    fn unseal_fails_on_single_bit_flip_in_ciphertext() {
        let (ck, case, author) = test_case_and_author();
        let content = Value::Text("wait 10m".to_string());
        let mut sealed =
            seal_body(&ck, "decision", 0, &case, &author, &content, &mut OsRng).unwrap();
        sealed.sealed.ct[0] ^= 0x01;
        assert!(unseal_body(&sealed, &ck, "decision", 0, &case, &author).is_err());
    }

    #[test]
    fn unseal_fails_if_commit_was_tampered_after_the_fact() {
        let (ck, case, author) = test_case_and_author();
        let content = Value::Text("wait 10m".to_string());
        let mut sealed =
            seal_body(&ck, "decision", 0, &case, &author, &content, &mut OsRng).unwrap();
        // Simulate someone substituting a different commit post hoc: AEAD still
        // opens fine (commit isn't part of the AEAD input), but the reveal-verify
        // step must catch the mismatch.
        let bytes = sealed.commit.as_bytes().to_vec();
        let mut tampered = [0u8; 32];
        tampered.copy_from_slice(&bytes);
        tampered[0] ^= 0x01;
        sealed.commit = praxis_types::Hash32::new(tampered);
        assert!(matches!(
            unseal_body(&sealed, &ck, "decision", 0, &case, &author),
            Err(SealError::CommitMismatch)
        ));
    }

    #[test]
    fn sealed_ciphertext_length_lands_on_a_padding_bucket() {
        let (ck, case, author) = test_case_and_author();
        for content_len in [0usize, 10, 100, 1000, 5000] {
            let content = Value::Text("x".repeat(content_len));
            let sealed = seal_body(&ck, "open", 0, &case, &author, &content, &mut OsRng).unwrap();
            // ct = plaintext + 16-byte Poly1305 tag, so the plaintext (padded
            // PlainBody encoding) length is ct.len() - 16; that must be exactly
            // one of the buckets.
            let plaintext_len = sealed.sealed.ct.len() - 16;
            assert!(
                PAD_BUCKETS.contains(&plaintext_len),
                "content_len={content_len}: plaintext_len={plaintext_len} is not a padding bucket"
            );
        }
    }

    #[test]
    fn same_bucket_regardless_of_content_within_it() {
        let (ck, case, author) = test_case_and_author();
        let small = seal_body(
            &ck,
            "open",
            0,
            &case,
            &author,
            &Value::Text("a".repeat(5)),
            &mut OsRng,
        )
        .unwrap();
        let bigger = seal_body(
            &ck,
            "open",
            0,
            &case,
            &author,
            &Value::Text("a".repeat(500)),
            &mut OsRng,
        )
        .unwrap();
        assert_eq!(small.sealed.ct.len(), bigger.sealed.ct.len());
        assert_eq!(small.sealed.ct.len() - 16, PAD_BUCKETS[0]);
    }

    #[test]
    fn rejects_content_larger_than_the_biggest_bucket() {
        let (ck, case, author) = test_case_and_author();
        let content = Value::Text("x".repeat(*PAD_BUCKETS.last().unwrap()));
        assert!(matches!(
            seal_body(&ck, "open", 0, &case, &author, &content, &mut OsRng),
            Err(SealError::TooLargeToPad(_))
        ));
    }

    #[test]
    fn choose_target_bucket_matches_exactly_at_boundaries() {
        assert_eq!(choose_target_bucket(0), Some(PAD_BUCKETS[0]));
        assert_eq!(choose_target_bucket(PAD_BUCKETS[0]), Some(PAD_BUCKETS[0]));
        assert_eq!(
            choose_target_bucket(PAD_BUCKETS[0] + 1),
            Some(PAD_BUCKETS[1])
        );
        assert_eq!(choose_target_bucket(*PAD_BUCKETS.last().unwrap() + 1), None);
    }
}
