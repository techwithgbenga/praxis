// SPDX-License-Identifier: Apache-2.0
//! XChaCha20-Poly1305 AEAD (`spec/PROTOCOL.md` §2, §8.3):
//! `ct = XChaCha20-Poly1305(key=bodykey, nonce, aad=kind||case||author, plaintext)`.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

use crate::kdf::BodyKey;

/// Decryption/authentication failed: wrong key, wrong nonce, wrong AAD, or a
/// tampered ciphertext. Deliberately carries no further detail (an oracle
/// distinguishing *why* AEAD decryption failed is itself a side channel).
#[derive(Debug, thiserror::Error)]
#[error("AEAD decryption failed")]
pub struct AeadError;

/// Builds `aad=kind||case||author` (`spec/PROTOCOL.md` §8.3, byte encodings
/// per `spec/pips/0001-sealing-byte-encoding.md`): `kind`'s UTF-8 bytes, the
/// `case` CID's raw multiformats binary encoding, then `author`'s UTF-8 bytes.
#[must_use]
pub fn build_aad(kind: &str, case: &praxis_types::Cid, author: &str) -> Vec<u8> {
    let case_bytes = case.to_bytes();
    let mut aad = Vec::with_capacity(kind.len() + case_bytes.len() + author.len());
    aad.extend_from_slice(kind.as_bytes());
    aad.extend_from_slice(&case_bytes);
    aad.extend_from_slice(author.as_bytes());
    aad
}

/// Seals `plaintext` under `key` with the given 24-byte nonce and associated
/// data, producing `ciphertext || tag` (`spec/PROTOCOL.md` §8.3).
///
/// # Panics
/// Never: `XChaCha20Poly1305::new` only fails for a wrong-length key (we
/// always pass exactly 32 bytes) and `encrypt` only fails if the plaintext
/// exceeds this AEAD's ~256 GiB limit, far above this protocol's 256 KiB
/// object size cap (`spec/PROTOCOL.md` §3.5).
#[must_use]
pub fn seal(key: &BodyKey, nonce: &[u8; 24], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    cipher
        .encrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("key is always 32 bytes and plaintext is always far below the AEAD size limit")
}

/// Opens `ciphertext` (`ciphertext || tag`, as produced by [`seal`]) under
/// `key` with the given nonce and associated data.
///
/// # Errors
/// Returns [`AeadError`] if authentication fails for any reason (wrong key,
/// nonce, AAD, or a tampered ciphertext/tag).
pub fn open(
    key: &BodyKey,
    nonce: &[u8; 24],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    cipher
        .decrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| AeadError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::CaseKey;

    fn test_key() -> BodyKey {
        crate::kdf::derive_body_key(&CaseKey::new([1u8; 32]), "decision", 0)
    }

    #[test]
    fn roundtrip_seal_and_open() {
        let key = test_key();
        let nonce = [2u8; 24];
        let aad = b"some aad";
        let ct = seal(&key, &nonce, aad, b"hello world");
        let pt = open(&key, &nonce, aad, &ct).unwrap();
        assert_eq!(pt, b"hello world");
    }

    #[test]
    fn open_fails_on_single_bit_flip_in_ciphertext() {
        let key = test_key();
        let nonce = [2u8; 24];
        let aad = b"some aad";
        let mut ct = seal(&key, &nonce, aad, b"hello world");
        ct[0] ^= 0x01;
        assert!(open(&key, &nonce, aad, &ct).is_err());
    }

    #[test]
    fn open_fails_on_single_bit_flip_in_tag() {
        let key = test_key();
        let nonce = [2u8; 24];
        let aad = b"some aad";
        let mut ct = seal(&key, &nonce, aad, b"hello world");
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(open(&key, &nonce, aad, &ct).is_err());
    }

    #[test]
    fn open_fails_with_wrong_aad() {
        let key = test_key();
        let nonce = [2u8; 24];
        let ct = seal(&key, &nonce, b"aad one", b"hello world");
        assert!(open(&key, &nonce, b"aad two", &ct).is_err());
    }

    #[test]
    fn open_fails_with_wrong_key() {
        let key = test_key();
        let other_key = crate::kdf::derive_body_key(&CaseKey::new([1u8; 32]), "decision", 1);
        let nonce = [2u8; 24];
        let ct = seal(&key, &nonce, b"aad", b"hello world");
        assert!(open(&other_key, &nonce, b"aad", &ct).is_err());
    }

    #[test]
    fn open_fails_with_wrong_nonce() {
        let key = test_key();
        let ct = seal(&key, &[2u8; 24], b"aad", b"hello world");
        assert!(open(&key, &[3u8; 24], b"aad", &ct).is_err());
    }

    /// draft-irtf-cfrg-xchacha-03 §A.3.1, the canonical developer-friendly
    /// `AEAD_XCHACHA20_POLY1305` test vector. Downloaded and parsed with a
    /// script, not retyped by hand.
    #[test]
    fn xchacha20_poly1305_test_vector() {
        let key: [u8; 32] =
            hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
                .unwrap()
                .try_into()
                .unwrap();
        let nonce: [u8; 24] = hex::decode("404142434445464748494a4b4c4d4e4f5051525354555657")
            .unwrap()
            .try_into()
            .unwrap();
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let plaintext = hex::decode(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617\
             373206f66202739393a204966204920636f756c64206f6666657220796f7520\
             6f6e6c79206f6e652074697020666f7220746865206675747572652c2073756\
             e73637265656e20776f756c642062652069742e",
        )
        .unwrap();
        let expected_ct = hex::decode(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cb\
             b731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b45\
             22f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3ff\
             f921f9664c97637da9768812f615c68b13b52e",
        )
        .unwrap();
        let expected_tag = hex::decode("c0875924c1c7987947deafd8780acf49").unwrap();
        assert_eq!(plaintext.len(), 114);
        assert_eq!(expected_ct.len(), 114);
        assert_eq!(expected_tag.len(), 16);

        let cipher = XChaCha20Poly1305::new((&key).into());
        let got = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(got[..114], expected_ct[..]);
        assert_eq!(got[114..], expected_tag[..]);
    }
}
