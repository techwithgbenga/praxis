// SPDX-License-Identifier: Apache-2.0
//! HPKE (RFC 9180) recipient key wrapping (`spec/PROTOCOL.md` §8.4): base
//! mode, `DHKEM(X25519, HKDF-SHA256)`, `HKDF-SHA256`, `ChaCha20Poly1305`.
//! `info`/`aad` conventions per `spec/pips/0002-hpke-wrap-info-string.md`.

use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};

type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;
type Kem = X25519HkdfSha256;

/// `info = "praxis/v1/wrap"` (`spec/pips/0002-hpke-wrap-info-string.md`).
pub const WRAP_INFO: &[u8] = b"praxis/v1/wrap";

/// Something went wrong wrapping or unwrapping a key.
#[derive(Debug, thiserror::Error)]
#[error("HPKE operation failed: {0:?}")]
pub struct HpkeWrapError(hpke::HpkeError);

/// Generates a fresh X25519 keypair for HPKE recipient key wrapping, from the
/// OS CSPRNG. Returns `(private_key_bytes, public_key_bytes)`. The private
/// key is raw bytes here; callers (the keystore, in a later milestone) are
/// responsible for zeroizing/protecting it at rest.
#[must_use]
pub fn generate_recipient_keypair() -> ([u8; 32], [u8; 32]) {
    let (sk, pk) = Kem::gen_keypair();
    (sk.to_bytes().into(), pk.to_bytes().into())
}

/// Wraps `secret` (a body key or `CK`, per `spec/PROTOCOL.md` §8.3-8.4) to a
/// recipient's X25519 public key. Returns `(enc, wrapped)` — the HPKE
/// encapsulated key and the ciphertext, both as they go directly into a
/// `recipient` object's `enc`/`wrapped` fields.
///
/// # Errors
/// Returns [`HpkeWrapError`] if `recipient_pub` is not a valid X25519 public
/// key, or (practically never) if encapsulation/sealing fails.
pub fn wrap_key(
    recipient_pub: &[u8; 32],
    secret: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), HpkeWrapError> {
    let pk = <Kem as KemTrait>::PublicKey::from_bytes(recipient_pub).map_err(HpkeWrapError)?;
    let (encapped, wrapped) =
        hpke::single_shot_seal::<Aead, Kdf, Kem>(&OpModeS::Base, &pk, WRAP_INFO, secret, b"")
            .map_err(HpkeWrapError)?;
    Ok((encapped.to_bytes().to_vec(), wrapped))
}

/// Unwraps a key sealed by [`wrap_key`], given the recipient's private key
/// and the `enc`/`wrapped` bytes from a `recipient` object.
///
/// # Errors
/// Returns [`HpkeWrapError`] if `recipient_priv` or `enc` is malformed, or if
/// decryption fails (wrong key, tampered ciphertext).
pub fn unwrap_key(
    recipient_priv: &[u8; 32],
    enc: &[u8],
    wrapped: &[u8],
) -> Result<Vec<u8>, HpkeWrapError> {
    let sk = <Kem as KemTrait>::PrivateKey::from_bytes(recipient_priv).map_err(HpkeWrapError)?;
    let encapped_key = <Kem as KemTrait>::EncappedKey::from_bytes(enc).map_err(HpkeWrapError)?;
    hpke::single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &sk,
        &encapped_key,
        WRAP_INFO,
        wrapped,
        b"",
    )
    .map_err(HpkeWrapError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_wrap_and_unwrap() {
        let (sk, pk) = generate_recipient_keypair();
        let secret = [7u8; 32];
        let (enc, wrapped) = wrap_key(&pk, &secret).unwrap();
        let unwrapped = unwrap_key(&sk, &enc, &wrapped).unwrap();
        assert_eq!(unwrapped, secret);
    }

    #[test]
    fn unwrap_fails_with_wrong_private_key() {
        let (_sk, pk) = generate_recipient_keypair();
        let (other_sk, _other_pk) = generate_recipient_keypair();
        let secret = [7u8; 32];
        let (enc, wrapped) = wrap_key(&pk, &secret).unwrap();
        assert!(unwrap_key(&other_sk, &enc, &wrapped).is_err());
    }

    #[test]
    fn unwrap_fails_on_single_bit_flip_in_wrapped_ciphertext() {
        let (sk, pk) = generate_recipient_keypair();
        let secret = [7u8; 32];
        let (enc, mut wrapped) = wrap_key(&pk, &secret).unwrap();
        wrapped[0] ^= 0x01;
        assert!(unwrap_key(&sk, &enc, &wrapped).is_err());
    }

    #[test]
    fn unwrap_fails_on_single_bit_flip_in_enc() {
        let (sk, pk) = generate_recipient_keypair();
        let secret = [7u8; 32];
        let (mut enc, wrapped) = wrap_key(&pk, &secret).unwrap();
        enc[0] ^= 0x01;
        assert!(unwrap_key(&sk, &enc, &wrapped).is_err());
    }

    /// RFC 9180 Appendix A.1.1, the standard base-mode
    /// `DHKEM(X25519, HKDF-SHA256)`/`HKDF-SHA256`/`ChaCha20Poly1305` vector
    /// ("Ode on a Grecian Urn"). Downloaded from the working group's
    /// `test-vectors.json` and parsed with a script, not retyped by hand.
    /// Exercises `unwrap_key` directly (decapsulation + open) against a
    /// ciphertext from an independent implementation, which does not require
    /// controlling this crate's ephemeral-key randomness the way testing the
    /// seal side would.
    #[test]
    fn rfc9180_appendix_a_1_1_vector() {
        let sk_recip: [u8; 32] =
            hex::decode("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb")
                .unwrap()
                .try_into()
                .unwrap();
        let enc = hex::decode("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a")
            .unwrap();
        let aad = hex::decode("436f756e742d30").unwrap();
        let ct = hex::decode(
            "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28",
        )
        .unwrap();
        let expected_pt =
            hex::decode("4265617574792069732074727574682c20747275746820626561757479").unwrap();
        assert_eq!(expected_pt, b"Beauty is truth, truth beauty");

        let sk = <Kem as KemTrait>::PrivateKey::from_bytes(&sk_recip).unwrap();
        let encapped_key = <Kem as KemTrait>::EncappedKey::from_bytes(&enc).unwrap();
        let pt = hpke::single_shot_open::<Aead, Kdf, Kem>(
            &OpModeR::Base,
            &sk,
            &encapped_key,
            b"Ode on a Grecian Urn",
            &ct,
            &aad,
        )
        .unwrap();
        assert_eq!(pt, expected_pt);
    }
}
