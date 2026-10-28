// SPDX-License-Identifier: Apache-2.0
//! Ed25519 signing and verification, with the domain-separation prefix from
//! `spec/PROTOCOL.md` §5.2 baked in.
//!
//! `sig = Ed25519.sign(signer_secret, "praxis/v1/object\x00" || canonical_bytes(object_without_sig))`

use ed25519_dalek::ed25519::signature::Signer as _;
use ed25519_dalek::{Signature, SigningKey, Verifier as _, VerifyingKey};
use rand::rngs::OsRng;
use zeroize::ZeroizeOnDrop;

/// The domain-separation prefix for object signatures (`spec/PROTOCOL.md` §5.2).
pub const OBJECT_SIGN_DOMAIN: &[u8] = b"praxis/v1/object\0";

/// Something went wrong signing or verifying.
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    /// Signature verification failed: wrong key, tampered message, or corrupt signature.
    #[error("signature verification failed")]
    InvalidSignature,
    /// A public or secret key was not exactly 32 bytes.
    #[error("key must be exactly 32 bytes, got {0}")]
    InvalidKeyLength(usize),
}

/// An Ed25519 secret signing key. Zeroized on drop; never implements `Debug`
/// or `Clone` with a visible value (see [`std::fmt::Debug`] impl below).
#[derive(ZeroizeOnDrop)]
pub struct SecretKey(SigningKey);

impl SecretKey {
    /// Generates a new secret key from the OS CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        Self(SigningKey::generate(&mut OsRng))
    }

    /// Reconstructs a secret key from its raw 32-byte seed (RFC 8032). Used
    /// for deterministic test vectors and for loading a key back out of a
    /// keystore; callers are responsible for that byte slice's own zeroing.
    ///
    /// # Errors
    /// Returns [`SignError::InvalidKeyLength`] if `bytes` is not 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignError> {
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| SignError::InvalidKeyLength(bytes.len()))?;
        Ok(Self(SigningKey::from_bytes(&seed)))
    }

    /// The corresponding public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }

    /// Signs `message` directly, with **no** domain separation applied. Most
    /// callers want [`sign_object`], not this.
    #[must_use]
    pub fn sign_raw(&self, message: &[u8]) -> [u8; 64] {
        self.0.sign(message).to_bytes()
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretKey")
            .field("public_key", &self.public_key())
            .finish_non_exhaustive()
    }
}

/// An Ed25519 public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(VerifyingKey);

impl PublicKey {
    /// Reconstructs a public key from its raw 32 bytes.
    ///
    /// # Errors
    /// Returns [`SignError::InvalidKeyLength`] or, if the 32 bytes are not a
    /// valid compressed Edwards point, [`SignError::InvalidSignature`] — the
    /// closest existing variant; a dedicated `InvalidKey` is not worth adding
    /// for this one call site.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignError> {
        let raw: [u8; 32] = bytes
            .try_into()
            .map_err(|_| SignError::InvalidKeyLength(bytes.len()))?;
        VerifyingKey::from_bytes(&raw)
            .map(Self)
            .map_err(|_| SignError::InvalidSignature)
    }

    /// The raw 32-byte public key.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Verifies `signature` over `message` directly, with **no** domain
    /// separation applied. Most callers want [`verify_object`], not this.
    ///
    /// # Errors
    /// Returns [`SignError::InvalidSignature`] if verification fails.
    pub fn verify_raw(&self, message: &[u8], signature: &[u8; 64]) -> Result<(), SignError> {
        let sig = Signature::from_bytes(signature);
        self.0
            .verify(message, &sig)
            .map_err(|_| SignError::InvalidSignature)
    }
}

/// Signs `canonical_bytes_without_sig` as a Praxis object (`spec/PROTOCOL.md`
/// §5.2): applies the `"praxis/v1/object\x00"` domain-separation prefix before
/// signing. `canonical_bytes_without_sig` must be the object's canonical
/// dag-cbor encoding with the `sig` field absent (`praxis-types::encode_object`
/// operates on the whole `Object`; producing the sig-less variant is the
/// caller's job, typically `praxis-validate`/`praxis-core`).
#[must_use]
pub fn sign_object(key: &SecretKey, canonical_bytes_without_sig: &[u8]) -> [u8; 64] {
    let mut message =
        Vec::with_capacity(OBJECT_SIGN_DOMAIN.len() + canonical_bytes_without_sig.len());
    message.extend_from_slice(OBJECT_SIGN_DOMAIN);
    message.extend_from_slice(canonical_bytes_without_sig);
    key.sign_raw(&message)
}

/// Verifies an object signature per `spec/PROTOCOL.md` §5.2 (see [`sign_object`]).
///
/// # Errors
/// Returns [`SignError::InvalidSignature`] if verification fails.
pub fn verify_object(
    key: &PublicKey,
    canonical_bytes_without_sig: &[u8],
    signature: &[u8; 64],
) -> Result<(), SignError> {
    let mut message =
        Vec::with_capacity(OBJECT_SIGN_DOMAIN.len() + canonical_bytes_without_sig.len());
    message.extend_from_slice(OBJECT_SIGN_DOMAIN);
    message.extend_from_slice(canonical_bytes_without_sig);
    key.verify_raw(&message, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_sign_and_verify_object() {
        let key = SecretKey::generate();
        let pubkey = key.public_key();
        let sig = sign_object(&key, b"canonical bytes here");
        assert!(verify_object(&pubkey, b"canonical bytes here", &sig).is_ok());
    }

    #[test]
    fn verification_fails_on_single_bit_flip_in_message() {
        let key = SecretKey::generate();
        let pubkey = key.public_key();
        let sig = sign_object(&key, b"canonical bytes here");
        let mut tampered = *b"canonical bytes here";
        tampered[0] ^= 0x01;
        assert!(verify_object(&pubkey, &tampered, &sig).is_err());
    }

    #[test]
    fn verification_fails_on_single_bit_flip_in_signature() {
        let key = SecretKey::generate();
        let pubkey = key.public_key();
        let mut sig = sign_object(&key, b"canonical bytes here");
        sig[0] ^= 0x01;
        assert!(verify_object(&pubkey, b"canonical bytes here", &sig).is_err());
    }

    #[test]
    fn verification_fails_with_the_wrong_key() {
        let key = SecretKey::generate();
        let other = SecretKey::generate();
        let sig = sign_object(&key, b"canonical bytes here");
        assert!(verify_object(&other.public_key(), b"canonical bytes here", &sig).is_err());
    }

    #[test]
    fn domain_separation_means_object_sig_differs_from_raw_sig() {
        let key = SecretKey::generate();
        let object_sig = sign_object(&key, b"message");
        let raw_sig = key.sign_raw(b"message");
        assert_ne!(object_sig, raw_sig);
    }

    /// RFC 8032 §7.1 test vector 1 (the empty-message case).
    #[test]
    fn rfc8032_test_vector_1() {
        let secret_seed =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let expected_pubkey =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .unwrap();
        let message = hex::decode("").unwrap();
        let expected_sig = hex::decode(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        )
        .unwrap();

        let key = SecretKey::from_bytes(&secret_seed).unwrap();
        assert_eq!(
            key.public_key().to_bytes().as_slice(),
            expected_pubkey.as_slice()
        );

        let sig = key.sign_raw(&message);
        assert_eq!(sig.as_slice(), expected_sig.as_slice());

        key.public_key().verify_raw(&message, &sig).unwrap();
    }
}
