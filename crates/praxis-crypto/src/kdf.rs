// SPDX-License-Identifier: Apache-2.0
//! HKDF-SHA256 key derivation (`spec/PROTOCOL.md` §8.3; byte encodings per
//! `spec/pips/0001-sealing-byte-encoding.md`): per-event body keys, derived
//! from a case's `CK` so that revealing one body key reveals only that event.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// `salt="praxis/v1/bodykey"` (`spec/PROTOCOL.md` §8.3).
pub const BODYKEY_SALT: &[u8] = b"praxis/v1/bodykey";

/// A case key `CK`: 32 random bytes, generated once per case
/// (`spec/PROTOCOL.md` §8.3). Zeroized on drop.
#[derive(Clone, ZeroizeOnDrop)]
pub struct CaseKey([u8; 32]);

impl CaseKey {
    /// Wraps raw bytes as a `CaseKey`. Callers generating a fresh `CK` should
    /// use a CSPRNG (e.g. `rand::rngs::OsRng`) and move the bytes in without
    /// copying where possible; this crate does not generate randomness
    /// itself, matching `AGENTS.md` §0.2 ("no custom ... RNG" — meaning no
    /// *bespoke* RNG; using the OS's own via an established crate at the call
    /// site, e.g. in `praxis-store`'s keystore, is the intended pattern).
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Debug for CaseKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaseKey").finish_non_exhaustive()
    }
}

/// A per-event body key, derived from a [`CaseKey`] (`spec/PROTOCOL.md` §8.3).
/// Zeroized on drop.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct BodyKey([u8; 32]);

impl BodyKey {
    /// The raw 32-byte key, for use as an AEAD key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for BodyKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BodyKey").finish_non_exhaustive()
    }
}

/// Derives the body key for event number `index_in_case` of kind `kind`
/// within a case keyed by `ck` (`spec/PROTOCOL.md` §8.3):
/// `HKDF-SHA256(ikm=CK, salt="praxis/v1/bodykey", info=kind||0x00||u32(index_in_case))`,
/// with `kind`'s UTF-8 bytes and a big-endian `u32` per PIP-0001.
///
/// # Panics
/// Never: 32 bytes is always a valid HKDF-SHA256 output length (the limit is
/// `255 * 32`).
#[must_use]
pub fn derive_body_key(ck: &CaseKey, kind: &str, index_in_case: u32) -> BodyKey {
    let mut info = Vec::with_capacity(kind.len() + 1 + 4);
    info.extend_from_slice(kind.as_bytes());
    info.push(0x00);
    info.extend_from_slice(&index_in_case.to_be_bytes());

    let hk = Hkdf::<Sha256>::new(Some(BODYKEY_SALT), &ck.0);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .expect("32 is a valid HKDF-SHA256 output length (max is 255*32)");
    info.zeroize();
    BodyKey(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_body_key_is_deterministic() {
        let ck = CaseKey::new([7u8; 32]);
        let a = derive_body_key(&ck, "decision", 0);
        let b = derive_body_key(&ck, "decision", 0);
        assert_eq!(a, b);
    }

    #[test]
    fn different_index_gives_a_different_key() {
        let ck = CaseKey::new([7u8; 32]);
        let a = derive_body_key(&ck, "decision", 0);
        let b = derive_body_key(&ck, "decision", 1);
        assert_ne!(a, b);
    }

    #[test]
    fn different_kind_gives_a_different_key() {
        let ck = CaseKey::new([7u8; 32]);
        let a = derive_body_key(&ck, "decision", 0);
        let b = derive_body_key(&ck, "claims", 0);
        assert_ne!(a, b);
    }

    #[test]
    fn different_case_key_gives_a_different_key() {
        let a = derive_body_key(&CaseKey::new([7u8; 32]), "decision", 0);
        let b = derive_body_key(&CaseKey::new([8u8; 32]), "decision", 0);
        assert_ne!(a, b);
    }

    /// Confirms the `info` byte layout directly: computing the same HKDF
    /// expand by hand (big-endian `u32`, single `0x00` separator) must match
    /// `derive_body_key`'s output, pinning PIP-0001's byte encoding against a
    /// regression rather than just trusting the implementation reads itself.
    #[test]
    fn info_byte_layout_matches_pip_0001() {
        let ck = CaseKey::new([9u8; 32]);
        let got = derive_body_key(&ck, "open", 0x0102_0304);

        let mut expected_info = Vec::new();
        expected_info.extend_from_slice(b"open");
        expected_info.push(0x00);
        expected_info.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // big-endian
        let hk = Hkdf::<Sha256>::new(Some(BODYKEY_SALT), &ck.0);
        let mut expected = [0u8; 32];
        hk.expand(&expected_info, &mut expected).unwrap();

        assert_eq!(got.as_bytes(), &expected);
    }

    /// RFC 5869 Appendix A.1 (HKDF-SHA256, extract-then-expand), checking our
    /// use of the underlying `hkdf` crate against an independent vector, not
    /// `derive_body_key`'s own specific construction.
    #[test]
    fn rfc5869_test_case_1() {
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let expected_okm = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )
        .unwrap();
        assert_eq!(expected_okm.len(), 42);

        let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut okm = vec![0u8; 42];
        hk.expand(&info, &mut okm).unwrap();
        assert_eq!(okm, expected_okm);
    }
}
