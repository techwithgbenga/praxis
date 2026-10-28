// SPDX-License-Identifier: Apache-2.0
//! The sealed-body commitment scheme (`spec/PROTOCOL.md` §8.2):
//! `commit = BLAKE3("praxis/v1/commit\x00" || plaintext_bytes)`, binding a
//! sealed body to its plaintext so a practitioner cannot later reveal a
//! substituted body.

use praxis_types::Hash32;

/// The domain-separation prefix for sealed-body commitments (`spec/PROTOCOL.md` §8.2).
pub const COMMIT_DOMAIN: &[u8] = b"praxis/v1/commit\0";

/// Computes the `commit` value for some sealed body's plaintext bytes
/// (the canonical encoding of `{content, salt}`, per `spec/PROTOCOL.md` §8.2 —
/// assembling that encoding is the caller's job, typically `praxis-core`).
#[must_use]
pub fn compute_commit(plaintext_bytes: &[u8]) -> Hash32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(COMMIT_DOMAIN);
    hasher.update(plaintext_bytes);
    Hash32::new(*hasher.finalize().as_bytes())
}

/// Verifies that `plaintext_bytes` matches a previously computed `commit`,
/// in constant time (the whole point of a commitment is that this check
/// cannot be timing-leaked into "how many leading bytes matched").
#[must_use]
pub fn verify_commit(commit: &Hash32, plaintext_bytes: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    compute_commit(plaintext_bytes)
        .as_bytes()
        .ct_eq(commit.as_bytes())
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_commit_accepts_matching_plaintext() {
        let commit = compute_commit(b"the plaintext");
        assert!(verify_commit(&commit, b"the plaintext"));
    }

    #[test]
    fn verify_commit_rejects_a_single_bit_flip() {
        let commit = compute_commit(b"the plaintext");
        assert!(!verify_commit(&commit, b"the plaintextx"));
        assert!(!verify_commit(&commit, b"the Plaintext"));
    }

    #[test]
    fn commit_is_deterministic() {
        assert_eq!(
            compute_commit(b"x").as_bytes(),
            compute_commit(b"x").as_bytes()
        );
    }

    #[test]
    fn domain_separation_means_commit_differs_from_plain_blake3() {
        let commit = compute_commit(b"message");
        let plain = blake3::hash(b"message");
        assert_ne!(commit.as_bytes(), plain.as_bytes());
    }
}
