// SPDX-License-Identifier: Apache-2.0
//! Praxis protocol cryptographic primitives: Ed25519 (strict, domain-separated)
//! signing/verification, HKDF-SHA256, XChaCha20-Poly1305 AEAD, and HPKE (RFC 9180)
//! key wrapping (`spec/PROTOCOL.md` §2, §8).
//!
//! Per `AGENTS.md` §0.2: only audited libraries named in `docs/TECH_STACK.md` are used
//! here. No primitive is implemented from scratch. Secrets are zeroized on drop and
//! comparisons are constant-time.
//!
//! M1-04/M1-05 fill this in.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

// OPEN(Q-008): hybrid post-quantum suite `pxs2` (ML-KEM/ML-DSA) lands here once
// audited crates exist; tracked in docs/EVALUATION.md §7 and gated at v1.0 (ADR per
// spec/PROTOCOL.md §2).
