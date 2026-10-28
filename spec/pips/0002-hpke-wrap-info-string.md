# PIP-0002: Explicit HPKE `info` string for recipient key wrapping
- **Status:** Accepted
- **Author(s):** techwithgbenga
- **Created:** 2026-10-28
- **Spec version affected:** v0.1-draft

## Motivation
`spec/PROTOCOL.md` §8.4 says a `recipient`'s `wrapped` field is "the
HPKE-sealed body key (or CK) to the recipient's `enc_pub`" but does not state
what HPKE `info` (RFC 9180's application-supplied context string, bound into
the key schedule) or `aad` (per-seal associated data) to use. Implementing
`praxis-crypto`'s `wrap_key`/`unwrap_key` (M1-04) requires picking concrete
values — a sender and receiver that disagree here produce HPKE contexts that
silently fail to agree, which is exactly the kind of implicit choice
`AGENTS.md` §0.1 asks to resolve via a PIP.

## Specification
HPKE operations for recipient key wrapping (`spec/PROTOCOL.md` §8.4) use:

- **Mode:** `Base` (RFC 9180 §5.1.1) — the sender has no long-term identity
  key to authenticate with here; authorization comes from the practitioner's
  signed `grant` object, not from HPKE's `Auth`/`AuthPsk` modes.
- **`info`:** the fixed ASCII string `praxis/v1/wrap` (14 bytes), consistent
  with this suite's other domain-separation strings
  (`spec/PROTOCOL.md` §5.2, §8.2, §8.3).
- **`aad`:** empty (`""`). Nothing case-specific needs binding into the AEAD
  tag here: the wrapped plaintext (a body key or `CK`) is itself already
  scoped to one case by construction (`spec/PROTOCOL.md` §8.3), and the
  `recipient` struct carrying `wrapped` is itself inside a signed object.

## Backward compatibility
None: no implementation of §8.4 predates this PIP.

## Security & privacy impact
Fixing `info` to a constant does not weaken the construction: RFC 9180's
`info` is not required to be unique per message (unlike a nonce); its role is
domain/context separation between different *protocols* that might otherwise
reuse the same KEM keys, which a single fixed string already achieves here.

## Test vectors
`crates/praxis-crypto`'s unit tests verify `unwrap_key` against the official
RFC 9180 Appendix A.1.1 vector (base mode, `DHKEM(X25519, HKDF-SHA256)`,
`HKDF-SHA256`, `ChaCha20Poly1305`) for the underlying primitive, and a
round-trip test for `wrap_key`/`unwrap_key` with this PIP's fixed `info`.

## Reference implementation status
Implemented in `crates/praxis-crypto` (M1-04) per this PIP from the start.

## Open questions
None.
