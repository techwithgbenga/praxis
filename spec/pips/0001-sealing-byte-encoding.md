# PIP-0001: Explicit byte encoding for §8.3's HKDF `info` and AEAD `aad`
- **Status:** Accepted
- **Author(s):** techwithgbenga
- **Created:** 2026-10-28
- **Spec version affected:** v0.1-draft

## Motivation
`spec/PROTOCOL.md` §8.3 defines the per-event body key as
`HKDF-SHA256(ikm=CK, salt="praxis/v1/bodykey", info=kind||0x00||u32(index_in_case))`
and the AEAD call as `XChaCha20-Poly1305(key=bodykey, nonce,
aad=kind||case||author, plaintext)`. Implementing this in `praxis-crypto`
(M1-04) surfaced that the prose leaves three byte-level choices unstated,
each of which changes the derived key/tag if two implementations guess
differently:

1. `u32(index_in_case)`'s endianness.
2. What bytes `kind` contributes (the CDDL string's UTF-8 bytes seems the
   only sensible reading, but it is nowhere stated).
3. What bytes `case` contributes: it is a CID, which has both a tag-42
   dag-cbor representation and a raw multiformats binary representation —
   these differ.

This is exactly the kind of ambiguity `AGENTS.md` §0.1 asks to resolve via a
PIP rather than let an implementation silently pick one. There is no existing
implementation to break (M1-04 is the first), so this is a pure
clarification, not a breaking change.

## Specification
Byte string concatenation (`||`) throughout §8.3 uses, left to right:

- `kind`: the UTF-8 bytes of the object's `kind` string exactly as it
  appears in `spec/praxis-v0.1.cddl` (e.g. `decision`, 8 bytes). Not
  length-prefixed.
- `u32(n)`: 4 bytes, **big-endian** (network byte order), matching the
  convention used throughout the IETF RFCs this suite otherwise depends on
  (RFC 5869, RFC 8032, RFC 9180).
- `case`: the raw multiformats binary encoding of the CID (version + codec
  varint + multihash varint-function-code + varint-length + digest) — the
  same bytes `ipld_core::cid::Cid::to_bytes()` (or equivalent) produces, with
  *no* CBOR tag-42 wrapper and no outer `bstr` length prefix.
- `author`: the UTF-8 bytes of the `did:praxis:...` string.
- `0x00`: one literal zero byte (unchanged from the existing prose).

`spec/PROTOCOL.md` §8.3 is amended to state this explicitly.

## Backward compatibility
None: no implementation of §8.3 predates this PIP.

## Security & privacy impact
None beyond making an already-intended construction unambiguous. Each
component's encoding is still unambiguous and self-delimiting given the
fixed structure (kind is always followed by exactly one `0x00` byte then
exactly 4 bytes; there is no parsing step that could be confused by, say, a
`kind` string containing a null byte, since none of the five defined `kind`
groups' string literals do).

## Test vectors
None yet; `crates/praxis-crypto`'s unit tests cover this construction
directly. Cross-language vectors land with M1-08/M1-09 once `praxis-validate`
exercises real sealed objects end to end.

## Reference implementation status
Implemented in `crates/praxis-crypto` (M1-04) per this PIP from the start.

## Open questions
None.
