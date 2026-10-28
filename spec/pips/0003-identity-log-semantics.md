# PIP-0003: Identity log semantics — DID derivation, signing authority, rotation
- **Status:** Accepted
- **Author(s):** techwithgbenga
- **Created:** 2026-10-28
- **Spec version affected:** v0.1-draft

## Motivation
Implementing `praxis-identity` (M1-06) surfaced three places `spec/PROTOCOL.md`
§4 describes the identity log's *shape* but not precisely enough to build a
second, interoperable implementation of its *behavior*:

1. **DID string format.** §4.1 says the DID is
   `did:praxis:<base32lower(CID of the id-genesis object)>` but doesn't say
   whether that means the CID's standard multibase string form (which, for a
   base32-lower multibase, already starts with the prefix character `b`) or
   the base32 encoding of the CID's raw bytes with that prefix stripped.
2. **Who may sign `id-delegate` / `id-revoke`.** §4.3 explicitly requires
   `id-rotate` to be signed by the current root key or a recovery key, but
   says nothing about who may sign `id-delegate` or `id-revoke`. Read
   literally, §4.4's general rule ("valid if the signer key was authorized at
   the object's `ts`") would let *any* currently-valid device key delegate
   new device keys or revoke other keys — a privilege-escalation hole: a
   single compromised device key could mint persistent new keys or revoke
   the legitimate ones.
3. **Does `id-rotate` implicitly end the old root key's validity?** §4.3 says
   rotation "replaces the root key" but the CDDL gives rotate the same
   `? keys: [+ key-entry]` shape as genesis/delegate — introducing a new key,
   not referencing or invalidating the old one. Left unstated, an
   implementation could plausibly keep the old root key valid forever
   alongside the new one, which is not what "replaces" should mean.

## Specification

1. **DID format:** `did:praxis:<cid>`, where `<cid>` is the id-genesis
   object's CID rendered in its standard CIDv1 string form (multibase
   base32-lower, i.e. what `ipld_core::cid::Cid::to_string()` / the `cid`
   crate's `Display` impl produce — e.g. `bafyr4ig...`). Verified empirically
   to be 59 ASCII characters for a `dag-cbor`/BLAKE3-256 CID, entirely within
   `[a-z2-7]` — comfortably inside the CDDL `did` pattern's `{20,100}` bound
   with no further encoding or stripping needed.
2. **Signing authority**, extending §4.3's existing rule for `id-rotate`:
   - `id-genesis` MUST be signed by a key listed in its own `keys`, with
     `role: root` (bootstrapping: there is no prior log to check against).
   - `id-rotate` MUST be signed by the current root key or a current
     recovery key (restated from §4.3, unchanged).
   - `id-delegate` MUST be signed by the current root key or a current
     recovery key.
   - `id-revoke` MUST be signed by the current root key or a current
     recovery key, **or** by the key named in `revoke.kid` itself
     (self-revocation — e.g. a device logging itself out). No other key may
     sign any of these three operations.
3. **Rotation retires the old root key:** when an `id-rotate` object is
   successfully applied, the key-entry that was root *immediately before*
   this rotation has its effective validity end at the rotate object's `ts`
   (as if revoked with `effective = ts`, no `compromised_since`) — for
   every purpose, not merely "no longer root". It is not demoted to
   `device`; if the practitioner wants to keep using that key pair for
   anything, a later `id-delegate` introduces a fresh key-entry for it.

## Backward compatibility
None: no implementation of §4 predates this PIP.

## Security & privacy impact
(2) closes a real privilege-escalation gap (see Motivation). (3) matches the
ordinary expectation of key rotation (the old key stops being trusted) and
removes an easy-to-miss step (a separate explicit revoke) that a careless
implementation could forget, leaving a rotated-away key silently still valid.

## Test vectors
`crates/praxis-identity`'s scenario tests (M1-06) cover genesis, rotation
(confirming the old root key is rejected for anything dated after the
rotation), an unauthorized delegate/revoke attempt (rejected), and
self-revocation.

## Reference implementation status
Implemented in `crates/praxis-identity` (M1-06) per this PIP from the start.

## Open questions
None.
