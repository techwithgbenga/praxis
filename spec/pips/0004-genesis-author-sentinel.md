# PIP-0004: `id-genesis`'s `author` field is a fixed sentinel, not the derived DID
- **Status:** Accepted
- **Author(s):** techwithgbenga
- **Created:** 2026-10-28
- **Spec version affected:** v0.1-draft

## Motivation
`spec/praxis-v0.1.cddl`'s comment on `object.author` for `id-genesis` says
"self-referential; see PROTOCOL §4.1", and §4.1 says the identity's DID is
`did:praxis:<base32lower(CID of the id-genesis object)>`. Taken together,
the obvious reading — "the `author` field of the genesis object equals the
DID it establishes" — is circular and unsatisfiable: computing the object's
CID requires its signature (`spec/PROTOCOL.md` §5.1, "CID of the entire
canonical encoding, *including* `sig`"); the signature covers the canonical
bytes of the object *including* the `author` field (§5.2); so `author` must
be fixed before the CID exists, and the CID cannot be known in time to put
it in `author`. There is no iterative/grinding resolution either: nothing
about `author`'s value feeds back into what CID would eventually result in a
way that could converge.

## Specification
For `id-genesis` objects only, `author` is set to the fixed, non-cryptographic
sentinel value:

```
did:praxis:selfselfselfselfself
```

(`"self"` repeated 5 times — 20 characters, satisfying the `did` pattern's
`[a-z2-7]{20,100}` bound with no digits needed, and chosen to be immediately
recognizable as a placeholder rather than a real identity.)

Implementations and validators MUST NOT treat this value as identifying any
real practitioner. The identity's one true, stable DID is always
`did:praxis:<cid>` per §4.1, computed from the genesis object's own CID
*after* it has been signed. Every object *other than* the genesis event
itself uses that real, derived DID in its `author` field (there is no
bootstrapping problem there: by the time a second object is created, the
genesis object's CID is already known).

## Backward compatibility
None: no implementation of §4.1/§4.2 predates this PIP.

## Security & privacy impact
None: the sentinel is never used as a basis for authorization decisions
(`praxis-identity`'s `IdentityLog::genesis` derives the real DID from the
object's CID and never reads the literal `author` field for genesis checks).
It is purely a shape-filler for a CDDL-required field in the one object kind
where circularity makes the "real" value unknowable in time.

## Test vectors
`crates/praxis-identity`'s genesis scenario tests use this sentinel directly.

## Reference implementation status
Implemented in `crates/praxis-identity` (M1-06) per this PIP from the start.

## Open questions
None.
