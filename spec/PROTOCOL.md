# Praxis Protocol: Specification v0.1-draft

*Status: Draft. Normative. License: CC-BY-4.0.*
The key words MUST, MUST NOT, SHOULD, MAY are used as in RFC 2119/8174.
Schemas are in [`praxis-v0.1.cddl`](praxis-v0.1.cddl). If prose and CDDL disagree, **test vectors win**, then CDDL, then prose; file a bug.

---

## 1. Design overview

Praxis is a **set of immutable, signed, content-addressed objects**. There are *no mutable pointers*:
replication is set reconciliation, history is a DAG, and "current state" is always a pure function of the object set.

Object families (all share one envelope, §5):

| Family | Kinds | Purpose |
|---|---|---|
| **Identity** | `id-genesis`, `id-rotate`, `id-delegate`, `id-revoke` | Long-lived practitioner identity and device keys |
| **Case events** | `open`, `prediction`, `decision`, `claims`, `elicitation`, `outcome`, `amend`, `retract`, `abandon` | One decision's lifecycle |
| **Lineage** | `grant`, `derive`, `diverge`, `canon` | Who learned from whom; curated sets |
| **Attestation** | `anchor`, `attest` | Time anchoring; signed aggregate statements (e.g. calibration) |

**Why `claims` is separate from `decision`:** calibration only needs claims and outcomes. Splitting them lets a practitioner prove their track record (selective disclosure, §9) **without revealing what they decided or why**.

## 2. Primitives (cipher suite `pxs1`)

| Purpose | Primitive | Reference |
|---|---|---|
| Hash / content address | BLAKE3-256 | BLAKE3 spec |
| Link format | CIDv1; events: codec `dag-cbor` (0x71), blobs: `raw` (0x55); multihash `blake3` (0x1e), 32 bytes | multiformats |
| Signatures | Ed25519 (RFC 8032, pure, deterministic) | |
| AEAD | XChaCha20-Poly1305 (24-byte nonce) | draft-irtf-cfrg-xchacha |
| KDF | HKDF-SHA256 (RFC 5869) | |
| Key encapsulation (recipient wrapping) | HPKE (RFC 9180) base mode: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305 | |
| Encoding | dag-cbor (deterministic CBOR; RFC 8949 §4.2 + IPLD restrictions) | |
| Text | UTF-8, NFC-normalized | |

**Suite agility:** every object carries `suite`. v0.1 defines only `pxs1`. Suite IDs `pxs2`+ are *reserved* for hybrid post-quantum (Ed25519+ML-DSA signatures; X25519+ML-KEM-768 KEM). Because Praxis is a long-lived archive, **hybrid KEM is a v1.0 gate** (harvest-now-decrypt-later risk applies to sealed bodies).

Implementations MUST use audited libraries; see `docs/TECH_STACK.md`. Implementations MUST NOT implement primitives themselves.

## 3. Canonical encoding

3.1 All signed/hashed objects are encoded as **dag-cbor**: definite lengths, shortest-form integers, map keys sorted by (length, bytewise), no duplicate keys, no CBOR tags other than 42 (CID link).

3.2 **No floating-point values anywhere.** Use fixed-point integers:
- Probabilities: `ppm` = integer 0…1,000,000.
- Surprise: `mnat` = milli-nats (uint).
- Timestamps: `ts` = integer milliseconds since Unix epoch, UTC.
- Decimals in domain data: `{"m": int, "e": int}` meaning m×10^e.

3.3 Text MUST be NFC-normalized UTF-8; control characters other than `\n` and `\t` are forbidden.

3.4 **Unknown fields MUST be preserved** on decode→encode round-trips and are covered by the signature. Fields named in `crit` that a validator does not understand MUST cause rejection.

3.5 **Size limits:** object ≤ 256 KiB encoded; `text` ≤ 16 KiB; `shorttext` ≤ 256 B; arrays ≤ 1024 items; nesting depth ≤ 16. Larger content goes in **blobs** (§8.4).

## 4. Identity

4.1 A practitioner identity is a signed log of identity objects. Its stable identifier is
`did:praxis:<base32lower(CID of the id-genesis object)>` — concretely (PIP-0003), the id-genesis object's CID in its standard CIDv1 multibase string form (e.g. `bafyr4ig...`). Because that CID is not known until after the genesis object is signed, its own `author` field cannot literally hold it; `id-genesis.author` is instead the fixed sentinel `did:praxis:selfselfselfselfself`, never a real identity (PIP-0004).

4.2 `id-genesis` lists initial keys: each `{kid, alg:"ed25519", pub, role, not_before, not_after?}`, with `role ∈ {root, device, recovery}` and optionally a separate **X25519 encryption key** (`enc_pub`) for HPKE. `id-genesis` MUST be signed by a key listed in its own `keys` with `role: root` (PIP-0003).

4.3 `id-rotate` replaces the root key; it MUST be signed by the **current root key** *or* by a `recovery` key, and (PIP-0003) retires the previous root key's validity as of the rotate object's `ts` for every purpose, not merely as root. `id-delegate` authorizes a device key (with optional expiry and **scope**: which kinds it may sign); it MUST be signed by the current root or a recovery key (PIP-0003). `id-revoke` revokes a key from a stated effective time; it MUST be signed by the current root or a recovery key, or by the key being revoked itself (self-revocation, PIP-0003).

4.4 **Validity of a signature** = signer key was authorized by the identity log at the object's `ts`, *and* the identity-log objects establishing that are themselves valid and causally prior.

4.5 **Honest limit:** `ts` is a claim by the signer. A compromised key can backdate objects. Mitigations: anchors (§7), revocation with a stated `compromised_since`, and verifiers' ability to treat objects with no anchor after a compromise window as *untrusted for scoring*.

4.6 **Recovery:** implementations SHOULD support Shamir 2-of-3 or 3-of-5 recovery shares for the root key (library: `vsss-rs` or equivalent audited crate) and MUST support hardware-key (FIDO2/PIV) root keys as an option.

## 5. Envelope

```
Object = {
  v: 1,
  kind, [case,] prev: [cid...], author: did, signer: kid, ts, suite, body, sig,
  [crit], ...unknown
}
```

5.1 **Object ID** = CID of the *entire* canonical encoding, **including `sig`** (Ed25519 is deterministic, so the ID is stable).

5.2 **Signature:**
`sig = Ed25519.sign(signer_secret, "praxis/v1/object\x00" || canonical_bytes(object_without_sig))`
The domain-separation prefix is part of the signed message. Verifiers MUST reject objects whose recomputed canonical bytes differ from received bytes (i.e. non-canonical encodings are invalid).

5.3 `prev` lists **causal parents** (object IDs the author had seen and builds on). `ts` MUST be ≥ every parent's `ts` (creators with slow clocks MUST use `max(parent.ts)+1`; validators MUST reject violations). This is what makes the log a verifiable, tamper-evident DAG.

5.4 `case` is the ID of the case's `open` object (omitted on `open` itself).

## 6. Case lifecycle

```
open ──► [prediction]* ──► decision ──► claims ──► [elicitation]* ──► outcome ──► (closed)
   │                           │                          ▲
   └─► abandon                 └─► amend / retract ───────┘ (any time after decision)
```

Normative rules:

| # | Rule |
|---|---|
| C1 | `open` MUST be the first object of a case; its ID is the case ID. |
| C2 | A `prediction` MUST causally precede the `decision` it concerns (`decision.prev` ∋ prediction ID) and MUST NOT contain the decision. This is the **anti-hindsight rule**: the apprentice commits to a distribution over options *before* the practitioner's choice is recorded. |
| C3 | `claims` MUST be created at decision time and MUST causally follow `decision` (or be in the same author-batch with consecutive `ts` and `claims.prev ∋ decision`). Claims MUST NOT be edited. |
| C4 | Each claim has a stable `id` (unique within the case), a `statement`, `p` (ppm), a **resolution** (§6.5) and a `horizon` (resolve-by `ts`). |
| C5 | `amend` MAY add commentary, correct typos, or add **late claims** (flagged `late:true`, **excluded from scoring**). It MUST NOT modify existing claims' `p`, `resolve`, or `horizon`. |
| C6 | `outcome` resolves claims. Each claim resolves at most once; the earliest causally-valid resolution is authoritative, later ones are treated as `amend`. `void` is allowed only with a stated reason from a controlled vocabulary (`premise_invalid`, `action_not_taken`, `unobservable`, `superseded`). |
| C7 | `retract` is a **tombstone**: it asserts the author withdraws consent for further use of the case. It does not delete bytes (immutability) but compliant clients MUST stop using the case in new retrieval/training/calibration publication (§10). Retracting a case with scored claims leaves an `n_retracted` count visible in calibration (anti-cherry-picking). |
| C8 | `abandon` closes an unresolved case. Abandonment counts are reported alongside calibration (§ SCORING 6). |

### 6.5 Resolution criteria
```
resolve = { kind: "cel", expr: text, inputs: [shorttext...] }       ; machine-checkable
        / { kind: "attested", by: "self" / "peer" / "registry", rubric: text }
```
`cel` expressions follow the Common Expression Language over named **observations** (`spec/POLICY.md` §4). They MUST be non-Turing-complete, side-effect free, and time-bounded in evaluation. `attested` resolutions require a `rubric` fixed at claim time (prevents goalpost shifting).

### 6.6 Event bodies (summary; schema is normative in CDDL)
- **open:** `domain` (`pack@version`), `situation` (summary, signals[], context map), `stakes`, `policy`.
- **prediction:** `model` (id, digest, lineage build), `options[{option, p}]` *(distribution over the pack's option set)*.
- **decision:** `options_considered`, `chosen`, optional `reasoning` text, optional `confidence`.
- **claims:** `[ {id, statement, p, resolve, horizon, core?} ]`.
- **elicitation:** `trigger{surprise_mnat, stakes_weight, budget_state}`, `qa[{q, choices?, a, latency_ms}]`, `modality`.
- **outcome:** `results[{claim, result: true/false/void, evidence[], attributed: auto/peer/self, void_reason?}]`, `confounders[]`, `narrative?`.

## 7. Time & anti-hindsight

7.1 Self-asserted `ts` is the baseline. **Anchors** strengthen it:
- `anchor` object: `{targets:[cid...], method, proof}` with `method ∈ {"relay-receipt","rfc3161","opentimestamps"}`.
- `relay-receipt`: a relay signs "first seen object X at time T". Weak-trust, cheap, offline-friendly via later batch anchoring.
- `rfc3161`: a TSA token over a Merkle root of targets. Stronger.
7.2 Scoring distinguishes **anchored** from **unanchored** claims (SCORING.md §6). Disclosed calibration MUST state the anchored fraction.
7.3 Clients SHOULD batch-anchor on reconnect (Merkle root of all un-anchored object IDs since last anchor).

## 8. Confidentiality: sealing

8.1 Each object body is `plain` or `sealed`.
```
plain  = { plain: content, salt: bstr16 }
sealed = { sealed: {alg:"xc20p", nonce: bstr24, ct: bstr}, commit: hash32, [rcpt: [recipient...]] }
```
8.2 **Plaintext** to be sealed is the canonical encoding of `{content, salt}`; `salt` is 16 random bytes (hides low-entropy content from guessing). `commit = BLAKE3("praxis/v1/commit\x00" || plaintext_bytes)`. After any reveal, anyone can verify the plaintext matches `commit`, so **a practitioner cannot later substitute a different body**.

8.3 **Key hierarchy.** Per case, the author generates `CK` (32 random bytes). Event body key = `HKDF-SHA256(ikm=CK, salt="praxis/v1/bodykey", info=kind||0x00||u32(index_in_case))`. Revealing one body key reveals **only that event**. CK is stored in the author's local keystore, encrypted under a key derived from the identity root (or hardware key).
`ct = XChaCha20-Poly1305(key=bodykey, nonce, aad=kind||case||author, plaintext)`.
Byte encodings for the concatenations above (PIP-0001): `kind` is the UTF-8 bytes of the CDDL `kind` string (e.g. `decision`); `u32(n)` is 4 bytes big-endian; `case` is the CID's raw multiformats binary encoding (no CBOR tag-42 wrapper, no outer `bstr` length prefix); `author` is the UTF-8 bytes of the `did:praxis:...` string; `0x00` is one literal zero byte.

8.4 **Recipients.** A `recipient` = `{kid, enc, wrapped}` where `wrapped` is the HPKE-sealed body key (or CK) to the recipient's `enc_pub`. A `grant` object (§10) is the normal way to give access after the fact.
HPKE parameters (PIP-0002): mode `Base`; `info` = the fixed ASCII string `praxis/v1/wrap`; `aad` = empty.

8.5 **Padding.** `ct` MUST be padded (inside the AEAD plaintext, via CBOR padding field `pad`) to the next bucket of {1 KiB, 4 KiB, 16 KiB, 64 KiB, 256 KiB}. This limits size-based leakage on relays.

8.6 **Blobs (attachments).** Blobs are `raw` CIDs (BLAKE3) of files, optionally sealed with a per-blob key listed inside a sealed body. Streaming verification uses BLAKE3 tree (Bao). Blob size ≤ 64 MiB in v0.1.

8.7 **What relays can see** (metadata): kind, author, case ID, `ts`, `prev`, size bucket. Not content. See `docs/PRIVACY_AND_THREAT_MODEL.md` §4.

## 9. Selective disclosure of calibration

9.1 A practitioner may publish an `attest` object: *"Over the set S of claims-events and outcome-events, the following aggregate statistics hold"*, where S is committed by a **Merkle root** over object IDs, and statistics are computed per `spec/SCORING.md`.
9.2 To let a verifier recompute, the practitioner reveals, for each claim: `{claim id, p, resolve, horizon, result, attributed}` + the unsealed bodies of the `claims` and `outcome` objects **only** (not `open`, `decision`, `elicitation`). Verifiers check `commit`s, signatures, timestamps, and anchor proofs, then recompute.
9.3 **Completeness problem (cherry-picking).** A practitioner could disclose only good claims. Mitigations in v0.1: (a) `attest` MUST include `n_opened`, `n_abandoned`, `n_retracted`, `n_void` counts *signed at the time of attestation* and anchored; (b) verifiers see the **claim coverage ratio**; (c) a registry (Phase 3) may require *continuous registration* (all `open` IDs registered at creation, content hidden), making omissions detectable. Zero-knowledge proofs of aggregate statistics are a research track (`Q-004`).

## 10. Lineage & policy

10.1 `grant`: `{grantee: did, scope: {cases: [cid...] | domain+filter}, wrapped_keys: [...], terms: usage, expires?}`: access and permitted uses.
10.2 `derive`: *B declares it learned from A in domain D* (optionally referencing a grant). Used for lineage graphs. Not an endorsement of A's correctness.
10.3 `diverge`: *B decided differently from A on situation S*, referencing A's case and B's case, with B's stated reasoning. This is the **fork** primitive.
10.4 `canon`: curated manifest `{id, name, domain, editors, inclusion_policy, members_root, version, prev_version}`; versioned like a branch. Members are case IDs (with the members' own policies still in force).
10.5 **Usage policy** is attached to each case at `open` (`policy` field, spec/POLICY.md). Compliant clients and services MUST evaluate it before: retrieval for others, training builds, calibration publication, export to third parties. `employment_evaluation` is a **fixed-false** field: no policy may set it to true. (Its *enforcement* is architectural + conformance suite, not magic: see threat model.)
10.6 **Build manifests.** Any model build (fine-tune, index) over others' cases MUST emit a signed `attest` build manifest listing included case IDs and the policies checked. Withdrawing consent (`retract`/policy change) excludes cases from *subsequent* builds; clients MUST support "rebuild without X".

## 11. Sync: Praxis Sync Protocol (PSP/1)

Transport-agnostic (v0.1 bindings: HTTPS+WebSocket; libp2p later). Messages are CBOR.

| Message | Purpose |
|---|---|
| `HELLO` | versions, suites, capabilities, caller DID + challenge response |
| `SUBSCRIBE` | filter: authors, domains, canons, kinds |
| `RECON` | **range-based set reconciliation** over the sorted set of `(ts, id)` (fingerprint = BLAKE3-based XOR/sum of IDs over the range; recursive bisection) |
| `GET` / `PUT` | fetch/push objects by ID |
| `HAVE` / `WANT` | optional hints |
| `ERR` | typed errors (`E_UNAUTHORIZED`, `E_INVALID`, `E_TOO_LARGE`, `E_RATE`...) |

11.1 **No mutable heads**: peers converge when their filtered sets are equal. Objects whose parents are unknown are **pending** until parents arrive (bounded buffer).
11.2 **Authorization:** servers return an object only if the requester is allowed by its policy/visibility; sealed objects with `public-ciphertext` visibility may be served to anyone (ciphertext is safe to relay).
11.3 **Relays are dumb stores** (like git remotes): they validate envelope, signature, size and rate limits; they never need keys.
11.4 **DoS controls:** per-DID rate limits, proof-of-identity on write, size limits, and optional hashcash-style proof-of-work for unknown DIDs.

## 12. Validation (reference algorithm)

`validate(obj, ctx)`:
1. Decode; reject if not canonical; enforce limits & `crit`.
2. Check `suite` supported; `v==1`.
3. Resolve identity log → signer key authorized at `ts`; verify `sig`.
4. For each parent in `prev`: if known, check `ts` monotonicity; if unknown → *pending*.
5. Kind-specific rules (§6 C1–C8, §10).
6. If `plain`: validate content against CDDL. If `sealed`: validate envelope only; content validation happens at reveal.
7. Accept → store; emit events to subscribers.

## 13. Versioning & extension
- Backward-compatible additions: new optional fields (preserved by old validators), new `kind`s marked `crit` when required.
- Breaking changes: new `v`; negotiated in `HELLO`; require a PIP and migration tool.
- Domain data lives in `situation.context` governed by **Domain Packs** (`docs/DOMAIN_PACKS.md`), never in the core schema.

## 14. Conformance levels

| Level | Requires |
|---|---|
| **L1 Core** | encode/decode, IDs, sign/verify, validation, identity log |
| **L2 Store** | durable store, queries by case/author/kind, pending-parent handling |
| **L3 Sync** | PSP/1 client and/or server |
| **L4 Privacy** | sealing, key hierarchy, grant, policy evaluation, retract semantics, build manifests |
| **L5 Scoring** | SCORING.md exactly, bit-identical on test vectors |

The conformance suite (`spec/test-vectors/` + `bench/conformance/`) is the arbiter.
