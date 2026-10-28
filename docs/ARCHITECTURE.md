# Architecture

## 1. Principles
Local-first · Immutable event log · Derived state is rebuildable · Small acyclic crates · Untrusted-input hygiene (everything parsed is hostile) · Pluggable intelligence, **fixed trust kernel**.

## 2. System view
```
┌───────────────────────────── Practitioner device ─────────────────────────────┐
│  CLI (praxis)   Desktop (Tauri)   VS Code   MCP clients (AI agents)   SDKs      │
│        │              │               │            │                  │         │
│        └──────────────┴───────┬───────┴────────────┴──────────────────┘         │
│                         praxis-core  (library; Rust)                              │
│  ┌──────────┬───────────┬──────────┬─────────┬──────────┬────────────┐          │
│  │ types/   │ crypto/   │ store/   │ score/  │ policy/  │ surprise/  │          │
│  │ codec    │ identity  │ SQLite   │ calib.  │ Cedar+CEL│ engine     │          │
│  └──────────┴───────────┴──────────┴─────────┴──────────┴────────────┘          │
│        │ optional local daemon: praxisd (UDS gRPC + MCP)                          │
│        ▼                                                                          │
│  Apprentice runtime (Python, separate process, gRPC over UDS)                     │
│   retrieval · predictor · calibrator · answer composer · local/remote models      │
└───────────────┬───────────────────────────────────────────────────────────────────┘
                │ PSP/1 (HTTPS/WebSocket; sealed objects only unless public)
        ┌───────▼────────┐        ┌──────────────────┐       ┌──────────────────┐
        │  praxis-relay  │◄──────►│  praxis-registry │       │ Blob store (S3)  │
        │ dumb object    │        │ anchors, canons  │       │ sealed blobs     │
        │ store + recon  │        │ directory (Ph.3) │       │                  │
        └────────────────┘        └──────────────────┘       └──────────────────┘
```

## 3. Crates (Rust workspace) and dependency rules
```
praxis-types      ← no deps on other praxis crates (codec, CIDs, schema types, validation of shapes)
praxis-crypto     ← types
praxis-identity   ← types, crypto           (identity log, key authorization)
praxis-validate   ← types, crypto, identity (the reference validator, §PROTOCOL 12)
praxis-store      ← types, validate         (SQLite, blobs, derived indexes, keystore interface)
praxis-policy     ← types                   (Cedar + CEL)
praxis-score      ← types                   (pure functions; NO I/O)
praxis-surprise   ← types, score            (trigger logic; model-agnostic)
praxis-sync       ← types, validate, store  (PSP/1 client+server logic, transport-agnostic)
praxis-core       ← all of the above        (façade; stable public API)
praxis-cli, praxisd, praxis-wasm, praxis-ffi ← praxis-core
praxis-relay, praxis-registry (AGPL) ← sync, store, policy
```
Rules: **no cycles; `score` and `types` never do I/O; only `store` touches disk; only `sync`/`relay` touch network.** Enforced by `cargo-deny` + a CI dependency-graph check.

## 4. Data flow: recording a decision
1. CLI → `core.open_case(...)` → build `open` object → sign (device key) → validate → store (append, index) → *(optional)* background anchor.
2. Core asks apprentice (UDS) `Predict(situation, options)` → builds `prediction` object **before** accepting `decision`.
3. User chooses → `decision` (sealed per policy) → `claims` → store.
4. Surprise engine computes `S = −ln q(chosen)`, `T = S×w` → enqueue elicitation (or not).
5. Later: observation snapshots frozen as evidence → CEL resolve → `outcome` → scoring recomputed (derived tables).

## 5. Storage (local)
SQLite (WAL), single file `praxis.db`, plus `blobs/` directory (content-addressed, sharded by CID prefix).
```
objects(cid BLOB PK, kind, author, case_cid, ts, size, bytes BLOB, status{valid|pending|rejected}, rejected_code)
edges(child BLOB, parent BLOB)                       -- prev links
identity_keys(did, kid, pub, role, not_before, not_after, revoked_at, compromised_since)
keystore(case_cid, wrapped_ck BLOB)                  -- CK wrapped under root-derived key (NEVER plaintext)
-- Derived (rebuildable from `objects` + keystore; dropped & rebuilt on schema change):
cases(case_cid PK, domain, state, opened_ts, decided_ts, closed_ts, chosen, stakes_impact, ...)
claims(case_cid, claim_id, p_ppm, horizon, template, core, result, attributed, anchored, ...)
anchors(cid, anchor_cid, method, ts)
fts_cases USING fts5(summary, reasoning, tags)       -- local only, only for bodies the user can decrypt
vec_cases USING vec0(embedding float[...])           -- sqlite-vec; local only
elicit_queue(case_cid, T, created_ts, expires_ts, state)
settings(...)
```
**Event-sourcing invariant:** deleting all derived tables and replaying `objects` MUST reproduce them exactly (tested).

## 6. Process model
- `praxis` CLI links `praxis-core` directly; no daemon required.
- `praxisd` (optional): long-running local service for desktop, IDE, and MCP; single-writer lock; gRPC over Unix domain socket / named pipe with OS-level permissions.
- **Apprentice runtime** is a separate process (Python) so ML dependencies and model weights never enter the trust kernel; the kernel treats its output as **untrusted advice** (distributions are validated; provenance IDs are verified to exist and be permitted).

## 7. Trust boundaries
| Boundary | Rule |
|---|---|
| Kernel ↔ apprentice | Apprentice cannot sign, cannot read keystore, receives only data the policy allows for the task |
| Kernel ↔ network | Only PSP/1 and explicit user-initiated model calls; sealed bodies leave the device only as ciphertext |
| Kernel ↔ plugins/integrations | Integrations produce *drafts*; the kernel never accepts unsigned writes |
| Relay ↔ client | Relay is untrusted for confidentiality and integrity; it is trusted only for availability and (weakly) for receipts |

## 8. Extensibility points
Domain packs (data) · Observation providers (Prometheus, Datadog, custom) · Model providers (local/remote) · Transports for PSP · Embedding models · Integrations (drafts only).

## 9. Deployment topologies
1. **Solo:** laptop only. 2. **Team:** self-hosted relay (Docker/Compose) with team canon. 3. **Public:** community relays + registry. 4. **Air-gapped:** sneakernet export/import bundles (same objects, CAR files).

## 10. Interop/export
Export format: **CAR (Content Addressable aRchive) v1** containing all objects + blobs, plus a human-readable `MANIFEST.md` and optional per-case Markdown/JSON renders (plaintext, if the user chooses to unseal).
