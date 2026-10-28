# Implementation Plan

*For the implementing AI agent and human maintainers. Read `AGENTS.md` first.*
Each task: **ID · description · acceptance criteria (AC)**. Size: S (<½ day) · M (1–2 days) · L (3–5 days) for a focused agent. **Do tasks in order within a milestone unless marked ∥ (parallelizable).** A milestone closes only when its gate passes.

---

## M0: Foundations
| ID | Task | AC |
|---|---|---|
| M0-01 (S) | Create Cargo workspace per `ARCHITECTURE.md §3` (empty crates, `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`), `rust-toolchain.toml`, `LICENSES` wiring, SPDX headers | `cargo check --workspace` passes; dep-graph matches rules (CI script) |
| M0-02 (S) | `justfile` (`ci`, `fmt`, `lint`, `test`, `deny`, `audit`, `docs`, `fuzz-smoke`) + GitHub Actions on Linux/macOS/Windows | CI green on empty workspace |
| M0-03 (S) | `deny.toml` (license allow-list per LICENSING §5), `cargo-vet` init, SPDX header check, DCO check | CI fails on a deliberately disallowed dep (test PR) |
| M0-04 (S) | CDDL lint of `spec/praxis-v0.1.cddl` in CI; generate JSON Schema artifacts | CDDL parses; invalid mutation fails |
| M0-05 (S) | mdBook site from `README`, `docs/`, `spec/`; link checker | `just docs` builds; zero broken links |
| M0-06 (S) ∥ | Skeletons: `sdk/ts` (pnpm), `apprentice/` (uv, ruff, mypy strict), `apps/desk` placeholder | CI lint passes for each |
| M0-07 (S) | **Human gate:** maintainers review spec; open issues for all `OPEN(Q-*)`; sign off "spec v0.1-draft frozen for M1" | Sign-off recorded in `adr/0009-spec-freeze-m1.md` |

## M1: Trust kernel (types, crypto, identity, validation, vectors)
| ID | Task | AC |
|---|---|---|
| M1-01 (M) | `praxis-types`: scalar newtypes (`Ppm`, `Mnat`, `Ts`, `Did`, `Kid`), `Object` envelope, content enums per CDDL | Constructors enforce ranges; serde round-trip tests |
| M1-02 (L) | **Canonical dag-cbor codec**: strict decode (reject non-canonical, floats, tags≠42, dup keys, over-limits), preserve unknown fields, `crit` handling | proptest encode∘decode=id; key-reorder ⇒ same bytes; cargo-fuzz target runs 10 min clean; 100% of PROTOCOL §3 rules have tests |
| M1-03 (S) | CIDv1 (dag-cbor, blake3-256) | Known-answer tests; matches independent TS impl later (M1-09) |
| M1-04 (M) | `praxis-crypto`: Ed25519 (strict) w/ domain separation; HKDF; XChaCha20-Poly1305; HPKE wrap/unwrap; zeroize; constant-time compares | RFC KATs pass; single-bit-flip always fails verify/decrypt |
| M1-05 (M) | **Sealing**: key hierarchy (CK→body keys), commit, padding buckets, seal/unseal/reveal-verify | Fixed-seed vectors; commit mismatch rejected; padding bucket test |
| M1-06 (L) | `praxis-identity`: identity log (`genesis/rotate/delegate/revoke`), key-validity-at-time, device scope, `compromised_since` | Scenario tests incl. rotation, revoked device, backdating attempt; property tests |
| M1-07 (L) | `praxis-validate`: algorithm §12; lifecycle rules **C1–C8**; ts monotonicity; pending-parent classification; typed `E_*` errors | Each rule has ≥1 valid and ≥1 invalid test; error codes stable |
| M1-08 (M) | Test-vector generator → `spec/test-vectors/**` | Vectors for every rule; includes `scoring/basic-001` placeholder expected values from SCORING §9 |
| M1-09 (L) | **Independent TS verifier** (`sdk/ts/verifier`, pure TS, no WASM) passes all vectors | CI job `vectors-ts` green. **If Rust and TS disagree, fix spec or impl: do not special-case** |
| M1-10 (S) | Fuzz targets for decode/validate/unseal; `SECURITY.md` checklist applied | 30 min fuzz clean in CI nightly |
**Gate M1:** M1-08/09 both implementations pass 100% of vectors; no `unsafe`; docs complete.

## M2: Local journal: value at n=1 (alpha)
| ID | Task | AC |
|---|---|---|
| M2-01 (L) | `praxis-store` (SQLite WAL): objects/edges/identity tables, append-with-validate, pending handling | **Event-sourcing invariant test:** drop derived tables, replay, byte-identical results |
| M2-02 (L) | Keystore: OS keychain via `keyring`; Argon2id passphrase fallback; CK wrapping; root-derived index key; Shamir recovery | Round-trip + loss/recovery tests; no plaintext keys on disk (test scans files) |
| M2-03 (M) ∥ | Blob store (BLAKE3/Bao streaming verify) | Corruption detected on read; 64 MiB limit enforced |
| M2-04 (M) | Domain pack loader/validator; **`incident-response` pack**; `praxis pack test` | Pack schema validated; 20 synthetic cases pass; no float fields |
| M2-05 (L) | `praxis-core` façade flows: open/decide/claims/amend/abandon/retract; "no-apprentice mode" commits prior-model `prediction` (rule C2 always honored) | Cannot save `decision` without causally-prior `prediction` (negative test) |
| M2-06 (L) | CLI v0: `init whoami open decide list show abandon retract export import doctor privacy audit` | Snapshot tests of `--json`; exit codes per spec; offline by default |
| M2-07 (M) | FTS5 local search on decrypted bodies; encrypted index at rest | Index unreadable without key (test) |
| M2-08 (M) | User guide "5-minute journal"; signed release `v0.1.0-alpha` via cargo-dist | Fresh-machine install-to-first-case < 10 min (timed) |
**Gate G1:** ≥10 alpha users, ≥3 weeks, median capture ≤ 30 s; fix friction before M3+.

## M3: Scoring, resolution, policy, attestation
| ID | Task | AC |
|---|---|---|
| M3-01 (L) | `praxis-score` per SCORING.md (Brier, log, BSS, adaptive bins, Wilson, ECE, bootstrap w/ ChaCha20 seed, Murphy, AUC, overconfidence, labels) | Golden vectors; TS port matches ≤1e-9; proptests (BS∈[0,1], BSS≤1, bin counts ≥10); degenerate inputs handled |
| M3-02 (L) | **CEL resolution engine**: whitelisted functions, time/memory bounds, evidence freezing, observation-provider trait, `void(unobservable)` semantics | Malicious/expensive expressions are bounded; deterministic re-evaluation from frozen evidence |
| M3-03 (M) | **Cedar integration**: baseline policy compiled in, `forbid` overrides, policy eval API | Tests: no config can weaken baseline `forbid`s |
| M3-04 (M) | `close`, `calibration`, reminders, coverage/void/abandon/anchored stats | CLI output matches SCORING §5–§6 labels and the causality caveat |
| M3-05 (L) | `attest calibration` + `verify`: Merkle set root, disclosure bundle, verifier recomputation | Third-party verifier reproduces stats; cherry-pick test flags missing counts |
| M3-06 (M) | Anchors: batch Merkle anchor objects; relay-receipt verification (stubbed until M5); optional RFC 3161 client | Anchored fraction computed correctly |

## M4: Surprise Engine & Apprentice v0
| ID | Task | AC |
|---|---|---|
| M4-01 (M) | `proto/` definitions; `praxisd` with UDS gRPC; capability tokens | Unauthorized client rejected; socket perms tested |
| M4-02 (M) | Apprentice runtime (Python): `Health`, `Embed`, `ExtractFeatures`; local model adapters; **model digest pinning** | Digest mismatch refuses to run |
| M4-03 (L) | Retrieval: hybrid BM25 + dense (sqlite-vec) + reranker v0 | Recall@k on synthetic benchmark; latency p95 < 150 ms @100k cases |
| M4-04 (L) | `Predict`: distribution over option set; calibrator (temperature/isotonic) fit on holdout; ECE tracking | Distribution sums to 1,000,000 ppm; ECE reported |
| M4-05 (M) | Prediction commit flow (rule C2) with latency budget | p95 < 1.5 s local; timeout falls back to prior and is recorded |
| M4-06 (L) | `praxis-surprise`: S, w, T, gating, budget, timing, adaptive τ, cold start | Deterministic simulations; invariants (never interrupts during time-pressure) |
| M4-07 (M) | Contrastive question generator; decoys; order randomization; blind-mode flag | Template tests; decoy-rate telemetry stays local |
| M4-08 (M) | `praxis elicit` UX; "why am I being asked?"; pause/cap/ask-less | Declined questions never re-asked |
| M4-09 (L) | `Consult`: provenance, **kernel-side citation verification**, dissent, abstention, author-weight caps | Forged/unauthorized citations stripped (adversarial tests); 100% provenance validity |
| M4-10 (M) | Reasoning Utility (cross-fit) + offline template bandit | RU unit tests with planted-signal synthetic data; no leakage test |
| M4-11 (M) | MCP server (draft-only writes; agent identities) | Agents cannot sign as human (negative tests) |
| M4-12 (M) | Adversarial suite: prompt injection, poisoned cases, citation forgery | All pass or documented residual risk |
**Gate G2:** provenance validity 100%; predictor ECE within bound; elicitation response ≥ 30% with ≤ 3 interruptions/day.

## M5: Sync, relay, lineage, canons
| ID | Task | AC |
|---|---|---|
| M5-01 (L) | PSP/1 codec + **range-based set reconciliation**; HELLO auth | Vectors in `spec/test-vectors/sync`; TS port interoperates |
| M5-02 (M) | `praxis-sync` client: pending buffer, backpressure, rate limits | Converges under packet loss/reorder (simulation) |
| M5-03 (L) | `praxis-relay` (AGPL): validate, rate-limit, storage (SQLite/Postgres + S3), receipts, Docker/Compose | 10k obj/s ingest; relay never sees keys (test) |
| M5-04 (M) | `grant` + HPKE wrapped keys; `share`; policy-checked retrieval | Unauthorized read denied; revoked grant stops future key wraps |
| M5-05 (M) ∥ | `derive`/`diverge` + lineage graph queries | Graph tests; sealed edges supported |
| M5-06 (L) | Canons: create/add/release; Merkle `members_root`; editors; inclusion policy; versioning | Immutable versions; diff between versions |
| M5-07 (M) | **"Rebuild without me"** + build manifests | Retracted case excluded from next build (test) |
| M5-08 (M) | Multi-device: delegate, sync between own devices | Revoked device cannot append after `effective` |
| M5-09 (M) | **Privacy-conformance suite** (PRIVACY §5), incl. network-sandbox test | Part of required CI |

## M6: Desktop app & integrations
| ID | Task | AC |
|---|---|---|
| M6-01 (L) | Tauri 2 shell bound to `praxis-core`; design system; WCAG 2.2 AA baseline | axe checks pass; full keyboard operation |
| M6-02 (M) | Quick-capture window (global hotkey); optional local STT | ≤30 s median in usability test |
| M6-03 (L) | Calibration dashboard (reliability curves, labels, caveats) | Matches CLI numbers exactly |
| M6-04 (L) | Elicitation panel; consult UI with provenance + dissent browsing | Usability test n≥8 |
| M6-05 (L) | Integrations (draft generation only): GitHub, Slack, PagerDuty/Opsgenie; Prometheus observation provider | Drafts never auto-saved |
| M6-06 (M) | Publish TS & Python SDKs + examples | Examples run in CI |
| M6-07 (M) | Onboarding, docs, "org adoption guidelines" (anti-surveillance practices) | Reviewed by Practitioner reps |

## M7: Study S1 (pre-registered)
| ID | Task | AC |
|---|---|---|
| M7-01 (M) | Pre-register (OSF), ethics review, power analysis, fix δ | Registration public **before** data collection |
| M7-02 (L) | "Study mode" build: arms B0–B4 harness, blind/non-blind elicitation, frozen prompts/models | Reproducible runs from seeds |
| M7-03 | Recruit & run | ≥ 20 participants, ≥ 2 orgs |
| M7-04 (L) | Analysis (`bench/study`), mixed-effects, Holm | Notebook reproduces tables from raw data |
| M7-05 (M) | Publish incl. negative results | Open data where consented |
**Gate G3:** apply the pre-registered rule honestly (EVALUATION §4).

## M8: Hardening → 1.0
| ID | Task | AC |
|---|---|---|
| M8-01 | External cryptography review + penetration test | No open High findings |
| M8-02 | Hybrid PQ suite `pxs2` (if audited crates exist) or documented deferral PIP | Decision recorded |
| M8-03 | `praxis-registry`: anchors, canon directory, transparency log, continuous registration | Log consistency proofs verified |
| M8-04 | Reproducible builds, SLSA ≥3, SBOM | Independent rebuild matches hash |
| M8-05 | ≥1 independent third-party implementation passes conformance | Listed in README |
| M8-06 | Foundation transfer (GOVERNANCE §2) | Legal docs complete |
| M8-07 | Spec v1.0 Final | PIPs closed |

---

## First 10 actions for the implementing agent
1. Read `AGENTS.md` and all of `spec/`. 2. Do M0 in full. 3. Open the human gate M0-07. 4. Start M1-01..M1-03. 5. After M1-02, start M1-09 (TS verifier) in parallel with M1-04+. 6. Generate vectors early and often. 7. Never advance a gate with failing vectors. 8. Keep `docs/` and `spec/` in sync with code (PRs). 9. Record deviations as ADRs. 10. Ask a human when a decision involves crypto, ethics, legal, or governance.

## Risk register (engineering)
| Risk | Mitigation |
|---|---|
| Spec ambiguity → divergent implementations | Two independent implementations from M1; vectors are arbiter |
| dag-cbor strictness differs across libraries | Own strict decoder tests; cross-impl vectors |
| CEL/Cedar crate gaps | Fall back to reference-engine subprocess *only* if documented in an ADR; keep interface narrow |
| Apprentice latency | Cache embeddings; small local models; fallback to prior |
| Scope creep | `AGENTS.md` §0.6; milestones gated |
