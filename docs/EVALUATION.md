# Evaluation: Falsifiable Claims, Experiments, Quality Gates

> A project that claims to capture judgment must be willing to measure whether it does.

## 1. Hypotheses
| ID | Hypothesis | Type |
|---|---|---|
| **H1** (central) | An apprentice conditioned on decisions **plus surprise-elicited reasoning** predicts a practitioner's *held-out surprising decisions* better than one given decisions alone, and better than one given decisions + conventional postmortems. | Primary |
| H2 | Observation-first, decoy-controlled elicitation yields reasoning with higher Reasoning Utility than free-form "why" prompts. | Secondary |
| H3 | Practitioners' calibration (ECE/BSS) improves with feedback over the study period vs. a control group that logs without feedback. | Secondary |
| H4 | Blind elicitation (no model prediction shown) vs. non-blind: difference in RU (anchoring). | Exploratory |
| H5 | Apprentice abstention improves selective risk: accuracy on answered subset > unconditional accuracy at matched coverage. | Secondary |
| H0 | No benefit from elicited reasoning (the project's transmission thesis fails). | Null |

## 2. Primary study design (Study S1)
- **Population:** ≥ 20 senior engineers (≥ 5 yrs on-call), ≥ 2 organizations to avoid single-culture artifacts. Voluntary, informed consent, IRB/ethics review (or equivalent). Pay participants.
- **Duration:** 4–8 weeks; target ≥ 40 cases/participant (power analysis to finalize in the pre-registration; adjust N accordingly).
- **Arms (within-subject comparison of apprentices on held-out cases):**
  - **B0** Domain prior (frequency/baseline).
  - **B1** Zero-shot general LLM + the participant's *postmortems/docs only* (no judgment cases).
  - **B2** Apprentice with **decisions only** (cases without elicitation).
  - **B3** Apprentice with decisions + **elicited reasoning** (full system).
  - **B4** Apprentice with decisions + *free-form post-hoc reasoning written without elicitation* (tests whether the Surprise Engine matters vs. just asking everyone to explain).
- **Held-out set:** chronologically last 25% of each participant's cases (forward-in-time split) + a **surprising-subset** (decisions with prior-model surprise in the top tercile).
- **Primary metric:** per-participant mean log-loss on the surprising-subset, B3 vs B2 (paired). **Pre-registered decision rule:** B3 beats B2 with a one-sided 95% bootstrap CI excluding 0 **and** relative log-loss reduction ≥ *δ* where *δ* is fixed in the pre-registration before data collection (do **not** pick after seeing data).
- **Secondary metrics:** top-1 accuracy, ECE, B3 vs B4, abstention selective-risk, RU by template, response rate, burden (time per case, per elicitation), participant-reported trust and intrusion.
- **Blinding/leakage controls:** cross-fitting for RU; no elicitation text from the held-out period leaks into the held-out evaluation; prompt templates frozen; model digests pinned; seeds logged.
- **Analysis:** mixed-effects model (participant random effects), bootstrap by participant; multiplicity control (Holm) across secondaries; report effect sizes and CIs, not just p-values; publish all code, **negative results included**.
- **Pre-registration:** OSF (or equivalent) before data collection; deviations documented.

## 3. Pre-study (Study S0): feasibility, cheap, first
Use **public incident postmortems** (verify license for each corpus before use) to test the *pipeline* (not H1): can the system extract structured situations/decisions/options from narratives, and does retrieval produce sensible precedents? Synthetic data from `bench/synth` may test plumbing, performance, and scoring correctness, **never** to support H1.

## 4. Go / No-go gates
| Gate | Condition | If fail |
|---|---|---|
| G1 (after M2) | ≥ 10 alpha users use the journal ≥ 3 weeks; median capture ≤ 30 s | Fix capture UX before building more |
| G2 (after M4) | Provenance validity 100%; predictor ECE within bound; elicitation response rate ≥ 30% with ≤ 3 interruptions/day | Rework Surprise Engine |
| **G3 (after M7)** | **H1 supported per pre-registered rule** | **Do not market "transmission of judgment". Publish; pivot to calibration/journal framing or revise elicitation** |
| G4 (before 1.0) | External crypto review + pen-test done, no open High findings; conformance suite green on ≥ 2 independent implementations | Block release |

## 5. Engineering quality gates (every PR)
Format/lint clean · all tests · property tests · fuzz smoke (60 s per target) · cross-language vector verification · dependency policy (`cargo deny`, `cargo vet`) · docs build · privacy-conformance suite.

## 6. Benchmark suite (`bench/`)
`bench/conformance` (vectors runner) · `bench/perf` (criterion: validate/store/recon/retrieval) · `bench/synth` (synthetic case generators with controllable ground truth, for plumbing/perf/scoring tests) · `bench/study` (S1 analysis code, pre-registered notebooks) · `bench/adversarial` (prompt-injection corpora, poisoned-case scenarios).

## 7. Open research questions
| ID | Question |
|---|---|
| Q-001 | Does elicited reasoning improve held-out prediction (H1)? |
| Q-002 | Is calibration domain-specific, or does it transfer across domains/templates? |
| Q-003 | Optimal interruption policy (value of information vs. fatigue)? |
| Q-004 | Can we prove aggregate calibration statistics in zero knowledge without revealing cases? |
| Q-005 | Sybil resistance and fair weighting in Canons without central identity |
| Q-006 | Influence attribution and privacy for fine-tuned/adapter models |
| Q-007 | Governance and consent models for community-owned knowledge (co-design with communities) |
| Q-008 | Practical timeline for hybrid post-quantum suites in the Rust ecosystem |
| Q-009 | Duress/coercion protections (plausible-deniability profiles) |
| Q-010 | Legal discoverability and privilege for judgment records across jurisdictions |
| Q-011 | Do agent-authored decisions (AI practitioners) belong in the same calibration framework? |
| Q-012 | Should `Value::Link` (a CID appearing where `content` embeds one, e.g. `amend-body.target`) be explicitly rejected if it appears in a strict CDDL `value`-grammar position instead (`signal.value`, `situation.context` entries, which exclude `cid`)? Unenforced today because nothing validates domain-pack signals before M2; see `praxis_types::value`'s module docs. |
