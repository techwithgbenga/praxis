# Product Specification (PRD)

*Version 0.1-draft. Requirement IDs are stable; reference them in tests and PRs.*

## 1. Product statement
Praxis helps a practitioner **make better decisions and leave a verifiable record of their judgment**, starting as a private journal with calibration feedback, growing into a network of lineages and canons, without ever surrendering ownership.

## 2. Personas
| Persona | Description | Job to be done |
|---|---|---|
| **Ana, senior SRE** (primary, wedge) | 10+ yrs, on-call, makes high-stakes calls in minutes | "Log my calls cheaply, see if my confidence is trustworthy, and pass on what I know before I leave." |
| **Ravi, junior engineer** | 2 yrs, wants to grow faster | "Learn how seniors actually decide, not just what the runbook says." |
| **Maya, engineering manager** | leads on-call rotation | "Onboard people faster and preserve team judgment, without surveilling anyone." |
| **Dr. Okafor, domain steward** | maintains a Canon/pack | "Curate high-quality judgment with dissent, provenance, and governance." |
| **Sam, researcher** | studies expertise | "Open, consented data and a reproducible evaluation harness." |
| **Agent-builder** | integrates AI agents | "Give my AI agent a consultable apprentice and let it log its own decisions transparently." |

## 3. Product goals / non-goals
**Goals:** (G1) value at n=1; (G2) <30 s capture at decision time; (G3) honest calibration feedback; (G4) interrupts only when valuable; (G5) portable, owner-controlled data; (G6) lineage and canons with provenance and dissent.
**Non-goals (v1):** employee monitoring; medical/legal decision support; autonomous action; social-media-style feeds or gamified streaks; storing non-consenting third parties' personal data.

## 4. Functional requirements

### 4.1 Capture (FR-C)
- **FR-C1** `open` a case in ≤ 30 s via CLI, desktop quick-capture, or MCP/agent. Domain pack supplies prompts/options. *Acceptance:* median ≤ 30 s in usability test; keyboard-only possible.
- **FR-C2** Record decision + ≥1 **claim** with probability and resolution criteria (template-assisted). Claims are immutable after save.
- **FR-C3** **Draft capture:** integrations may propose case drafts from incident timelines (PagerDuty, Slack, GitHub issues). Drafts are never saved or shared without explicit practitioner confirmation.
- **FR-C4** Offline-first: every capture works with no network.
- **FR-C5** Voice capture (local speech-to-text) optional.

### 4.2 Prediction & elicitation (FR-E)
- **FR-E1** Apprentice predicts a distribution over options **before** the decision is saved; the prediction is committed (protocol rule C2).
- **FR-E2** Surprise Engine queues elicitation only when surprise × stakes exceeds a per-user threshold *and* budget remains ([SURPRISE_ENGINE.md](SURPRISE_ENGINE.md)).
- **FR-E3** Elicitation never interrupts during high time-pressure; defers to a calm moment. Always skippable. No streaks, no guilt.
- **FR-E4** Answers are optional structured choices + ≤30 s free text/voice.

### 4.3 Outcomes & calibration (FR-O)
- **FR-O1** Reminders to close cases at claim horizons (gentle, batched, snooze-able).
- **FR-O2** Machine-resolvable claims auto-resolve from frozen observations (CEL).
- **FR-O3** `calibration` view: reliability curve, Brier/BSS, CIs, sample-size labels, coverage/void/abandon stats, causality caveat. Matches [SCORING.md](../spec/SCORING.md) exactly.
- **FR-O4** Personal insights: "you're overconfident when p≥0.8 on X-type claims," with n shown. No grades, no leaderboards.

### 4.4 Consultation (FR-A)
- **FR-A1** `ask` returns: distribution over options, supporting cases with provenance, dissent, calibration of contributors, and an explicit **insufficient-precedent** abstention when support is weak.
- **FR-A2** Every statement in an answer maps to case IDs or is labeled *ungrounded*.
- **FR-A3** Advisory only. The UI states who/what the answer descends from.

### 4.5 Lineage & Canons (FR-L)
- **FR-L1** Share cases by policy (`grant`). **FR-L2** Declare `derive` and `diverge`. **FR-L3** Create/curate Canons with editors and inclusion policy; versioned.
- **FR-L4** "Rebuild without me": a contributor can withdraw and be excluded from subsequent builds.

### 4.6 Data ownership (FR-D)
- **FR-D1** One-command **full export** (open format) and import. **FR-D2** Keys under user control (OS keychain/hardware key); recovery via social/Shamir shares. **FR-D3** No account needed for local use.
- **FR-D4** Retention controls per case (auto-expire local plaintext after N years, keep calibration counts).

### 4.7 Integrations (FR-I)
- MCP server (agents log/consult), GitHub, Slack, PagerDuty/Opsgenie, Prometheus/Grafana observations, VS Code. SDKs: TypeScript, Python.

## 5. Non-functional requirements
| ID | Requirement |
|---|---|
| NFR-1 | Core ops (append, validate, query by case) p95 < 20 ms on a 100k-object local store |
| NFR-2 | `praxis open`+`decide`: cold start < 150 ms to first prompt |
| NFR-3 | Store scales to ≥ 10M objects/relay with range-reconcile sync in O(diff · log N) |
| NFR-4 | Zero plaintext in logs; fuzzed parsers; `forbid(unsafe_code)` outside FFI |
| NFR-5 | Reproducible builds; signed releases (Sigstore); SBOM; SLSA ≥ 3 target |
| NFR-6 | Accessibility: WCAG 2.2 AA for desktop app; full keyboard operation; screen-reader tested |
| NFR-7 | i18n-ready: UTF-8/NFC everywhere; RTL-safe UI; pack vocabularies translatable |
| NFR-8 | Long-term readability: format spec + vectors enable re-implementation in 20 years without our code |
| NFR-9 | Platforms: Linux, macOS, Windows; iOS/Android viewer later |

## 6. UX principles
1. **Quiet by default.** Praxis speaks when it has something valuable to ask.
2. **Never punish.** No red marks for wrong claims; show *calibration*, not *correctness*.
3. **Show uncertainty everywhere.** Counts, intervals, labels.
4. **Provenance on every answer.**
5. **Fast path first.** Power users never touch a mouse.

## 7. Core flows
**Flow A: decision under pressure (≤30 s).**
`praxis open` → pack asks 3 required fields (situation summary, top signals, stakes) → apprentice prediction fetched in background → `decide`: option + 1 core claim with p → saved. *No questions asked during incident.*
**Flow B: elicitation (later, calm).**
Desktop notification (or next CLI invocation): "One quick question about Tuesday's failover call?" → 1–3 contrastive choices + optional voice note → done.
**Flow C: closing.** Horizon reached → auto-resolution or one-tap confirm → calibration updates.
**Flow D: consult.** `ask` → grounded answer with dissent; "show me the dissenting cases".

## 8. Success metrics
| Metric | Target (first 12 mo, to be validated) |
|---|---|
| Time-to-first-value | < 10 min from install to first case logged |
| Capture friction | median case capture ≤ 30 s |
| Weekly active practitioners with ≥ 3 cases in 4 wks | track; no target until baseline |
| Outcome closure rate | ≥ 70% of cases closed or auto-resolved |
| Elicitation response rate | ≥ 40%, with *decline never penalized* |
| **Calibration improvement** (ECE or BSS) in cohort between first and last 30 claims | positive, CI excludes 0 (pre-registered) |
| **Scientific:** H1 in EVALUATION.md | pre-registered threshold |
| Trust: practitioner survey "I would let Praxis hold my judgment" | ≥ 4/5 |
No engagement-maximizing metrics (time in app, streaks) are tracked.

## 9. Risks (product)
| Risk | Mitigation |
|---|---|
| Capture burden kills adoption | n=1 value, template-assisted capture, drafts from timelines, voice |
| Fear of surveillance | local-first, no employer view, ETHICS.md, conformance-gated mark |
| Legal discoverability of records | per-org retention settings, privileged-mode design (Q-010), counsel guidance in docs |
| Confabulated reasoning | decoys, utility-weighting (RU), evaluation gates |
| Cold-start for the network | personal value first; seed Canons by invited masters |
| Goodhart on calibration | proper scoring, coverage/abandon accounting, no leaderboards |
