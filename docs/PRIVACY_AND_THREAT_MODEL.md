# Privacy & Threat Model

*Honesty clause: this document lists what Praxis does **not** protect against as prominently as what it does.*

## 1. Assets
A1 Practitioner's private keys · A2 Plaintext case bodies (situations, reasoning, elicitation answers) · A3 Calibration history · A4 Lineage graph (who learned from whom) · A5 Integrity of the record (no forgery/backdating) · A6 Apprentice outputs' integrity · A7 Availability of data (longevity).

## 2. Actors
Practitioner (owner) · Employer/org · Co-workers · Relay/registry operators · Network attacker · Malicious canon contributor · Sybil attacker · Curious researcher · Lawyer/regulator (discovery) · Malware on device · Supply-chain attacker · Model provider (if remote used).

## 3. Threats and mitigations

| # | Threat | Impact | Mitigation | Residual risk |
|---|---|---|---|---|
| T1 | **Employer uses Praxis to rank/discipline staff** | Chilling effect; destroys trust | Local-first; keys owned by practitioner; no org-visible dashboards by default; calibration disclosure only via signed, practitioner-initiated `attest`; `employment_evaluation` fixed-false in policy; hosted ToS ban; trademark gated on privacy-conformance tests | **A coerced practitioner can be forced to disclose.** Law and labor norms matter. Mitigate with org adoption guidelines and public commitments (Q-009) |
| T2 | Relay operator reads content | Confidentiality loss | Bodies sealed (XChaCha20-Poly1305); keys never leave device except HPKE-wrapped to recipients | Relay sees **metadata** (kind, author, case ID, `ts`, size bucket). Padding reduces size leakage; Tor/mixnet transports are future work |
| T3 | Key theft (device malware) | Forgery, decryption | OS keychain/hardware key; device sub-keys with scope+expiry; `id-revoke` with `compromised_since`; Argon2id passphrase fallback | Malware with user privileges can read decrypted data in memory |
| T4 | **Backdating / hindsight forgery** of claims | Fake track record | Anti-hindsight rule C2/C3; hash-linked DAG; **anchors** (relay receipts, RFC 3161, OpenTimestamps); scoring reports anchored fraction | Unanchored claims remain self-asserted |
| T5 | **Cherry-picking** disclosure | Misleading calibration | `attest` must include signed counts of opened/abandoned/retracted/void; claim-coverage reporting; registry continuous registration (Phase 3); ZK research (Q-004) | Determined offline gaming without registration |
| T6 | Sybil/herding in Canons | Manipulated apprentice answers | Per-author weight caps; calibration-based weights requiring verified history; editor-governed inclusion; dissent surfacing | Open problem (Q-005) |
| T7 | **Data poisoning** via malicious cases | Bad advice | Canon editor review; outcome-based reranking; quarantine for new contributors; provenance lets users inspect | Subtle, slow poisoning remains hard to detect |
| T8 | **Prompt injection** via case text | Apprentice manipulated | Data delimiters; no tools in `Consult`; strict output schema; kernel-verified citations; least-privilege apprentice | LLM robustness is imperfect: advisory-only design bounds harm |
| T9 | **Model memorization/extraction** of others' sealed content | Leakage | v0 does no training on others' data; retrieval honors policy; future training requires DP evaluation + manifests | Future risk when training is added |
| T10 | Non-canonical/malformed objects exploit parsers | RCE/DoS | Rust, `forbid(unsafe)`, strict canonical decode, size/depth limits, cargo-fuzz, bounded pending-parent buffer | Library bugs always possible; audits before 1.0 |
| T11 | **Supply-chain compromise** | Total compromise | lockfiles, `cargo-vet`, `cargo-deny`, reproducible builds, Sigstore, SBOM, minimal deps in kernel | Residual |
| T12 | **Legal discoverability** of records (litigation, regulators) | Records of mistakes become evidence | Per-org retention settings; local plaintext auto-expiry with calibration counts retained; guidance to consult counsel; "privileged mode" design (Q-010) | **Real and unresolved in many jurisdictions: do not claim protection** |
| T13 | Coercion / duress | Forced decryption | Future: hidden/duress profile (Q-009) | Not addressed in v0.1 |
| T14 | Re-identification of third parties in case text | Harm to others | On-device PII scrubber before share; `public` visibility requires scrub confirmation; pack guidance to avoid personal data | Scrubbers are imperfect |
| T15 | Harvest-now-decrypt-later (quantum) | Future confidentiality loss of archives | Suite agility; **hybrid ML-KEM + X25519 is a v1.0 gate**; guidance to avoid `public` ciphertext of sensitive data until then | Pre-v1 archives remain exposed |
| T16 | Social inference from lineage graph | Reveals mentorship/org structure | `derive` is opt-in; graph edges can be sealed to recipients; relay sees only what is public | Graph metadata may leak via timing |
| T17 | Elicitation as manipulation (dark patterns) | Harm to user autonomy | Anti-dark-pattern rules; transparency ("why am I asked?"); user-editable thresholds | Needs ongoing UX review |

## 4. Metadata visible to a relay (explicit)
Object kind, author DID, case ID, `ts`, parent links, size bucket, and (for public cases) content. **Not** body content, option choices, claims, or reasoning for sealed objects.

## 5. Privacy conformance tests (part of CI and trademark)
1. No plaintext in logs, panics, crash dumps. 2. Sealed objects never serialized unsealed to disk except in the explicitly-decrypted local FTS/vec indexes (which are encrypted at rest under a key derived from the root). 3. Policy `forbid` rules cannot be bypassed by configuration. 4. Revoked/retracted cases excluded from new builds. 5. Export contains no data the user didn't scope. 6. No outbound network calls without explicit user action (verified by network-sandbox test).

## 6. Local data-at-rest
SQLite file is *not* encrypted by default for performance/portability, but **sensitive tables (`fts`, `vec`, plaintext caches) are encrypted** (SQLCipher-compatible build option; default on for desktop). Sealed objects are already ciphertext. Users should also use OS full-disk encryption.

## 7. Security process
See `SECURITY.md`. External cryptography review and a penetration test are **gates for v1.0** (not optional).
