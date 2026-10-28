# Calibration & Scoring: Normative (v0.1-draft)

Goal: a **reproducible, hard-to-game, honest-about-uncertainty** measure of how well a practitioner's *stated confidence* matches reality, per domain.
All implementations MUST produce identical results on `spec/test-vectors/scoring/*` (integer arithmetic where specified; otherwise IEEE-754 double with the stated order of operations and a tolerance of 1e-9).

## 1. Inputs
A **scored claim** is a claim with: `p_ppm`, a resolved `result ∈ {true,false}` (void excluded), `horizon`, `anchored: bool`, `attributed ∈ {auto,peer,self}`, `domain`, optional `template` (pack claim-template id).
Late claims (`late:true`) and claims in retracted cases (after retraction) are **excluded from scores but counted** (§6).
Let `p = p_ppm / 1e6`, `y = 1` if true else `0`.

## 2. Proper scoring rules
- **Brier:** `BS = mean((p − y)²)` lower is better.
- **Log score:** `LS = mean(−ln(p_y))`, where `p_y = p` if y=1 else `1−p`; probabilities clipped to `[1e-3, 1−1e-3]` before `ln`.
Proper rules make honest reporting optimal. Never use accuracy-at-threshold as a headline metric.

## 3. Skill vs reference
`BSS = 1 − BS / BS_ref`, where `BS_ref` is the Brier of a **reference forecaster** that always states the base rate for that (domain, template):
1. If the pack provides `base_rate_ppm` for the template, use it (community prior).
2. Else use the **leave-one-out empirical base rate** over the practitioner's own scored claims in that (domain, template), Laplace-smoothed: `(k+1)/(n+2)`.
Skill is reported **relative to difficulty**: predicting an easy-to-predict event is not credit.

## 4. Calibration (reliability)
- Sort claims by `p`. Form **adaptive bins** of ≥10 claims each, at most 10 bins (equal-count; ties never split across bins).
- Per bin: mean predicted `p̄`, observed frequency `ȳ`, count, **Wilson 95% interval** for `ȳ`.
- **ECE** = Σ (n_b/N)·|p̄_b − ȳ_b|.
- **Bootstrap CIs** for BS, BSS, ECE: B = 2000 resamples of claims (resample cases, not claims, if any case has multiple claims), PRNG = ChaCha20 seeded with `BLAKE3(sorted claim object IDs)`: **reproducible** across implementations.
- **Murphy decomposition:** `BS = REL − RES + UNC` reported for transparency.
- **Discrimination:** AUC (rank-based, ties averaged) if both classes ≥ 10.
- **Overconfidence index:** `mean(p) − mean(y)` over claims with `p ≥ 0.8` (and mirrored `mean(y) − mean(p)` for `p ≤ 0.2`), reported with n.

## 5. Sample-size honesty
| n scored claims (per domain) | Label | Display rule |
|---|---|---|
| < 30 | `insufficient` | No headline number; show raw reliability points only |
| 30–99 | `provisional` | Show with CIs, no ranking/comparison |
| ≥ 100 | `established` | Full reporting |

Per-template breakdown requires n ≥ 30 *within* the template. Optional empirical-Bayes shrinkage (Beta-Binomial) MAY be shown **alongside** raw values, never instead.

## 6. Selective-reporting accounting (anti-gaming)
Every calibration disclosure MUST include, signed and anchored where possible:
- `n_opened` (cases opened in scope), `n_scored`, `n_void`, `n_abandoned`, `n_retracted`, `n_unanchored`.
- **Claim coverage** = decisions-with-core-claims / decisions in scored domains.
- **Anchored fraction** = anchored scored claims / scored claims.
- **Attribution mix** = share by `auto|peer|self`; stratified scores are reported when each stratum has n ≥ 30.
Thresholds (e.g. "coverage < 80% ⇒ flagged") are display policy, not part of the score.
**Void abuse:** void rate > 25% in a domain is flagged.

## 7. Domain-pack requirements for scorable claims
A pack MUST define **claim templates** with: statement pattern, default `resolve` (CEL where possible), `horizon` bounds, `base_rate_ppm` (optional, with provenance), and which claims are `core`. This both enables fair skill baselines and limits "pick easy claims" gaming.

## 8. Causality caveat (displayed, not computed away)
Claims are **conditional on the chosen action** ("if I do X, then Y with probability p"). Outcomes can be confounded by other events. `outcome.confounders` is recorded; scores are *evidence about calibration*, never proof of causal skill. UIs MUST show the caveat on any shared calibration view.

## 9. Worked example (golden vector `scoring/basic-001`)
Claims `(p, y)`: (0.9,1), (0.8,1), (0.7,0), (0.6,1), (0.3,0); reference base rate 0.6 (from pack).
- Brier terms: 0.01, 0.04, 0.49, 0.16, 0.09 → **BS = 0.158**
- `BS_ref` = mean((0.6−y)²) = (3·0.16 + 2·0.36)/5 = **0.24** → **BSS = 0.341667**
- Log score terms: 0.105361, 0.223144, 1.203973, 0.510826, 0.356675 → **LS = 0.479995**
(n=5 ⇒ label `insufficient`; the example only checks arithmetic.)

## 10. What this score is not
Not a ranking of people. Not a hiring signal. Not a measure of being right. See ETHICS.md.
