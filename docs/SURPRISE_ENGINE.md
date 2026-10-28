# The Surprise Engine

*The mechanism that turns tacit judgment into speakable observation, without exhausting the person.*

## 1. Principle
A model of the practitioner predicts their choice **before** they make it. **Surprise** (how improbable the choice was under that model) × **stakes** (how consequential the decision was) = **value of asking**. Ask only when that value is high, the person is free, and the budget allows.

## 2. Definitions
- `q(o | s)`: apprentice's *calibrated* distribution over options given situation `s` (committed in `prediction`).
- Chosen option `c`. **Surprise** `S = −ln q(c|s)` nats (stored as `mnat`).
- **Stakes weight** `w ∈ [0,1]` from the stakes record: `w = clamp(a·impact/5 + b·irreversibility + c·1[time_pressure≥minutes])`, defaults `a=.5, b=.3, c=.2`; pack-overridable.
- **Trigger score** `T = S · w`.

## 3. Gating (all must hold)
1. `T ≥ τ_u` (per-user adaptive threshold, §5).
2. Predictor is **calibrated enough**: apprentice's held-out ECE below a bound; otherwise surprise is inflated and we raise `τ_u`.
3. Budget: `used_today < cap_today` (default cap 3/day), min spacing 20 min.
4. **Timing:** never during `time_pressure ∈ {seconds, minutes}`; defer until (a) outcome recorded, (b) user idle/calm signal, or (c) `+cooldown` (default 2 h). Value decays with delay (recall degrades): `value(t) = T · 2^(−Δt/48h)`. Drop when below floor.
5. Not previously declined for this case; at most 1 elicitation per case unless the user opts in.

## 4. Cold start
n < 20 cases in a domain: `q` = pack prior blended with zero-shot model; ask only for the top quartile of `T` and keep `cap_today = 1`. Tell the user why ("I'm still learning your style").

## 5. Adaptive threshold
Target response-rate `r*` (default 50%) and cap. Update `τ_u` by stochastic approximation: raise when the user declines/skips, lower when answers are provided and later show positive Reasoning Utility. **Declines are never penalized** (ETHICS §1.6); they only inform timing/quantity, never inference about the person.

## 6. Question generation (contrastive, observation-first)
1. **Contrast set.** Retrieve nearest past cases (this practitioner + permitted lineage) where the *predicted* option was chosen. Diff `situation.signals`/`context` against the current case → candidate **observations** that differ.
2. **Compose choices (3–5):** top-k differing observations (phrased as *what you may have noticed*), plus *"Something else (say it)"*, *"Just a hunch"*, *"Skip"*.
3. **Decoy.** Include one plausible but irrelevant observation (drawn from the contrast set with low model-estimated relevance). If a user selects decoys at an elevated rate over time, **down-weight their selections** (acquiescence bias estimate).
4. **Order randomization.** Avoid position effects.
5. **Wording:** observation before theory ("What did you notice?" > "Why did you do that?"), because retrospective *theorizing* is where confabulation lives (Nisbett & Wilson, 1977); *noticing* is more reliable.
6. **Blind mode (A/B in the study):** optionally omit the model's prediction from the prompt to avoid anchoring the explanation to the model's frame.
7. Free text ≤ 30 s (voice or text). Stored sealed. A derived structured extraction (tags, features) is stored separately and **flagged derived**.

## 7. Reasoning Utility (RU): does an answer actually help?
For elicitation `e` on case `c` (cross-fitted, so `e` never informs its own evaluation):
`RU(e) = Σ_{held-out cases d similar to c} [ log q_with(e)(chosen_d | s_d) − log q_without(e)(chosen_d | s_d) ]` (normalized per case).
- Aggregated per **question template**, per **practitioner**, per **domain**.
- Used to (i) weight retrieval of reasoning, (ii) run a Thompson-sampling bandit over templates (reward = RU + small bonus for response and brevity, minus latency), (iii) flag confabulation-prone templates.
- RU is also the **primary scientific measurement** (EVALUATION.md H1).

## 8. Anti-dark-pattern rules (hard requirements)
No streaks, badges, countdowns, or guilt copy. No re-asking declined questions. A visible "why am I being asked?" explanation (shows S, w, and that the apprentice expected X). One-tap **"ask me less"** and **"pause for N days"**. All thresholds user-visible and editable.

## 9. Interfaces
```
trait ElicitationPolicy {
  fn score(&self, pred: &Prediction, chosen: &str, stakes: &Stakes) -> Trigger;      // S, w, T
  fn decide(&self, t: &Trigger, ctx: &UserCtx) -> Decision;                          // Enqueue|Drop|Defer(until)
  fn on_feedback(&mut self, fb: Feedback);                                           // adjust τ_u
}
```
Pure and deterministic given inputs and a seeded RNG: fully unit-testable.

## 10. Failure modes & mitigations
| Failure | Mitigation |
|---|---|
| Confabulation | observation-first prompts, decoys, RU-weighting, evaluation gate H1 |
| Anchoring on the model's guess | blind mode, show contrast only after decision recorded |
| Interruption fatigue | budget, timing, adaptive τ, user controls |
| Miscalibrated predictor inflates surprise | calibration layer + gating on predictor ECE |
| Gaming (answering to please) | decoy-based acquiescence estimate; no rewards for answering |
