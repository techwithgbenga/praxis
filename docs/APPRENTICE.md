# Apprentice Runtime

An **apprentice** is a consultable model of a lineage (a practitioner, a team, or a Canon). It *advises with provenance*; it never acts.

## 1. Interface (gRPC over UDS; `proto/apprentice.proto`)
```
Predict(PredictRequest{situation, option_set, scope}) -> Distribution{options[{option,p_ppm}], model_ref, support}
Consult(ConsultRequest{query, situation?, scope})    -> Answer{distribution, claims[], provenance[], dissent[], abstained, caveats[]}
Embed(texts)                                          -> vectors
Build(BuildRequest{scope, case_ids, policy_ctx})      -> BuildManifest   // index/adapter build; emits signed manifest
ExtractFeatures(text, pack)                           -> tags (derived, flagged)
Health()                                              -> status, model digests
```
**Scope** = `{self | team:<id> | canon:<id>@ver | lineage:<did>}`; the kernel resolves permitted case IDs *before* calling the apprentice (the apprentice never sees data the policy forbids).

## 2. v0 design: Case-Based Reasoning, not fine-tuning
Retrieval-and-reasoning over cases gives **provenance by construction**. Training-based attribution is an open research problem (Q-006), so v0 avoids it.

Pipeline for `Consult`:
1. **Normalize** the situation into the pack's schema (LLM extraction; validated against pack vocabulary; user-confirmable).
2. **Retrieve** K cases per scope: hybrid BM25 + dense embeddings + structured filter (domain, stakes), then a learned/heuristic **reranker** that up-weights cases with (a) similar signals, (b) closed outcomes, (c) high contributor calibration in this domain, (d) high Reasoning Utility elicitations.
3. **Condition a language model** with the retrieved cases (treated strictly as *data* inside delimiters; see §6) to produce a **structured** distribution over options plus cited rationale.
4. **Calibrate** the distribution with a held-out-fitted calibrator (temperature scaling / isotonic) per domain; track the calibrator's own ECE.
5. **Compose the answer** with provenance and dissent (§3–4); **abstain** if support is thin (§5).

`Predict` = steps 1–4 only (no prose), optimized for latency (target < 1.5 s local, cached embeddings).

## 3. Provenance format
```json
{
  "answer_id": "…",
  "distribution": [{"option":"wait","p_ppm":520000},{"option":"failover","p_ppm":410000}],
  "support": {"n_cases": 212, "n_authors": 14, "n_closed": 171, "domain": "incident-response@0.1"},
  "claims": [
    {"text": "Lag patterns that match scheduled backups usually self-resolve.",
     "cases": ["bafy…","bafy…"], "grounded": true}
  ],
  "contributors": [{"did":"did:praxis:…","weight_ppm":140000,"calibration":{"label":"established","bss_ppm":310000}}],
  "dissent": [{"option":"failover","n_authors":3,"n_cases":29,"outcome_rate":{"claim_template":"service-recovers","ppm":640000},"cases":["bafy…"]}],
  "abstained": false,
  "caveats": ["Calibration reflects stated confidence, not causal skill.", "3 dissenting lineages."]
}
```
**Rule:** every `claims[].text` has ≥ 1 case CID or `"grounded": false` and renders as *ungrounded*. The kernel **verifies** every cited CID exists, is permitted for this requester, and is in scope; invalid citations are stripped and the answer flagged.

## 4. Dissent and anti-monoculture
- Group retrieved cases by **chosen option**. A group is surfaced as **dissent** if it has ≥ 3 distinct authors *or* ≥ 10% of weight.
- **Weight per author is capped** (default ≤ 20% of total) so no single voice (or Sybil cluster) dominates.
- Contributor weight = f(domain calibration label, closed-outcome count, recency), *not* seniority or title; new identities start low. Sybil resistance beyond this is open (Q-005); canon editors/inclusion policy are the primary defense in v0.
- Always show outcome rates per option where outcomes exist.

## 5. Abstention
Abstain ("insufficient precedent") when any: `n_cases < n_min` (default 5), top-k similarity below threshold, retrieved cases lack closed outcomes, or predictor/calibrator ECE exceeds bound. An abstention still shows the nearest cases. *Saying "I don't know" is a feature.*

## 6. Safety
- **Prompt-injection hygiene:** case text is untrusted. It is passed inside clearly delimited data blocks; the model has **no tools** in `Consult`; output is parsed to a strict schema; citations verified by the kernel.
- **No autonomous actions.** The apprentice has no write path to the kernel except through explicit user-confirmed drafts.
- **Memorization/leakage:** v0 doesn't fine-tune on others' sealed data. Any future adapter training requires policy `training` permission, a build manifest, DP-SGD evaluation, and extraction-attack testing (Q-006).
- **Model supply chain:** model digests pinned and recorded in `prediction.model`; only user-approved models; default **local**; remote calls require explicit opt-in and a visible data-egress notice.

## 7. Model-agnostic layer
Adapters: `llama.cpp`/Ollama (local), `vLLM` (self-hosted), and remote providers behind opt-in. Required capabilities: JSON/structured output, logprobs *or* a calibrated sampling fallback. The kernel records `model.id` + `digest` so predictions are auditable and reproducible.

## 8. Evaluation hooks
`praxis-bench` replays held-out decisions: top-1, log-loss, calibration (ECE), abstention quality (selective-risk curves), provenance validity rate (must be 100% after kernel verification), and RU per elicitation template. See EVALUATION.md.
