# Usage Policy (Cedar) & Resolution Criteria (CEL)

Praxis **does not invent a language**. It uses two existing, safe, non-Turing-complete languages for the two places a rule language is needed.

## 1. Two layers of policy
1. **Portable usage terms**: the structured `usage` field on each case (CDDL). Travels with the data; machine-checkable by any client.
2. **Authorization rules**: [Cedar](https://www.cedarpolicy.com/) policies evaluated by clients and services to decide *whether a specific request may proceed* (read, train, publish, export). Cedar gives analyzable, formally verifiable policy semantics.

## 2. Cedar entity model (v0.1)
```
Practitioner  (id: did)                 attrs: domains: Set<String>
Case          (id: cid)                 attrs: owner: Practitioner, domain: String, usage: Record, stakes: Record
Canon         (id: canonId)             attrs: editors: Set<Practitioner>
Action: Read, Retrieve, Train, PublishCalibration, Export, Grant
Context: purpose: String, requester_role: String, build_id?: String
```

## 3. Baseline policy (shipped, immutable defaults)
```cedar
// Owner can always read/export their own cases.
permit(principal, action in [Action::"Read", Action::"Export"], resource)
  when { resource.owner == principal };

// Retrieval by others only if the case's usage.retrieval permits and a grant/canon membership exists.
permit(principal, action == Action::"Retrieve", resource)
  when { resource.usage.retrieval != "none" &&
         (resource.usage.retrieval == "public" || principal in resource.grantees) };

// Training only if explicitly allowed for the requested scope.
permit(principal, action == Action::"Train", resource)
  when { resource.usage.training != "none" && context.purpose == "model-build" };

// HARD FORBID: employment evaluation is never permitted, regardless of other policies.
forbid(principal, action, resource)
  when { context.purpose == "employment-evaluation" };

// Retracted cases are never used in new builds or publications.
forbid(principal, action in [Action::"Train", Action::"PublishCalibration", Action::"Retrieve"], resource)
  when { resource.retracted == true && resource.owner != principal };
```
`forbid` overrides `permit` in Cedar semantics, which is exactly the property wanted for the ethics rules. Services MUST ship the baseline `forbid` rules compiled in; operators may *add* forbids but not remove them (conformance L4).

**Honest limit:** `context.purpose` is asserted by the caller. Enforcement is by (a) compliant clients/services, (b) not issuing wrapped keys for non-permitted purposes, (c) audit logs on official services, (d) conformance-gated trademark. It is not a cryptographic guarantee against a determined malicious holder of plaintext.

## 4. Resolution criteria: CEL
[CEL](https://cel.dev) expressions resolve machine-checkable claims. Properties we rely on: no loops, no side effects, bounded cost, deterministic, with mature Rust/Go/Java implementations.

**Environment** (read-only):
- `obs.<name>`: *observation snapshots* captured as evidence blobs (time-stamped series, e.g. `obs.replica_lag_s`).
- `t`: resolution time (ms); `t_open`: case `open` timestamp; `t_action`: `decision` timestamp; `claim.horizon`.
- Helper functions (whitelisted): `max(series, from, to)`, `min(...)`, `mean(...)`, `at(series, t)` (last observation at or before `t`), `last(series)`, `count_where(series, pred)`, `within(a, b, tol)`.

**Examples**
```
// "Replica lag self-resolves within 30 minutes"
obs.replica_lag_s.max(claim.horizon - duration('30m'), claim.horizon) < 5

// "No customer-visible errors above 1% in the next hour"
obs.error_rate_ppm.max(t_open, t_open + duration('1h')) < 10000
```
**Rules**
- Evaluation MUST be time-bounded (default 50 ms) and memory-bounded (default 16 MiB).
- Inputs are **frozen as evidence** at resolution so verifiers can re-run the same expression on the same data.
- If any required observation is missing the result is `void(unobservable)`, never `false`.
- No floats in the *protocol*; CEL may compute with doubles internally but compares against integer-scaled thresholds in the stored expression.

## 5. Extension rule
New policy or expression languages require a PIP. Domain packs may **not** embed arbitrary code; they supply data (templates, vocabularies, CEL snippets) only.
