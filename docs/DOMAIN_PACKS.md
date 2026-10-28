# Domain Packs

A **domain pack** teaches Praxis a profession without changing the core. A pack is **data**, never code.

## 1. Anatomy (`pack.yaml`, versioned with SemVer)
| Section | Purpose |
|---|---|
| `id`, `version`, `title`, `license` | identity; packs are separately licensed (default CC-BY-4.0 data / Apache-2.0 tooling) |
| `risk_tier` | `low` / `moderate` / `high`. **High** (medicine, law, critical infrastructure) needs domain governance, is **out of scope for v1**, and the CLI refuses to load it without `--i-accept-governance-requirements` + a signed governance manifest |
| `maintainers`, `governance` | who stewards it and how changes are approved |
| `situation_fields` | typed fields (names, types, vocab, required?) mapped into `situation.context` (no floats; decimals as `{m,e}`) |
| `signal_vocabulary` | canonical signal names + units (for retrieval and contrast generation) |
| `situation_types` → `option_sets` | the options a practitioner can choose among, per situation type |
| `stakes_mapping` | how domain facts map to `stakes` and the Surprise Engine's `w` |
| `claim_templates` | scorable claims: statement pattern, default CEL resolution, horizon bounds, `core`, optional `base_rate_ppm` + provenance |
| `elicitation_seeds` | initial question templates (observation-first) |
| `observation_providers` | named observation sources (e.g., Prometheus queries) for CEL resolution |
| `redaction_rules` | PII patterns to scrub before sharing |
| `translations` | vocabulary localization |

## 2. Governance
- Packs live in their own repos or `packs/` with a `CODEOWNERS` of domain stewards.
- Changes are versioned; **minor** = additive; **major** = breaking vocabulary. Cases record `domain: "pack@version"`; old cases stay valid under their pack version.
- Base rates **must cite evidence** (study/telemetry/aggregated consented data) or be left `null`. Never invent base rates.

## 3. Extending: add a pack in 6 steps
1. Copy `packs/_template`. 2. Define situation types/options with 3+ practitioners. 3. Write claim templates with CEL where possible. 4. Add seeds for elicitation. 5. Add 20 synthetic example cases + tests (`praxis pack test`). 6. Submit via PIP-lite (pack proposal issue) and domain steward review.

## 4. Reference pack
[`packs/incident-response/pack.yaml`](../packs/incident-response/pack.yaml): first wedge domain (software incident response / SRE / database operations).
Observation providers there are **abstract** (provider interface only); concrete connectors (Prometheus, Datadog) ship in integrations.

## 5. Why software incident response first
Decisions are already digital and timestamped; outcomes are measurable (recovery, rollback, regression); practitioners are comfortable with open tooling and local-first software; stakes are real yet bounded (not life-critical).
