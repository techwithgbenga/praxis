# PRAXIS

**The open protocol for capturing, verifying, and transmitting expert judgment.**
*Git for judgment: decisions, reasons, outcomes, lineage, and calibrated trust. Owned by practitioners, not platforms.*

> **Status: Pre-alpha / design phase (spec v0.1-draft).** Nothing here is validated yet. The central
> hypothesis (see [docs/EVALUATION.md](docs/EVALUATION.md)) must survive a pre-registered experiment
> before the project claims it works. Contributions that *falsify* parts of the design are as welcome as contributions that extend it.

> **Naming note:** "Praxis" is a common word and already used by other products. `praxis` is a **working name**.
> Do a trademark/namespace search before any public launch (see [TRADEMARK in LICENSING.md](LICENSING.md#trademark)).

---

## The problem

Humanity built superb systems for *explicit* knowledge: writing, the web, language models. The most valuable
expertise (what Aristotle called *phronesis*, what Polanyi called "tacit knowledge") is **judgment**:
knowing which signal to distrust, when to break the protocol, when to wait. It dies when the expert retires,
and AI trained on what humans *wrote* mostly misses it.

## The idea

Tacit knowledge becomes speakable at the moment an expert **surprises a model that was watching them**.

1. A **Case** records a decision *as it happens*: situation, options, choice, stated confidence, and
   machine-checkable **claims** about what will happen, registered *before* the outcome is known.
2. A local **apprentice** predicts the practitioner's choice. When the practitioner does something
   surprising *and* consequential, a short, well-timed question elicits what they noticed.
3. Cases are later **closed** with outcomes. Claims resolve; **calibration** (not titles) accrues per domain.
4. **Lineage**: students fork teachers' judgment where they diverge; communities merge views into **Canons**
   that preserve dissent.
5. **Consultable apprentices** answer with provenance: *"descends from 212 cases by 14 practitioners,
   calibration 0.81 in this domain, 3 dissenting lineages."*

## Principles (non-negotiable)

1. **Local-first, practitioner-owned.** Your keys, your data, your export, your exit.
2. **Useful at n=1.** A personal decision journal that makes *you* better must work before any network exists.
3. **Trust is verifiable.** Signatures, content addressing, pre-registered claims, auditable scoring.
4. **Dissent is a feature.** The protocol preserves minority judgment; it never averages it away.
5. **Not a surveillance tool.** Enforced by architecture first, license/trademark second. See [ETHICS.md](ETHICS.md).
6. **Boring cryptography, boring storage, boring sync.** Novelty only where the idea is novel.

## Repository map

| Path | Contents |
|---|---|
| [`AGENTS.md`](AGENTS.md) | **Start here if you are an AI agent implementing this project.** |
| [`docs/VISION.md`](docs/VISION.md) | Why, history, civilizational framing |
| [`docs/PRODUCT_SPEC.md`](docs/PRODUCT_SPEC.md) | Personas, requirements, UX, metrics |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | System design, components, data flow |
| [`docs/TECH_STACK.md`](docs/TECH_STACK.md) | Stack, rationale, rejected alternatives, the "own language?" decision |
| [`spec/PROTOCOL.md`](spec/PROTOCOL.md) | **Normative** protocol v0.1 (objects, IDs, signing, sealing, sync) |
| [`spec/praxis-v0.1.cddl`](spec/praxis-v0.1.cddl) | **Normative** schemas |
| [`spec/SCORING.md`](spec/SCORING.md) | **Normative** calibration & scoring |
| [`spec/POLICY.md`](spec/POLICY.md) | Usage policy (Cedar) & resolution criteria (CEL) |
| [`docs/SURPRISE_ENGINE.md`](docs/SURPRISE_ENGINE.md) | The elicitation algorithm |
| [`docs/APPRENTICE.md`](docs/APPRENTICE.md) | Apprentice runtime, provenance, dissent |
| [`docs/PRIVACY_AND_THREAT_MODEL.md`](docs/PRIVACY_AND_THREAT_MODEL.md) | Threats, mitigations, honest limits |
| [`docs/EVALUATION.md`](docs/EVALUATION.md) | The falsifiable experiment and quality gates |
| [`docs/DOMAIN_PACKS.md`](docs/DOMAIN_PACKS.md) | How domains plug in |
| [`docs/CLI_AND_API.md`](docs/CLI_AND_API.md) | CLI, local API, MCP, SDK surface |
| [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md) | Milestones & tasks with acceptance criteria |
| [`docs/GLOSSARY.md`](docs/GLOSSARY.md) | Terms |
| [`adr/`](adr/) | Architecture Decision Records |
| [`GOVERNANCE.md`](GOVERNANCE.md), [`CONTRIBUTING.md`](CONTRIBUTING.md), [`SECURITY.md`](SECURITY.md), [`ETHICS.md`](ETHICS.md), [`LICENSING.md`](LICENSING.md), [`ROADMAP.md`](ROADMAP.md) | Project governance |

## Quickstart (target UX; not implemented yet)

```bash
praxis init                                   # create identity + local store (no account, no network)
praxis open --domain incident-response        # 30-second case capture
praxis decide <case> --chose "wait 10m" \
  --claim "self-resolves within 30m" --p 0.70 --resolve-by +30m
praxis close <case>                           # resolve claims, update calibration
praxis calibration --domain incident-response # your reliability curve, with honest uncertainty
praxis ask "replica lag 40s, no alert fired"  # consult your apprentice (with provenance + dissent)
```

## Getting the code on GitHub

This repository was authored offline; no remote exists yet. See [`scripts/publish.sh`](scripts/publish.sh).
Canonical URL after publishing: `https://github.com/techwithgbenga/praxis`.

## License

Spec text: CC-BY-4.0 · Protocol libraries, CLI, SDKs, schemas: Apache-2.0 · Servers (relay, registry): AGPL-3.0-or-later.
Details and rationale in [LICENSING.md](LICENSING.md).
