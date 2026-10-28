# ADR-0007: Split licensing; ethics via architecture, trademark, ToS
**Status:** Accepted · **Date:** 2026-10-28

## Context
Maximizing adoption favors permissive licenses; preventing closed hosted forks of servers favors copyleft. Ethical-use license clauses are non-OSI and unenforceable at scale.

## Decision
Spec text CC-BY-4.0; libraries/CLI/SDKs/schemas Apache-2.0; servers AGPL-3.0-or-later. Ethics enforced by architecture (owner-held keys, sealing, per-case policy), conformance-gated trademark, and hosted-service terms.

## Consequences
OSI-compliant and adoptable; ethical guarantees depend primarily on design, which is auditable. See LICENSING.md.
