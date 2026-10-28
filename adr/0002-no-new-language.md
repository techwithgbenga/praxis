# ADR-0002: No new programming language; adopt CDDL + Cedar + CEL
**Status:** Accepted · **Date:** 2026-10-28

## Context
The project brief invited creating a new language if it were the best option. The only candidate needs are: data schemas, authorization/usage policy, claim-resolution rules, and domain definitions. Each has an existing, mature, non-Turing-complete, security-analyzed tool. A new language multiplies attack surface, fragments a small community, and requires years to earn trust.

## Decision
Use **CDDL** (RFC 8610) for schemas, **Cedar** for authorization/usage policy, **CEL** for claim resolution, and **YAML/JSON data** for domain packs. Core in **Rust**. Revisit only if (a) zero-knowledge calibration proofs need a circuit language (prefer proving Rust in an existing zkVM) or (b) Cedar/CEL fail in a documented, specific way.

## Consequences
Faster delivery, stronger security posture, easier contributor onboarding. We accept dependence on Cedar/CEL implementations and their release cadence; interfaces are kept narrow to allow replacement.
