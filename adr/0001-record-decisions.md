# ADR-0001: Record decisions as ADRs
**Status:** Accepted · **Date:** 2026-10-28

## Context
A long-lived, community-governed protocol needs a durable memory of *why* choices were made, so future maintainers do not relitigate or unknowingly reverse them.

## Decision
Significant architectural, protocol, and process decisions are recorded as ADRs in `adr/`. Accepted ADRs are immutable; changes supersede.

## Consequences
Small overhead per decision; much lower onboarding cost; agents and humans share the same rationale.
