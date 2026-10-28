# ADR-0003: Immutable signed object DAG; no mutable pointers
**Status:** Accepted · **Date:** 2026-10-28

## Context
Git-like mutable refs introduce coordination, conflict, and trust problems. Judgment records must be tamper-evident and offline-first; sync must be simple for dumb relays.

## Decision
All state is a set of immutable, signed, content-addressed objects linked by causal parents. Replication = set reconciliation. Current state is a pure function of the set (event sourcing).

## Consequences
Simple relays, easy verification, trivially cacheable, resilient offline. Deletion is impossible at the protocol level; consent withdrawal is modelled via `retract` tombstones and policy, with honest limits documented.
