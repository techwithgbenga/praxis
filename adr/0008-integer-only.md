# ADR-0008: Integer-only signed encodings (no floats)
**Status:** Accepted · **Date:** 2026-10-28

## Context
Floating-point has multiple encodings, NaNs, and cross-platform differences that break canonical hashing and signatures.

## Decision
No floats in any signed object. Probabilities are ppm integers; surprise in milli-nats; timestamps in ms; decimals as {m,e}. Scoring functions may use IEEE-754 internally but inputs/outputs are fixed-point with specified tolerances.

## Consequences
Deterministic IDs and signatures across languages. Slight ergonomic cost, hidden by SDKs.
