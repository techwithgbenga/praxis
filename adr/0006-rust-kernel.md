# ADR-0006: Rust trust kernel; Python apprentice in a separate process
**Status:** Accepted · **Date:** 2026-10-28

## Context
The kernel parses hostile input and handles keys; the apprentice needs the Python ML ecosystem and may call model weights or remote providers.

## Decision
Rust for the kernel and all trust-critical code. Apprentice is an isolated Python process behind gRPC/UDS; its outputs are untrusted advice, validated by the kernel (provenance verified, distributions normalized).

## Consequences
Strong isolation and memory safety where it matters; ML iteration speed where it matters. Cost: IPC boundary and two toolchains.
