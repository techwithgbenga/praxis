# ADR-0005: Build a minimal protocol; borrow primitives, not platforms
**Status:** Accepted · **Date:** 2026-10-28

## Context
IPFS, Nostr, AT Protocol, and blockchains each solve adjacent problems. None provides case lifecycle rules, pre-registered claims, identity continuity with device scoping, and a privacy model suited to private-by-default judgment records.

## Decision
Define a small purpose-built protocol that borrows proven primitives: CID/IPLD, DID-shaped identity, HPKE, Negentropy-style range reconciliation, TSA/OpenTimestamps anchors, and transparency logs (registry).

## Consequences
We own the protocol's evolution and its ethics guarantees; we accept the cost of writing a spec and two implementations.
