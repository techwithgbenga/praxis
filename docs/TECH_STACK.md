# Technology Stack & Decisions

Selection criteria: **(1)** memory safety for parsers of hostile data, **(2)** runs everywhere (desktop, server, browser/WASM, mobile via FFI), **(3)** long-term maintainability by a community, **(4)** mature, audited crypto, **(5)** no vendor lock-in, **(6)** boring where trust matters.

## 1. Stack

| Layer | Choice | Rationale |
|---|---|---|
| **Core language** | **Rust** (stable) | Memory safety for untrusted parsing; WASM + FFI; strong crypto ecosystem; single reference implementation reused everywhere |
| Encoding | **dag-cbor** via `serde_ipld_dagcbor`, `cid`, `multihash` | Deterministic, IPLD-compatible, widely implemented |
| Hash | **BLAKE3** (`blake3`), Bao (`bao-tree`) for streaming verification | Speed, tree-hash for large blobs |
| Signatures | **Ed25519** (`ed25519-dalek` v2+, strict verification) | Deterministic, ubiquitous |
| AEAD / KDF / KEM | `chacha20poly1305` (XChaCha), `hkdf`+`sha2`, `hpke` (RFC 9180) | RustCrypto/IETF-standard; avoid bespoke constructions |
| Key at rest | OS keychain via `keyring`; passphrase fallback with **Argon2id** (`argon2`); hardware keys via FIDO2/PIV (`ctap-hid-fido2` / `yubikey`) | Standard options |
| Secret recovery | Shamir (`vsss-rs` or equivalent audited) | Social recovery |
| PQ readiness | `ml-kem`, `ml-dsa` crates *when audited*; suite `pxs2` hybrid | v1.0 gate |
| Local store | **SQLite** (`rusqlite`, bundled) + FTS5 + **sqlite-vec** | Ubiquitous, durable, single file, 20-year readability |
| Policy | **Cedar** (`cedar-policy`) | Analyzable, formally-backed authorization language |
| Resolution expressions | **CEL** (`cel-interpreter`/`cel-rust`) | Non-Turing-complete, bounded, widely implemented |
| Sync | **PSP/1**: HTTPS + WebSocket (`axum`, `tokio`, `tungstenite`); later libp2p | Simple, firewall-friendly |
| Relay server | **Rust (axum)**, storage: SQLite for small, **PostgreSQL** + S3-compatible blob store for large | Operability |
| Local RPC | **gRPC (`tonic`) over Unix domain sockets** / named pipes | Typed, cross-language (Python apprentice) |
| Agent integration | **MCP server** (Rust `rmcp` or TS SDK) | Standard for AI agent tooling |
| Apprentice runtime | **Python 3.12+** (`uv`, `ruff`, `mypy --strict`), models via `llama.cpp`/Ollama/vLLM adapters; embeddings via ONNX Runtime | ML ecosystem lives here; isolated process |
| Desktop app | **Tauri 2** + **TypeScript** + **React** (or SolidJS) + Tailwind | Small footprint, Rust backend shares core, security model |
| TS SDK | wasm-bindgen build of core + typed wrappers; **independent pure-TS verifier** for cross-checking | Second implementation guards against spec drift |
| TS verifier crypto | `@noble/hashes` (BLAKE3), `@noble/curves` (Ed25519), `@noble/ciphers` (XChaCha20-Poly1305) | Pure TS/JS, no WASM (the verifier's whole point is to be a *second*, independently-built implementation — see row above); zero runtime dependencies; audited, widely deployed (MetaMask and other major wallets); maintained by the same author across all three, keeping the API style consistent. `@noble/hashes` also supplies HKDF-SHA256 directly (no separate package needed). |
| Python SDK | PyO3 (`maturin`) | ML community |
| Mobile (later) | UniFFI (Swift/Kotlin) | Reuse core |
| Docs | **mdBook**; CDDL lint (`cddl` crate); spec rendered to site | |
| Build/CI | **just**, GitHub Actions, `cargo-deny`, `cargo-audit`, **`cargo-vet`**, `cargo-fuzz`, `proptest`, `criterion`, `cargo-dist` for releases | Supply-chain & quality |
| Supply chain | Sigstore signing, SBOM (CycloneDX), SLSA provenance, reproducible builds | NFR-5 |
| Observability (servers only) | OpenTelemetry, **opt-in**, no client telemetry | Privacy |

## 2. Decision: Should we create our own programming language? **No (not now).**
This was weighed seriously (see ADR-0002). Summary:

| Candidate need | Why a *new language* is the wrong tool | What we do instead |
|---|---|---|
| Schema/data definition | CDDL (RFC 8610) already expresses it | CDDL + generated JSON Schema + test vectors |
| Authorization/usage policy | Needs analyzability and a security track record that takes years to earn | **Cedar** |
| Claim resolution rules | Must be bounded and deterministic; mature options exist | **CEL** |
| Domain packs | Must be *data*, not code, to stay safe and governable | YAML/JSON + CEL snippets |
| Core logic | Rust's WASM/FFI reach already covers every target | Rust |

A new language multiplies the attack surface, splits a small community, and delivers no capability these don't. **Revisit if** (a) we need *zero-knowledge proofs of calibration* (Q-004). Even then we'd prove Rust code in an existing zkVM (e.g., RISC Zero / SP1) rather than invent a language, or (b) Cedar/CEL prove insufficient in a documented, specific way.

## 3. Build vs adopt: protocol layer
We borrow primitives, not platforms: **CID/IPLD** (content addressing), **DIDs** (identity shape), **Negentropy-style range reconciliation** (sync), **HPKE** (key wrapping), **Sigstore/CT-style transparency logs** (registry, Phase 3).
We do **not** adopt IPFS (public-by-default retrieval, privacy model mismatch), Nostr (event model lacks case lifecycle, weak identity continuity), AT Protocol (heavier, repo-centric), or blockchains (cost, privacy, no need; anchoring via TSAs/OpenTimestamps suffices). See ADR-0005.

## 4. Version policy
Rust: latest stable minus 0 (pinned in `rust-toolchain.toml`, bumped monthly). MSRV documented per crate. Python ≥ 3.12. Node ≥ 22 LTS (for TS SDK/desktop build). Dependencies pinned by lockfiles; updates via Renovate with `cargo-vet` review for new crypto/parsing deps.

## 5. Performance targets (reference hardware: 4-core laptop, NVMe)
- Validate+store 10k objects/s sustained (batched). Range-reconcile 1M-object sets with 1k diffs in < 2 s over LAN. Embedding + retrieval for 100k cases < 150 ms p95.
