// SPDX-License-Identifier: Apache-2.0
//! C ABI bindings to `praxis-core` for mobile (UniFFI: Swift/Kotlin) and other
//! native embedders (`docs/ARCHITECTURE.md` §3).
//!
//! This is the **one crate in the workspace permitted to use `unsafe`**
//! (`AGENTS.md` §3 `DoD`: "FFI crates isolate and document each `unsafe`"). Every
//! `unsafe` block added here MUST carry a `// SAFETY:` comment explaining why it is
//! sound. `unsafe_code` is intentionally *not* `#![forbid]`'d, unlike every other
//! crate in this workspace.
#![deny(missing_docs)]

// Empty until praxis-core has a surface worth exposing (later milestone; mobile is
// explicitly "later" per docs/ARCHITECTURE.md §Mobile).
