# SPDX-License-Identifier: Apache-2.0
"""Praxis apprentice runtime (docs/APPRENTICE.md).

A separate process (gRPC over a Unix domain socket / named pipe) so ML
dependencies and model weights never enter the Rust trust kernel
(docs/ARCHITECTURE.md §6-7, ADR-0006). Its outputs are untrusted advice: the
kernel validates distributions and verifies every citation before use.

Implements `Predict`, `Consult`, `Embed`, `Build`, `ExtractFeatures`, `Health`
(docs/APPRENTICE.md §1) starting at M4-02.
"""

__version__ = "0.1.0"
