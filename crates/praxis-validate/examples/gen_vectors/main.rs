#![allow(missing_docs, clippy::all)]
// SPDX-License-Identifier: Apache-2.0
//! Generates `spec/test-vectors/**` (`docs/IMPLEMENTATION_PLAN.md` M1-08):
//! run with `cargo run -p praxis-validate --example gen_vectors`.
//!
//! Scope: `sync/` is not generated — no `praxis-sync` implementation exists
//! yet to produce real RECON transcripts from (M5). `scoring/basic-001` is
//! hand-written (see `scoring.rs`), not generated: `praxis-score` doesn't
//! exist yet either (M3-01); it is SCORING.md §9's worked example transcribed
//! directly, which is exactly what the task plan calls it — a placeholder.

mod canonical;
mod events;
mod identity;
mod scoring;
mod sealing;
mod vector;

fn main() {
    canonical::generate();
    identity::generate();
    events::generate();
    sealing::generate();
    scoring::generate();
    println!("done");
}
