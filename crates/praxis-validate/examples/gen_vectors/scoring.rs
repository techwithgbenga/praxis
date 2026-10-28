// SPDX-License-Identifier: Apache-2.0
//! `scoring/basic-001`: the hand-computed worked example from
//! `spec/SCORING.md` §9 — Brier score, skill-vs-reference (`BSS`), and log
//! score over 5 claims. There is no `praxis-score` crate yet (M1 doesn't
//! build it), so this vector's `expected` values are computed here directly
//! from §2/§3's formulas (not transcribed by hand from the spec's prose,
//! per this session's "verify against the source, never hand-transcribe"
//! discipline) and cross-checked against §9's own stated results before
//! being written, so a mistake in *this* generator — not just a future
//! `praxis-score` implementation — would be caught immediately.

use serde_json::json;

use crate::vector::write_vector;

/// `spec/SCORING.md` §9's five `(p, y)` pairs.
const CLAIMS: [(f64, f64); 5] = [(0.9, 1.0), (0.8, 1.0), (0.7, 0.0), (0.6, 1.0), (0.3, 0.0)];
/// §9: "reference base rate 0.6 (from pack)".
const BASE_RATE: f64 = 0.6;
/// §4's `ln` clipping bound; irrelevant here (no claim is within 1e-3 of 0 or 1).
const LOG_CLIP: f64 = 1e-3;

fn brier_score(claims: &[(f64, f64)]) -> f64 {
    let n = u32::try_from(claims.len()).expect("5 claims fits a u32");
    claims.iter().map(|(p, y)| (p - y).powi(2)).sum::<f64>() / f64::from(n)
}

fn brier_against_reference(claims: &[(f64, f64)], reference_p: f64) -> f64 {
    let n = u32::try_from(claims.len()).expect("5 claims fits a u32");
    claims
        .iter()
        .map(|(_, y)| (reference_p - y).powi(2))
        .sum::<f64>()
        / f64::from(n)
}

fn log_score(claims: &[(f64, f64)]) -> f64 {
    let n = u32::try_from(claims.len()).expect("5 claims fits a u32");
    claims
        .iter()
        .map(|(p, y)| {
            let p_y = if (*y - 1.0).abs() < f64::EPSILON {
                *p
            } else {
                1.0 - *p
            };
            let clipped = p_y.clamp(LOG_CLIP, 1.0 - LOG_CLIP);
            -clipped.ln()
        })
        .sum::<f64>()
        / f64::from(n)
}

pub fn generate() {
    crate::vector::clean_category("scoring");

    let bs = brier_score(&CLAIMS);
    let bs_ref = brier_against_reference(&CLAIMS, BASE_RATE);
    let bss = 1.0 - bs / bs_ref;
    let ls = log_score(&CLAIMS);

    // Cross-check against spec/SCORING.md §9's own stated results (tolerance
    // 1e-9 per §1's cross-implementation requirement, except BSS/LS which the
    // spec prints rounded to 6dp, so compare at that rounding instead).
    assert!((bs - 0.158).abs() < 1e-9, "BS={bs}");
    assert!((bss - 0.341_666_666_666_666_7).abs() < 1e-9, "BSS={bss}");
    assert!((ls - 0.479_995).abs() < 5e-7, "LS={ls}");

    write_vector(
        "scoring/basic-001",
        "SCORING.md#9",
        "The hand-worked Brier/BSS/log-score example from SCORING.md §9: 5 \
         claims, reference base rate 0.6. BS=0.158, BSS=0.341667, LS=0.479995. \
         n=5 is below the §5 'insufficient' threshold (30); this vector only \
         checks the arithmetic, not sample-size display rules.",
        &json!({
            "claims": CLAIMS.iter().map(|(p, y)| json!({"p": p, "y": y})).collect::<Vec<_>>(),
            "reference_p": BASE_RATE,
        }),
        &json!({
            "bs": bs,
            "bs_ref": bs_ref,
            "bss": bss,
            "ls": ls,
        }),
    );
}
