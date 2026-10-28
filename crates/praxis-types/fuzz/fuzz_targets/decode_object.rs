// SPDX-License-Identifier: Apache-2.0
//! Fuzzes `praxis_types::decode_object` against arbitrary bytes
//! (`docs/IMPLEMENTATION_PLAN.md` M1-02/M1-10; `AGENTS.md` §4).
//!
//! The only invariant under test is "never panics, never hangs, never reads
//! out of bounds" on attacker-controlled input — `decode_object` returning
//! `Err` is always a fine outcome. If it *does* decode successfully, re-encode
//! the result and confirm encoding is total for anything that decoded (it
//! must be, since every decoded value already satisfies the reserved-field-name
//! invariant `encode_object` checks — see `crates/praxis-types/src/codec.rs`).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(object) = praxis_types::decode_object(data) {
        let _ = praxis_types::encode_object(&object)
            .expect("anything decode_object accepted must also re-encode");
    }
});
