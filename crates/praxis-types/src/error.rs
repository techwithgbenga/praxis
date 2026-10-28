// SPDX-License-Identifier: Apache-2.0
//! Typed construction/validation errors for this crate (`AGENTS.md` §3 `DoD`: errors
//! are typed, never `unwrap`/`expect` outside tests).

use std::fmt;

/// A value failed one of the shape/range constraints in `spec/praxis-v0.1.cddl` or
/// `spec/PROTOCOL.md` §3.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TypeError {
    /// A `ppm` value was outside `0..=1_000_000` (`spec/PROTOCOL.md` §3.2).
    #[error("ppm {0} out of range 0..=1_000_000")]
    PpmOutOfRange(u32),
    /// A length-bounded string (`shorttext`, `text`, `kid`, ...) violated its byte-length bound.
    #[error("{field} byte length {len} out of range {min}..={max}")]
    LengthOutOfRange {
        /// Name of the field/type being validated (for diagnostics only).
        field: &'static str,
        /// The byte length that was found.
        len: usize,
        /// The valid minimum, inclusive.
        min: usize,
        /// The valid maximum, inclusive.
        max: usize,
    },
    /// Text was not NFC-normalized, or contained a forbidden control character
    /// (`spec/PROTOCOL.md` §3.3: only `\n` and `\t` are permitted).
    #[error("{field} is not valid protocol text: {reason}")]
    InvalidText {
        /// Name of the field/type being validated.
        field: &'static str,
        /// Human-readable reason (not NFC-normalized, or which control character).
        reason: TextViolation,
    },
    /// A DID did not match `did:praxis:[a-z2-7]{20,100}` (`spec/praxis-v0.1.cddl`).
    #[error("invalid did:praxis identifier: {0:?}")]
    InvalidDid(String),
}

/// Why a text value was rejected by the shared protocol text check
/// (`spec/PROTOCOL.md` §3.3), used by [`crate::ShortText`] and [`crate::LongText`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextViolation {
    /// The text was not already in Unicode Normalization Form C.
    NotNfc,
    /// The text contained a control character other than `\n` (U+000A) or `\t` (U+0009).
    ForbiddenControlChar(char),
}

impl fmt::Display for TextViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotNfc => write!(f, "not NFC-normalized"),
            Self::ForbiddenControlChar(c) => {
                write!(f, "forbidden control character {c:?}")
            }
        }
    }
}
