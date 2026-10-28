// SPDX-License-Identifier: Apache-2.0
//! Scalar newtypes from `spec/PROTOCOL.md` §3 and `spec/praxis-v0.1.cddl`.
//!
//! Every constructor enforces its range/shape and every `Deserialize` impl is
//! hand-written (not derived) to re-run the same validation on untrusted input,
//! per `docs/IMPLEMENTATION_PLAN.md` M1-01 ("constructors enforce ranges").

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use unicode_normalization::is_nfc;

use crate::error::{TextViolation, TypeError};

/// Checks the shared protocol text rule (`spec/PROTOCOL.md` §3.3): NFC-normalized
/// UTF-8, no control characters other than `\n` and `\t`. Used by [`ShortText`]
/// and [`LongText`]; byte-length bounds are checked separately by each caller.
pub fn validate_protocol_text(field: &'static str, s: &str) -> Result<(), TypeError> {
    if !is_nfc(s) {
        return Err(TypeError::InvalidText {
            field,
            reason: TextViolation::NotNfc,
        });
    }
    if let Some(c) = s
        .chars()
        .find(|c| c.is_control() && *c != '\n' && *c != '\t')
    {
        return Err(TypeError::InvalidText {
            field,
            reason: TextViolation::ForbiddenControlChar(c),
        });
    }
    Ok(())
}

/// A probability, parts-per-million: integer `0..=1_000_000` (`spec/PROTOCOL.md` §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Ppm(u32);

impl Ppm {
    /// The maximum representable value (certainty, 100%).
    pub const MAX: u32 = 1_000_000;

    /// Builds a `Ppm`, rejecting values above [`Ppm::MAX`].
    ///
    /// # Errors
    /// Returns [`TypeError::PpmOutOfRange`] if `value > Ppm::MAX`.
    pub fn new(value: u32) -> Result<Self, TypeError> {
        if value > Self::MAX {
            return Err(TypeError::PpmOutOfRange(value));
        }
        Ok(Self(value))
    }

    /// The underlying integer value.
    #[must_use]
    pub fn get(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for Ppm {
    type Error = TypeError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for Ppm {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u32::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Surprise, in milli-nats: a non-negative integer (`spec/PROTOCOL.md` §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Mnat(u64);

impl Mnat {
    /// Builds an `Mnat` from a raw milli-nat count. Every `u64` is valid.
    #[must_use]
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    /// The underlying integer value.
    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }
}

impl From<u64> for Mnat {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

/// Milliseconds since the Unix epoch, UTC (`spec/PROTOCOL.md` §3.2). Every `u64` is
/// a valid `Ts`; monotonicity vs. causal parents is a validator rule (`praxis-validate`),
/// not a shape constraint of this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Ts(u64);

impl Ts {
    /// Builds a `Ts` from raw epoch milliseconds. Every `u64` is valid.
    #[must_use]
    pub fn from_millis(value: u64) -> Self {
        Self(value)
    }

    /// The underlying epoch-millisecond value.
    #[must_use]
    pub fn as_millis(self) -> u64 {
        self.0
    }
}

impl From<u64> for Ts {
    fn from(value: u64) -> Self {
        Self::from_millis(value)
    }
}

/// The lowercase RFC 4648 base32 alphabet (no padding), used by `did:praxis:` identifiers.
const DID_ALPHABET: fn(u8) -> bool = |b| matches!(b, b'a'..=b'z' | b'2'..=b'7');

/// A practitioner identity, `did:praxis:<base32lower, 20-100 chars>`
/// (`spec/praxis-v0.1.cddl`, `spec/PROTOCOL.md` §4.1). Hand-checked against the
/// grammar rather than via the `regex` crate, to keep this dependency-light
/// (`docs/PRIVACY_AND_THREAT_MODEL.md` T11: "minimal deps in kernel").
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Did(String);

impl Did {
    const PREFIX: &'static str = "did:praxis:";

    /// Validates and builds a `Did` from an owned string.
    ///
    /// # Errors
    /// Returns [`TypeError::InvalidDid`] if the value is not
    /// `did:praxis:` followed by 20-100 lowercase base32 characters.
    pub fn new(value: impl Into<String>) -> Result<Self, TypeError> {
        let value = value.into();
        let Some(suffix) = value.strip_prefix(Self::PREFIX) else {
            return Err(TypeError::InvalidDid(value));
        };
        let len = suffix.len();
        if !(20..=100).contains(&len) || !suffix.bytes().all(DID_ALPHABET) {
            return Err(TypeError::InvalidDid(value));
        }
        Ok(Self(value))
    }

    /// The full `did:praxis:...` string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Did {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// A key identifier, `tstr .size (1..64)` (`spec/praxis-v0.1.cddl`): an opaque,
/// author-scoped label for one of the author's keys (e.g. a device key).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Kid(String);

impl Kid {
    /// Validates and builds a `Kid` from an owned string: 1-64 UTF-8 bytes,
    /// NFC-normalized, no forbidden control characters (`spec/PROTOCOL.md` §3.3).
    ///
    /// # Errors
    /// Returns [`TypeError::LengthOutOfRange`] or [`TypeError::InvalidText`].
    pub fn new(value: impl Into<String>) -> Result<Self, TypeError> {
        let value = value.into();
        let len = value.len();
        if !(1..=64).contains(&len) {
            return Err(TypeError::LengthOutOfRange {
                field: "kid",
                len,
                min: 1,
                max: 64,
            });
        }
        validate_protocol_text("kid", &value)?;
        Ok(Self(value))
    }

    /// The underlying string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Kid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// `shorttext = tstr .size (1..256)` (`spec/praxis-v0.1.cddl`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ShortText(String);

impl ShortText {
    /// Validates and builds a `ShortText` from an owned string: 1-256 UTF-8 bytes,
    /// NFC-normalized, no forbidden control characters.
    ///
    /// # Errors
    /// Returns [`TypeError::LengthOutOfRange`] or [`TypeError::InvalidText`].
    pub fn new(value: impl Into<String>) -> Result<Self, TypeError> {
        let value = value.into();
        let len = value.len();
        if !(1..=256).contains(&len) {
            return Err(TypeError::LengthOutOfRange {
                field: "shorttext",
                len,
                min: 1,
                max: 256,
            });
        }
        validate_protocol_text("shorttext", &value)?;
        Ok(Self(value))
    }

    /// The underlying string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ShortText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// `text = tstr .size (0..16384)` (`spec/praxis-v0.1.cddl`): long-form free text
/// (situation summaries, reasoning, elicitation answers).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct LongText(String);

impl LongText {
    /// Validates and builds a `LongText` from an owned string: 0-16384 UTF-8
    /// bytes, NFC-normalized, no forbidden control characters.
    ///
    /// # Errors
    /// Returns [`TypeError::LengthOutOfRange`] or [`TypeError::InvalidText`].
    pub fn new(value: impl Into<String>) -> Result<Self, TypeError> {
        let value = value.into();
        let len = value.len();
        if len > 16384 {
            return Err(TypeError::LengthOutOfRange {
                field: "text",
                len,
                min: 0,
                max: 16384,
            });
        }
        validate_protocol_text("text", &value)?;
        Ok(Self(value))
    }

    /// The underlying string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for LongText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// `suite = "pxs1"` (`spec/PROTOCOL.md` §2). Reserved for `pxs2`+ hybrid
/// post-quantum suites at the v1.0 gate; v0.1 defines only `pxs1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Suite {
    /// The only cipher suite defined by spec v0.1.
    #[default]
    Pxs1,
}

impl Suite {
    /// The suite's wire string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pxs1 => "pxs1",
        }
    }
}

impl Serialize for Suite {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Suite {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            "pxs1" => Ok(Self::Pxs1),
            other => Err(serde::de::Error::custom(format!(
                "unsupported suite {other:?}"
            ))),
        }
    }
}

/// A 32-byte hash (`hash32 = bstr .size 32`): a commit value or a raw BLAKE3-256 digest.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Hash32(#[serde(with = "crate::bytes_serde")] [u8; 32]);

impl Hash32 {
    /// Wraps a raw 32-byte digest.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The underlying bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Hash32")
            .field(&hex_preview(&self.0))
            .finish()
    }
}

/// An Ed25519 signature (`sig = bstr .size 64`).
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Sig(#[serde(with = "crate::bytes_serde")] [u8; 64]);

impl Sig {
    /// Wraps a raw 64-byte Ed25519 signature.
    #[must_use]
    pub fn new(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// The underlying bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl fmt::Debug for Sig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Sig").field(&hex_preview(&self.0)).finish()
    }
}

fn hex_preview(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut s = String::with_capacity(16);
    for b in bytes.iter().take(6) {
        let _ = write!(s, "{b:02x}");
    }
    s.push_str("..");
    s
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn roundtrip<T>(value: &T)
    where
        T: Serialize + for<'de> Deserialize<'de> + PartialEq + fmt::Debug,
    {
        let json = serde_json::to_string(value).expect("serialize");
        let back: T = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(value, &back, "round-trip via {json:?} changed the value");
    }

    #[test]
    fn ppm_accepts_full_range_boundaries() {
        assert_eq!(Ppm::new(0).unwrap().get(), 0);
        assert_eq!(Ppm::new(Ppm::MAX).unwrap().get(), Ppm::MAX);
        roundtrip(&Ppm::new(520_000).unwrap());
    }

    #[test]
    fn ppm_rejects_above_max() {
        assert_eq!(
            Ppm::new(Ppm::MAX + 1),
            Err(TypeError::PpmOutOfRange(Ppm::MAX + 1))
        );
    }

    #[test]
    fn ppm_deserialize_rejects_out_of_range() {
        let err = serde_json::from_str::<Ppm>("1000001").unwrap_err();
        assert!(err.to_string().contains("out of range"));
    }

    proptest! {
        #[test]
        fn ppm_new_matches_range_check(value: u32) {
            let result = Ppm::new(value);
            prop_assert_eq!(result.is_ok(), value <= Ppm::MAX);
        }
    }

    #[test]
    fn mnat_and_ts_roundtrip() {
        roundtrip(&Mnat::new(123_456));
        roundtrip(&Ts::from_millis(1_793_000_000_000));
    }

    #[test]
    fn did_accepts_valid_and_rejects_invalid() {
        let valid = "did:praxis:".to_string() + &"a".repeat(20);
        let did = Did::new(valid.clone()).unwrap();
        assert_eq!(did.as_str(), valid);
        roundtrip(&did);

        assert!(Did::new("did:praxis:tooshort").is_err()); // < 20 chars after prefix
        assert!(Did::new("did:other:".to_string() + &"a".repeat(20)).is_err()); // wrong prefix
        assert!(Did::new("did:praxis:".to_string() + &"A".repeat(20)).is_err()); // uppercase not in alphabet
        assert!(Did::new("did:praxis:".to_string() + &"1".repeat(20)).is_err());
        // '1' not in base32-lower
    }

    #[test]
    fn kid_enforces_length_bounds() {
        assert!(Kid::new("").is_err());
        assert!(Kid::new("x".repeat(64)).is_ok());
        assert!(Kid::new("x".repeat(65)).is_err());
        roundtrip(&Kid::new("device-1").unwrap());
    }

    #[test]
    fn shorttext_and_longtext_enforce_length_and_text_rules() {
        assert!(ShortText::new("").is_err());
        assert!(ShortText::new("x".repeat(256)).is_ok());
        assert!(ShortText::new("x".repeat(257)).is_err());
        roundtrip(&ShortText::new("wait 10m").unwrap());

        assert!(LongText::new("").is_ok());
        assert!(LongText::new("x".repeat(16384)).is_ok());
        assert!(LongText::new("x".repeat(16385)).is_err());

        // Forbidden control character (carriage return is not \n or \t).
        assert!(LongText::new("line1\rline2").is_err());
        // \n and \t are explicitly permitted.
        assert!(LongText::new("line1\nline2\ttabbed").is_ok());

        // Not NFC-normalized: "e" + combining acute accent (U+0065 U+0301) vs "é" (U+00E9).
        let decomposed = "e\u{0301}";
        assert!(LongText::new(decomposed).is_err());
        let composed = "\u{00e9}";
        assert!(LongText::new(composed).is_ok());
    }

    #[test]
    fn suite_roundtrips_and_rejects_unknown() {
        roundtrip(&Suite::Pxs1);
        assert_eq!(Suite::Pxs1.as_str(), "pxs1");
        assert!(serde_json::from_str::<Suite>("\"pxs2\"").is_err());
    }

    #[test]
    fn hash32_and_sig_roundtrip() {
        roundtrip(&Hash32::new([7u8; 32]));
        roundtrip(&Sig::new([9u8; 64]));
    }

    #[test]
    fn hash32_debug_does_not_print_all_bytes() {
        let debug = format!("{:?}", Hash32::new([0xab; 32]));
        assert!(debug.contains("abababab"));
        assert!(!debug.contains(&"ab".repeat(32)));
    }
}
