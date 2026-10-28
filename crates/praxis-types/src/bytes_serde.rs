// SPDX-License-Identifier: Apache-2.0
//! `#[serde(with = "bytes_serde")]` helper for fixed-size byte arrays (`[u8; N]`),
//! shared by every CDDL `bstr .size N` field in this crate (`salt`, `nonce`,
//! `hash32`, `sig`, ...). Serde's derive does not support const-generic byte
//! arrays directly on stable without this.

use serde::{Deserializer, Serializer};

/// Serializes `bytes` as a byte string (not a generic sequence), matching how
/// dag-cbor and most other self-describing formats represent `bstr`.
pub fn serialize<S: Serializer, const N: usize>(
    bytes: &[u8; N],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serde_bytes::serialize(bytes.as_slice(), serializer)
}

/// Deserializes exactly `N` bytes, rejecting any other length.
pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
    deserializer: D,
) -> Result<[u8; N], D::Error> {
    let bytes: Vec<u8> = serde_bytes::deserialize(deserializer)?;
    let len = bytes.len();
    <[u8; N]>::try_from(bytes)
        .map_err(|_| serde::de::Error::invalid_length(len, &"the expected fixed byte-array length"))
}

/// `#[serde(with = "bytes_serde::opt_bytes")]` for `Option<Vec<u8>>` as a byte
/// string (`serde_bytes` only covers `Vec<u8>`/`[u8]` directly, not the `Option` of it).
pub mod opt_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    // `serde(with = ...)` always calls `serialize(&field, serializer)`, so the
    // parameter must be `&Option<T>`, not clippy::ref_option's preferred `Option<&T>`.
    #[allow(clippy::ref_option)]
    pub fn serialize<S: Serializer>(
        value: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(bytes) => serde_bytes::serialize(bytes.as_slice(), serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        #[derive(Deserialize)]
        struct Wrapper(#[serde(with = "serde_bytes")] Vec<u8>);
        Option::<Wrapper>::deserialize(deserializer).map(|opt| opt.map(|Wrapper(b)| b))
    }
}

/// `#[serde(with = "bytes_serde::opt_array")]` for `Option<[u8; N]>` (see [`opt_bytes`]).
pub mod opt_array {
    use serde::{Deserialize, Deserializer, Serializer};

    #[allow(clippy::ref_option)]
    pub fn serialize<S: Serializer, const N: usize>(
        value: &Option<[u8; N]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(bytes) => serde_bytes::serialize(bytes.as_slice(), serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        deserializer: D,
    ) -> Result<Option<[u8; N]>, D::Error> {
        #[derive(Deserialize)]
        struct Wrapper(#[serde(with = "serde_bytes")] Vec<u8>);
        match Option::<Wrapper>::deserialize(deserializer)? {
            None => Ok(None),
            Some(Wrapper(bytes)) => {
                let len = bytes.len();
                let arr = <[u8; N]>::try_from(bytes).map_err(|_| {
                    serde::de::Error::invalid_length(len, &"the expected fixed byte-array length")
                })?;
                Ok(Some(arr))
            }
        }
    }
}
