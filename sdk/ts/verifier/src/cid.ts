// SPDX-License-Identifier: Apache-2.0
//
// CIDv1, restricted to the exact multicodec/multihash combinations
// spec/PROTOCOL.md §2 uses (dag-cbor or raw, always BLAKE3-256) — mirrors
// crates/praxis-types/src/envelope.rs's `Cid`, built from raw multiformats
// bytes directly rather than reusing any Rust-side CID library.

import { blake3 } from "@noble/hashes/blake3.js";

const MULTICODEC_DAG_CBOR = 0x71;
const MULTICODEC_RAW = 0x55;
const MULTIHASH_BLAKE3 = 0x1e;
const DIGEST_LEN = 32;
const BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";

export type CidCodec = "dag-cbor" | "raw";

function codecByte(codec: CidCodec): number {
  return codec === "dag-cbor" ? MULTICODEC_DAG_CBOR : MULTICODEC_RAW;
}

function codecFromByte(byte: number): CidCodec | undefined {
  if (byte === MULTICODEC_DAG_CBOR) return "dag-cbor";
  if (byte === MULTICODEC_RAW) return "raw";
  return undefined;
}

/** Lowercase, unpadded RFC 4648 base32 (the multibase `b` prefix's alphabet),
 * used only for `Cid.toString()`'s `did:praxis:<cid>` form (spec/PROTOCOL.md
 * §4.1, PIP-0003) — never for anything security-relevant. */
function base32Lower(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET.charAt((value >>> (bits - 5)) & 0x1f);
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET.charAt((value << (5 - bits)) & 0x1f);
  }
  return output;
}

/** A CIDv1 restricted to `{dag-cbor, raw} x blake3-256`, matching
 * `praxis_types::Cid`'s own validation exactly. */
export class Cid {
  private constructor(
    public readonly codec: CidCodec,
    public readonly digest: Uint8Array,
  ) {}

  /** Builds a `Cid` directly from a codec and a 32-byte BLAKE3 digest. */
  public static fromDigest(codec: CidCodec, digest: Uint8Array): Cid {
    if (digest.length !== DIGEST_LEN) {
      throw new Error(`CID digest must be exactly ${String(DIGEST_LEN)} bytes`);
    }
    return new Cid(codec, digest);
  }

  /** `blake3(bytes)`, wrapped as a `Cid` (spec/PROTOCOL.md §5.1: "Object ID =
   * CID of the entire canonical encoding"). `bytes` must already be
   * canonically encoded. */
  public static fromCanonicalBytes(codec: CidCodec, bytes: Uint8Array): Cid {
    return Cid.fromDigest(codec, blake3(bytes));
  }

  /** Parses a CID's raw multiformats bytes: `version || codec || hashFn ||
   * hashLen || digest` (36 bytes for our fixed parameters), re-validating
   * every constraint CDDL leaves to prose, exactly like
   * `praxis_types::Cid`'s `Deserialize`/`Cid::validate`. */
  public static fromRawBytes(bytes: Uint8Array): Cid {
    if (bytes.length < 4) {
      throw new Error("CID bytes too short");
    }
    const version = bytes[0];
    if (version !== 1) {
      throw new Error("cid must be CIDv1");
    }
    const codecByteValue = bytes[1];
    const codec = codecByteValue === undefined ? undefined : codecFromByte(codecByteValue);
    if (codec === undefined) {
      throw new Error("unsupported CID multicodec (expected dag-cbor 0x71 or raw 0x55)");
    }
    if (bytes[2] !== MULTIHASH_BLAKE3) {
      throw new Error("unsupported CID multihash code (expected BLAKE3 0x1e)");
    }
    if (bytes[3] !== DIGEST_LEN) {
      throw new Error("CID digest must be exactly 32 bytes");
    }
    const digest = bytes.subarray(4);
    if (digest.length !== DIGEST_LEN) {
      throw new Error("CID digest must be exactly 32 bytes");
    }
    return new Cid(codec, Uint8Array.from(digest));
  }

  /** The CID's raw multiformats binary encoding (36 bytes: no CBOR tag-42
   * wrapper, no leading 0x00, no outer `bstr` length prefix) — this is the
   * `case` byte string in `aad=kind||case||author`
   * (spec/pips/0001-sealing-byte-encoding.md), matching
   * `praxis_types::Cid::to_bytes()` exactly, not the tag-42 wire form. */
  public toBytes(): Uint8Array {
    const out = new Uint8Array(4 + DIGEST_LEN);
    out[0] = 1;
    out[1] = codecByte(this.codec);
    out[2] = MULTIHASH_BLAKE3;
    out[3] = DIGEST_LEN;
    out.set(this.digest, 4);
    return out;
  }

  public equals(other: Cid): boolean {
    if (this.codec !== other.codec || this.digest.length !== other.digest.length) {
      return false;
    }
    for (let i = 0; i < this.digest.length; i += 1) {
      if (this.digest[i] !== other.digest[i]) {
        return false;
      }
    }
    return true;
  }

  /** The CIDv1 multibase string form (base32-lower, e.g. `bafyr4ig...`),
   * matching `praxis_types::Cid`'s `Display` impl — what `did:praxis:<cid>`
   * (spec/PROTOCOL.md §4.1) embeds. */
  public toString(): string {
    return `b${base32Lower(this.toBytes())}`;
  }
}
