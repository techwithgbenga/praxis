// SPDX-License-Identifier: Apache-2.0
//
// A second, independent implementation of canonical dag-cbor decode/encode
// (spec/PROTOCOL.md §3.1-3.2), deliberately not sharing any code with the
// Rust reference (crates/praxis-types/src/codec.rs, value.rs): definite
// lengths only, shortest-form integers, map keys sorted by (length, then
// bytewise), no duplicate keys, no CBOR tags other than 42 (CID link), no
// floats. Out of scope here (no vector exercises it): the object-size/array-
// length/nesting-depth limits from spec/PROTOCOL.md §3.5 — those are a
// decode-side DoS guard, not a canonicality rule, and M1-08 did not generate
// vectors for them.

import { Cid } from "./cid.js";

/** A CBOR tag-42 CID link, embedded wherever `content` (not the stricter
 * `value` grammar) carries a `cid` field — see praxis_types::value's module
 * docs on the Rust side for why `Value` needs this at all. */
export class Link {
  public constructor(public readonly cid: Cid) {}
}

/** `value = null / bool / int / tstr / bstr / [* value] / {* tstr => value}`
 * (spec/praxis-v0.1.cddl), plus `Link` for the reason given above. Integers
 * are `bigint` throughout (never `number`): dag-cbor's full int64/uint64
 * range does not fit a JS `number` without silent precision loss. */
export type Value =
  | null
  | boolean
  | bigint
  | string
  | Uint8Array
  | Value[]
  | Map<string, Value>
  | Link;

const E_DECODE = "E_DECODE";
const E_FLOAT_NOT_ALLOWED = "E_FLOAT_NOT_ALLOWED";
const E_NONCANONICAL = "E_NONCANONICAL";

/** Mirrors `praxis_types::CodecError`'s `.code()` (stable `E_*` strings), not
 * its exact `Display` wording. */
export class DecodeError extends Error {
  public constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "DecodeError";
  }
}

class Reader {
  private pos = 0;
  public constructor(private readonly bytes: Uint8Array) {}

  public get position(): number {
    return this.pos;
  }

  public get remaining(): number {
    return this.bytes.length - this.pos;
  }

  public byte(): number {
    if (this.pos >= this.bytes.length) {
      throw new DecodeError(E_DECODE, "unexpected end of input");
    }
    const value = this.bytes[this.pos];
    if (value === undefined) {
      throw new DecodeError(E_DECODE, "unexpected end of input");
    }
    this.pos += 1;
    return value;
  }

  public take(n: number): Uint8Array {
    if (this.pos + n > this.bytes.length) {
      throw new DecodeError(E_DECODE, "unexpected end of input");
    }
    const slice = this.bytes.subarray(this.pos, this.pos + n);
    this.pos += n;
    return slice;
  }
}

/** Reads a (major, additionalInfo) header byte. */
function readHeader(r: Reader): { major: number; ai: number } {
  const b = r.byte();
  return { major: b >> 5, ai: b & 0x1f };
}

/** Reads the big-endian unsigned integer the header's additional-info field
 * describes, enforcing dag-cbor's "integers must be as small as possible"
 * rule (spec/PROTOCOL.md §3.1) for every use of this encoding (unsigned/
 * negative int values, and byte-string/text-string/array/map/tag lengths). */
function readMinimalLength(r: Reader, ai: number): bigint {
  if (ai <= 23) {
    return BigInt(ai);
  }
  if (ai === 24) {
    const v = r.byte();
    if (v < 24) {
      throw new DecodeError(E_DECODE, "non-minimal 1-byte length/integer encoding");
    }
    return BigInt(v);
  }
  if (ai === 25) {
    const bytes = r.take(2);
    const v = (BigInt(bytes[0] ?? 0) << 8n) | BigInt(bytes[1] ?? 0);
    if (v < 256n) {
      throw new DecodeError(E_DECODE, "non-minimal 2-byte length/integer encoding");
    }
    return v;
  }
  if (ai === 26) {
    const bytes = r.take(4);
    let v = 0n;
    for (const byte of bytes) {
      v = (v << 8n) | BigInt(byte);
    }
    if (v < 65536n) {
      throw new DecodeError(E_DECODE, "non-minimal 4-byte length/integer encoding");
    }
    return v;
  }
  if (ai === 27) {
    const bytes = r.take(8);
    let v = 0n;
    for (const byte of bytes) {
      v = (v << 8n) | BigInt(byte);
    }
    if (v < 4294967296n) {
      throw new DecodeError(E_DECODE, "non-minimal 8-byte length/integer encoding");
    }
    return v;
  }
  // ai in {28,29,30}: reserved/invalid. ai === 31: indefinite length, which
  // dag-cbor forbids outright (spec/PROTOCOL.md §3.1) — we never support it.
  throw new DecodeError(E_DECODE, `unsupported or indefinite-length additional info ${String(ai)}`);
}

function decodeOne(r: Reader): Value {
  const { major, ai } = readHeader(r);
  switch (major) {
    case 0: {
      return readMinimalLength(r, ai);
    }
    case 1: {
      const n = readMinimalLength(r, ai);
      return -1n - n;
    }
    case 2: {
      const len = readMinimalLength(r, ai);
      return Uint8Array.from(r.take(Number(len)));
    }
    case 3: {
      const len = readMinimalLength(r, ai);
      return new TextDecoder("utf-8", { fatal: true }).decode(r.take(Number(len)));
    }
    case 4: {
      const len = readMinimalLength(r, ai);
      const items: Value[] = [];
      for (let i = 0n; i < len; i += 1n) {
        items.push(decodeOne(r));
      }
      return items;
    }
    case 5: {
      const pairs = readMinimalLength(r, ai);
      const entries = new Map<string, Value>();
      for (let i = 0n; i < pairs; i += 1n) {
        const key = decodeOne(r);
        if (typeof key !== "string") {
          throw new DecodeError(E_DECODE, "map key must be a text string");
        }
        if (entries.has(key)) {
          throw new DecodeError(E_DECODE, `duplicate map key ${JSON.stringify(key)}`);
        }
        const value = decodeOne(r);
        entries.set(key, value);
      }
      return entries;
    }
    case 6: {
      const tag = readMinimalLength(r, ai);
      if (tag !== 42n) {
        throw new DecodeError(E_DECODE, `unsupported CBOR tag ${tag.toString()} (only 42 is allowed)`);
      }
      const inner = decodeOne(r);
      if (!(inner instanceof Uint8Array)) {
        throw new DecodeError(E_DECODE, "tag 42 must wrap a byte string");
      }
      if (inner.length !== 37 || inner[0] !== 0) {
        throw new DecodeError(E_DECODE, "tag 42 payload must be a 0x00-prefixed 36-byte CID");
      }
      return new Link(Cid.fromRawBytes(inner.subarray(1)));
    }
    case 7: {
      if (ai === 20) return false;
      if (ai === 21) return true;
      if (ai === 22) return null;
      if (ai === 25 || ai === 26 || ai === 27) {
        throw new DecodeError(E_FLOAT_NOT_ALLOWED, "floating-point values are not permitted (spec/PROTOCOL.md §3.2)");
      }
      throw new DecodeError(E_DECODE, `unsupported simple value, additional info ${String(ai)}`);
    }
    default:
      throw new DecodeError(E_DECODE, `impossible major type ${String(major)}`);
  }
}

/** Big-endian length prefix helper for `encodeHeader`/callers below. */
function pushMinimalLength(out: number[], major: number, n: bigint): void {
  const base = major << 5;
  if (n < 0n) {
    throw new DecodeError(E_DECODE, "internal: negative length");
  }
  if (n <= 23n) {
    out.push(base | Number(n));
  } else if (n <= 255n) {
    out.push(base | 24, Number(n));
  } else if (n <= 65535n) {
    out.push(base | 25, Number(n >> 8n), Number(n & 0xffn));
  } else if (n <= 4294967295n) {
    out.push(base | 26);
    for (let shift = 24; shift >= 0; shift -= 8) {
      out.push(Number((n >> BigInt(shift)) & 0xffn));
    }
  } else {
    out.push(base | 27);
    for (let shift = 56; shift >= 0; shift -= 8) {
      out.push(Number((n >> BigInt(shift)) & 0xffn));
    }
  }
}

/** Sorts map keys by (utf-8 byte length, then bytewise) — dag-cbor's
 * canonical order (spec/PROTOCOL.md §3.1), not lexicographic string order. */
function canonicalKeyOrder(a: string, b: string): number {
  const aBytes = new TextEncoder().encode(a);
  const bBytes = new TextEncoder().encode(b);
  if (aBytes.length !== bBytes.length) {
    return aBytes.length - bBytes.length;
  }
  for (let i = 0; i < aBytes.length; i += 1) {
    const diff = (aBytes[i] ?? 0) - (bBytes[i] ?? 0);
    if (diff !== 0) {
      return diff;
    }
  }
  return 0;
}

function encodeInto(out: number[], value: Value): void {
  if (value === null) {
    out.push(0xf6);
    return;
  }
  if (typeof value === "boolean") {
    out.push(value ? 0xf5 : 0xf4);
    return;
  }
  if (typeof value === "bigint") {
    if (value >= 0n) {
      pushMinimalLength(out, 0, value);
    } else {
      pushMinimalLength(out, 1, -1n - value);
    }
    return;
  }
  if (typeof value === "string") {
    const bytes = new TextEncoder().encode(value);
    pushMinimalLength(out, 3, BigInt(bytes.length));
    out.push(...bytes);
    return;
  }
  if (value instanceof Uint8Array) {
    pushMinimalLength(out, 2, BigInt(value.length));
    out.push(...value);
    return;
  }
  if (Array.isArray(value)) {
    pushMinimalLength(out, 4, BigInt(value.length));
    for (const item of value) {
      encodeInto(out, item);
    }
    return;
  }
  if (value instanceof Link) {
    out.push(0xd8, 0x2a); // tag(42), minimally encoded (ai=24, byte 0x2a)
    const raw = value.cid.toBytes();
    const prefixed = new Uint8Array(raw.length + 1);
    prefixed.set(raw, 1);
    prefixed[0] = 0x00;
    pushMinimalLength(out, 2, BigInt(prefixed.length));
    out.push(...prefixed);
    return;
  }
  // value instanceof Map<string, Value>
  const keys = [...value.keys()].sort(canonicalKeyOrder);
  pushMinimalLength(out, 5, BigInt(keys.length));
  for (const key of keys) {
    encodeInto(out, key);
    const entry = value.get(key);
    if (entry === undefined) {
      throw new DecodeError(E_DECODE, "internal: map key vanished during encode");
    }
    encodeInto(out, entry);
  }
}

/** Encodes `value` to its canonical dag-cbor bytes. Never produces a
 * non-canonical encoding, so this is also the reference `decodeCanonical`
 * re-encodes against to catch out-of-order map keys (see below). */
export function encodeCanonical(value: Value): Uint8Array {
  const out: number[] = [];
  encodeInto(out, value);
  return Uint8Array.from(out);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

/** Decodes and fully validates `bytes` as canonical dag-cbor (mirrors
 * `praxis_types::decode_canonical`'s two-phase design): a strict structural
 * parse (rejecting non-minimal ints, duplicate keys, indefinite lengths, any
 * tag but 42, and floats, all as `E_DECODE`/`E_FLOAT_NOT_ALLOWED`), then a
 * re-encode-and-compare step that catches anything structurally valid but
 * out of canonical order (map keys not sorted by length-then-bytewise) as
 * `E_NONCANONICAL`. */
export function decodeCanonical(bytes: Uint8Array): Value {
  const reader = new Reader(bytes);
  const value = decodeOne(reader);
  if (reader.remaining !== 0) {
    throw new DecodeError(E_DECODE, "trailing data after a complete value");
  }
  const reencoded = encodeCanonical(value);
  if (!bytesEqual(reencoded, bytes)) {
    throw new DecodeError(E_NONCANONICAL, "input bytes are not the canonical encoding of their own value");
  }
  return value;
}
