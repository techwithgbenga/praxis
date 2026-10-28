// SPDX-License-Identifier: Apache-2.0
//
// Reads a decoded dag-cbor `Value` as a Praxis object envelope
// (spec/PROTOCOL.md §5, spec/praxis-v0.1.cddl `object`). Deliberately just
// accessor functions over a generic `Map<string, Value>`, not a parallel
// class hierarchy: `serde_ipld_dagcbor` canonically sorts *any* struct's or
// map's fields at encode time (confirmed by reading its `ser.rs`), so
// `Object`'s field order in the Rust source carries no wire meaning either —
// a plain `Map` plus `encodeCanonical`'s existing key-sorting is exactly
// equivalent to a hand-rolled `Object` encoder, with far less code.

import { Cid } from "./cid.js";
import { decodeCanonical, encodeCanonical, DecodeError, Link, type Value } from "./dagcbor.js";

function asMap(value: Value, context: string): Map<string, Value> {
  if (!(value instanceof Map)) {
    throw new DecodeError("E_DECODE", `expected a map for ${context}`);
  }
  return value;
}

function field(map: Map<string, Value>, key: string, context: string): Value {
  const value = map.get(key);
  if (value === undefined) {
    throw new DecodeError("E_DECODE", `missing field ${JSON.stringify(key)} in ${context}`);
  }
  return value;
}

function asString(value: Value, context: string): string {
  if (typeof value !== "string") {
    throw new DecodeError("E_DECODE", `expected a string for ${context}`);
  }
  return value;
}

function asBigInt(value: Value, context: string): bigint {
  if (typeof value !== "bigint") {
    throw new DecodeError("E_DECODE", `expected an integer for ${context}`);
  }
  return value;
}

function asBytes(value: Value, context: string): Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new DecodeError("E_DECODE", `expected bytes for ${context}`);
  }
  return value;
}

function asLink(value: Value, context: string): Cid {
  if (!(value instanceof Link)) {
    throw new DecodeError("E_DECODE", `expected a CID link for ${context}`);
  }
  return value.cid;
}

function asArray(value: Value, context: string): Value[] {
  if (!Array.isArray(value)) {
    throw new DecodeError("E_DECODE", `expected an array for ${context}`);
  }
  return value;
}

/** Decodes `bytes` as a generic dag-cbor value and asserts it is a Praxis
 * object's top-level map (every object is `{v, kind, ...}`, never a bare
 * scalar/array). */
export function decodeObjectMap(bytes: Uint8Array): Map<string, Value> {
  return asMap(decodeCanonical(bytes), "object");
}

export function objectKind(object: Map<string, Value>): string {
  return asString(field(object, "kind", "object.kind"), "object.kind");
}

export function objectAuthor(object: Map<string, Value>): string {
  return asString(field(object, "author", "object.author"), "object.author");
}

export function objectSigner(object: Map<string, Value>): string {
  return asString(field(object, "signer", "object.signer"), "object.signer");
}

export function objectTs(object: Map<string, Value>): bigint {
  return asBigInt(field(object, "ts", "object.ts"), "object.ts");
}

export function objectCase(object: Map<string, Value>): Cid | null {
  const value = object.get("case");
  return value === undefined ? null : asLink(value, "object.case");
}

export function objectPrev(object: Map<string, Value>): Cid[] {
  return asArray(field(object, "prev", "object.prev"), "object.prev").map((item, i) =>
    asLink(item, `object.prev[${String(i)}]`),
  );
}

export function objectSig(object: Map<string, Value>): Uint8Array {
  return asBytes(field(object, "sig", "object.sig"), "object.sig");
}

/** The content held in a *plain* body's `plain` field (spec/PROTOCOL.md §8.1:
 * `plain-body = { plain: content, salt: bstr .size 16, ? pad: bstr }`). Every
 * M1-08 vector uses plain bodies only; sealed-body decode is out of scope
 * here (no vector exercises a sealed body nested inside a full signed
 * object — `sealing/*`'s own vectors exercise `seal_body`/`unseal_body`
 * directly on a bare `SealedBody`, never wrapped in an `Object`). */
export function objectPlainContent(object: Map<string, Value>): Value {
  const body = asMap(field(object, "body", "object.body"), "object.body");
  return field(body, "plain", "object.body.plain");
}

/** The object's canonical bytes with `sig` entirely absent — the
 * `canonical_bytes(object_without_sig)` half of spec/PROTOCOL.md §5.2's
 * `sig = Ed25519.sign(signer_secret, "praxis/v1/object\x00" ||
 * canonical_bytes(object_without_sig))`. */
export function canonicalSigningBytes(object: Map<string, Value>): Uint8Array {
  const withoutSig = new Map(object);
  withoutSig.delete("sig");
  return encodeCanonical(withoutSig);
}

/** An object's own ID: the CID of its *entire* canonical encoding, including
 * `sig` (spec/PROTOCOL.md §5.1). Hashes the original bytes directly rather
 * than re-encoding the decoded map — `decodeCanonical` already proved
 * `encodeCanonical(decoded) === originalBytes` as part of decoding
 * successfully at all, so this is exactly equivalent and avoids a needless
 * round trip. */
export function objectId(originalBytes: Uint8Array): Cid {
  return Cid.fromCanonicalBytes("dag-cbor", originalBytes);
}
