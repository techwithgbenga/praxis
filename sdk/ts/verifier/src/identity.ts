// SPDX-License-Identifier: Apache-2.0
//
// The identity log state machine (spec/PROTOCOL.md §4; byte-level and
// signing-authority gaps resolved by spec/pips/0003-identity-log-semantics.md)
// — an independent port of crates/praxis-identity/src/log.rs's `IdentityLog`.

import { DecodeError, type Value } from "./dagcbor.js";
import {
  canonicalSigningBytes,
  decodeObjectMap,
  objectAuthor,
  objectId,
  objectKind,
  objectSig,
  objectSigner,
  objectTs,
} from "./object.js";
import { verifyObject } from "./sign.js";

/** `spec/pips/0004-genesis-author-sentinel.md`. */
export const GENESIS_AUTHOR_SENTINEL = "did:praxis:selfselfselfselfself";

export type KeyRole = "root" | "device" | "recovery";

export interface KeyEntry {
  readonly kid: string;
  readonly publicKey: Uint8Array;
  readonly role: KeyRole;
  readonly notBefore: bigint;
  readonly notAfter: bigint | null;
  readonly scope: readonly string[] | null;
}

export type IdOp = "genesis" | "rotate" | "delegate" | "revoke";

export interface Revocation {
  readonly kid: string;
  readonly effective: bigint;
  readonly compromisedSince: bigint | null;
}

export interface IdContent {
  readonly op: IdOp;
  readonly keys: readonly KeyEntry[] | null;
  readonly revoke: Revocation | null;
}

function asMap(value: Value, context: string): Map<string, Value> {
  if (!(value instanceof Map)) {
    throw new DecodeError("E_DECODE", `expected a map for ${context}`);
  }
  return value;
}
function asString(value: Value | undefined, context: string): string {
  if (typeof value !== "string") {
    throw new DecodeError("E_DECODE", `expected a string for ${context}`);
  }
  return value;
}
function asBytes(value: Value | undefined, context: string): Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new DecodeError("E_DECODE", `expected bytes for ${context}`);
  }
  return value;
}
function asBigInt(value: Value | undefined, context: string): bigint {
  if (typeof value !== "bigint") {
    throw new DecodeError("E_DECODE", `expected an integer for ${context}`);
  }
  return value;
}
function asRole(value: string): KeyRole {
  if (value === "root" || value === "device" || value === "recovery") {
    return value;
  }
  throw new DecodeError("E_DECODE", `unknown key role ${JSON.stringify(value)}`);
}

export function decodeKeyEntry(value: Value): KeyEntry {
  const map = asMap(value, "key-entry");
  const scopeValue = map.get("scope");
  const notAfterValue = map.get("not_after");
  return {
    kid: asString(map.get("kid"), "key-entry.kid"),
    publicKey: asBytes(map.get("pub"), "key-entry.pub"),
    role: asRole(asString(map.get("role"), "key-entry.role")),
    notBefore: asBigInt(map.get("not_before"), "key-entry.not_before"),
    notAfter: notAfterValue === undefined ? null : asBigInt(notAfterValue, "key-entry.not_after"),
    scope: scopeValue === undefined ? null : decodeScope(scopeValue),
  };
}

function decodeScope(value: Value): string[] {
  if (!Array.isArray(value)) {
    throw new DecodeError("E_DECODE", "expected an array for key-entry.scope");
  }
  return value.map((k, i) => asString(k, `key-entry.scope[${String(i)}]`));
}

function decodeIdOp(value: string): IdOp {
  if (value === "genesis" || value === "rotate" || value === "delegate" || value === "revoke") {
    return value;
  }
  throw new DecodeError("E_DECODE", `unknown id-content op ${JSON.stringify(value)}`);
}

export function decodeIdContent(value: Value): IdContent {
  const map = asMap(value, "id-content");
  const keysValue = map.get("keys");
  const revokeValue = map.get("revoke");
  return {
    op: decodeIdOp(asString(map.get("op"), "id-content.op")),
    keys: keysValue === undefined ? null : asArrayOfKeyEntries(keysValue),
    revoke: revokeValue === undefined ? null : decodeRevocation(revokeValue),
  };
}

function asArrayOfKeyEntries(value: Value): KeyEntry[] {
  if (!Array.isArray(value)) {
    throw new DecodeError("E_DECODE", "expected an array for id-content.keys");
  }
  return value.map(decodeKeyEntry);
}

function decodeRevocation(value: Value): Revocation {
  const map = asMap(value, "revocation");
  const compromisedSinceValue = map.get("compromised_since");
  return {
    kid: asString(map.get("kid"), "revocation.kid"),
    effective: asBigInt(map.get("effective"), "revocation.effective"),
    compromisedSince:
      compromisedSinceValue === undefined ? null : asBigInt(compromisedSinceValue, "revocation.compromised_since"),
  };
}

export class IdentityError extends Error {
  public constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "IdentityError";
  }
}

interface KeyRecord {
  entry: KeyEntry;
  retiredAt: bigint | null;
  compromisedSince: bigint | null;
}

/** `not_before <= at`, `at <= not_after` (if bounded), and not retired as of `at`. */
function withinValidityWindow(record: KeyRecord, at: bigint): boolean {
  if (at < record.entry.notBefore) {
    return false;
  }
  if (record.entry.notAfter !== null && at > record.entry.notAfter) {
    return false;
  }
  if (record.retiredAt !== null && at >= record.retiredAt) {
    return false;
  }
  return true;
}

/** Verifies `object`'s signature (its `canonicalSigningBytes`, decoded from
 * `originalBytes`) against `entry`'s public key. */
function verifySignature(object: Map<string, Value>, entry: KeyEntry): void {
  const bytes = canonicalSigningBytes(object);
  const ok = verifyObject(entry.publicKey, bytes, objectSig(object));
  if (!ok) {
    throw new IdentityError("E_INVALID_SIGNATURE", "signature verification failed");
  }
}

/** One practitioner's identity log — see `crates/praxis-identity/src/log.rs`'s
 * module docs for the scope boundary (no causal/`prev` ordering or
 * case-lifecycle rules here; `praxis-validate`'s job, one layer up). */
export class IdentityLog {
  private readonly keys = new Map<string, KeyRecord>();
  private currentRootKid: string;
  private lastTs: bigint;
  public readonly did: string;

  private constructor(did: string, rootKid: string, ts: bigint) {
    this.did = did;
    this.currentRootKid = rootKid;
    this.lastTs = ts;
  }

  public static genesis(originalBytes: Uint8Array, content: IdContent): IdentityLog {
    const object = decodeObjectMap(originalBytes);
    if (objectKind(object) !== "id-genesis" || content.op !== "genesis") {
      throw new IdentityError("E_KIND_OP_MISMATCH", "object kind does not match identity content op");
    }
    if (objectAuthor(object) !== GENESIS_AUTHOR_SENTINEL) {
      throw new IdentityError("E_INVALID_GENESIS_AUTHOR", "id-genesis.author must be the fixed sentinel");
    }
    const entries = content.keys ?? [];
    if (entries.length === 0) {
      throw new IdentityError("E_GENESIS_HAS_NO_KEYS", "id-genesis must list at least one key");
    }
    const signerEntry = entries.find((k) => k.kid === objectSigner(object) && k.role === "root");
    if (signerEntry === undefined) {
      throw new IdentityError("E_UNAUTHORIZED_SIGNER", "signer is not listed in id-genesis as a root key");
    }
    verifySignature(object, signerEntry);

    const cid = objectId(originalBytes);
    const did = `did:praxis:${cid.toString()}`;

    const log = new IdentityLog(did, signerEntry.kid, objectTs(object));
    for (const entry of entries) {
      log.insertNewKey(entry);
    }
    return log;
  }

  public apply(originalBytes: Uint8Array, content: IdContent): void {
    const object = decodeObjectMap(originalBytes);
    const ts = objectTs(object);
    if (ts < this.lastTs) {
      throw new IdentityError("E_TS_NOT_MONOTONIC", "object ts precedes this log's last-applied event");
    }
    if (content.op === "genesis") {
      throw new IdentityError("E_UNEXPECTED_GENESIS", "a log has exactly one genesis event");
    } else if (content.op === "rotate") {
      this.applyRotate(object, content);
    } else if (content.op === "delegate") {
      this.applyDelegate(object, content);
    } else {
      this.applyRevoke(object, content);
    }
  }

  private applyRotate(object: Map<string, Value>, content: IdContent): void {
    if (objectKind(object) !== "id-rotate") {
      throw new IdentityError("E_KIND_OP_MISMATCH", "object kind does not match identity content op");
    }
    const signerEntry = this.requireRootOrRecoverySigner(object);
    verifySignature(object, signerEntry);

    const entries = content.keys ?? [];
    if (entries.length !== 1) {
      throw new IdentityError("E_INVALID_PAYLOAD", "id-rotate must list exactly one key");
    }
    const newRoot = entries[0];
    if (newRoot === undefined || newRoot.role !== "root") {
      throw new IdentityError("E_INVALID_PAYLOAD", "id-rotate's key must have role root");
    }

    const oldRoot = this.keys.get(this.currentRootKid);
    if (oldRoot !== undefined) {
      oldRoot.retiredAt = objectTs(object);
    }
    this.insertNewKey(newRoot);
    this.currentRootKid = newRoot.kid;
    this.lastTs = objectTs(object);
  }

  private applyDelegate(object: Map<string, Value>, content: IdContent): void {
    if (objectKind(object) !== "id-delegate") {
      throw new IdentityError("E_KIND_OP_MISMATCH", "object kind does not match identity content op");
    }
    const signerEntry = this.requireRootOrRecoverySigner(object);
    verifySignature(object, signerEntry);

    const entries = content.keys ?? [];
    if (entries.length === 0) {
      throw new IdentityError("E_INVALID_PAYLOAD", "id-delegate must list at least one key");
    }
    for (const entry of entries) {
      this.insertNewKey(entry);
    }
    this.lastTs = objectTs(object);
  }

  private applyRevoke(object: Map<string, Value>, content: IdContent): void {
    if (objectKind(object) !== "id-revoke") {
      throw new IdentityError("E_KIND_OP_MISMATCH", "object kind does not match identity content op");
    }
    const revoke = content.revoke;
    if (revoke === null) {
      throw new IdentityError("E_INVALID_PAYLOAD", "id-revoke must carry a revoke record");
    }

    const signer = objectSigner(object);
    if (signer === revoke.kid) {
      const record = this.keys.get(signer);
      if (record === undefined) {
        throw new IdentityError("E_UNKNOWN_SIGNER", `signer key ${signer} is not known to this identity log`);
      }
      if (!withinValidityWindow(record, objectTs(object))) {
        throw new IdentityError("E_UNAUTHORIZED_SIGNER", `key ${signer} is not authorized to sign this operation`);
      }
      verifySignature(object, record.entry);
    } else {
      const signerEntry = this.requireRootOrRecoverySigner(object);
      verifySignature(object, signerEntry);
    }

    const target = this.keys.get(revoke.kid);
    if (target === undefined) {
      throw new IdentityError("E_UNKNOWN_REVOKE_TARGET", `id-revoke targets unknown key id ${revoke.kid}`);
    }
    target.retiredAt = revoke.effective;
    target.compromisedSince = revoke.compromisedSince;
    this.lastTs = objectTs(object);
  }

  private insertNewKey(entry: KeyEntry): void {
    if (this.keys.has(entry.kid)) {
      throw new IdentityError("E_DUPLICATE_KID", `key id ${entry.kid} is already present in this identity log`);
    }
    this.keys.set(entry.kid, { entry, retiredAt: null, compromisedSince: null });
  }

  private requireRootOrRecoverySigner(object: Map<string, Value>): KeyEntry {
    const signer = objectSigner(object);
    const record = this.keys.get(signer);
    if (record === undefined) {
      throw new IdentityError("E_UNKNOWN_SIGNER", `signer key ${signer} is not known to this identity log`);
    }
    if (record.entry.role !== "root" && record.entry.role !== "recovery") {
      throw new IdentityError("E_UNAUTHORIZED_SIGNER", `key ${signer} is not authorized to sign this operation`);
    }
    if (!withinValidityWindow(record, objectTs(object))) {
      throw new IdentityError("E_UNAUTHORIZED_SIGNER", `key ${signer} is not authorized to sign this operation`);
    }
    return record.entry;
  }

  /** `spec/PROTOCOL.md` §4.4's "signer key was authorized by the identity log
   * at the object's `ts`", for ordinary (non-identity) objects. */
  public isAuthorized(kid: string, at: bigint, forKind: string | null): boolean {
    const record = this.keys.get(kid);
    if (record === undefined) {
      return false;
    }
    if (!withinValidityWindow(record, at)) {
      return false;
    }
    if (forKind !== null && record.entry.scope !== null && !record.entry.scope.includes(forKind)) {
      return false;
    }
    return true;
  }

  public compromisedSince(kid: string): bigint | null {
    return this.keys.get(kid)?.compromisedSince ?? null;
  }
}
