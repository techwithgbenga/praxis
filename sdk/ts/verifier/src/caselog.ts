// SPDX-License-Identifier: Apache-2.0
//
// The case-lifecycle state machine (spec/PROTOCOL.md §6, rules C1-C8) — an
// independent port of crates/praxis-validate/src/case_log.rs's `CaseLog`.
// Same scope boundary as the Rust original: no signature checks, no I/O, no
// end-to-end orchestration (picking which `CaseLog` an object belongs to,
// looking up causal parents by CID) — that's `praxis-core`'s job, later.

import { Cid } from "./cid.js";
import { DecodeError, type Value } from "./dagcbor.js";
import { decodeObjectMap, objectCase, objectId, objectKind, objectPlainContent, objectPrev } from "./object.js";

export class ValidateError extends Error {
  public constructor(
    public readonly code: string,
    message: string,
    public readonly detail?: string,
  ) {
    super(message);
    this.name = "ValidateError";
  }
}

function asMap(value: Value, context: string): Map<string, Value> {
  if (!(value instanceof Map)) {
    throw new DecodeError("E_DECODE", `expected a map for ${context}`);
  }
  return value;
}
function asArray(value: Value | undefined, context: string): Value[] {
  if (!Array.isArray(value)) {
    throw new DecodeError("E_DECODE", `expected an array for ${context}`);
  }
  return value;
}
function asString(value: Value | undefined, context: string): string {
  if (typeof value !== "string") {
    throw new DecodeError("E_DECODE", `expected a string for ${context}`);
  }
  return value;
}

/** Pulls the claim ids out of a `claims`/`amend` body's claim list, the only
 * part of each claim `CaseLog` itself inspects (statement/p/resolve/horizon
 * shape validation is `Claim`'s own type's job on the Rust side, M1-01 —
 * out of scope for this verifier, which only re-checks the *lifecycle*
 * rules C1-C8). */
function claimIds(content: Map<string, Value>, field: string): { id: string; late: boolean }[] {
  const claimsValue = content.get(field);
  if (claimsValue === undefined) {
    return [];
  }
  return asArray(claimsValue, `claims body's ${field}`).map((claim, i) => {
    const claimMap = asMap(claim, `${field}[${String(i)}]`);
    const id = asString(claimMap.get("id"), `${field}[${String(i)}].id`);
    const lateValue = claimMap.get("late");
    return { id, late: lateValue === true };
  });
}

function outcomeClaimIds(content: Map<string, Value>): string[] {
  const results = asArray(content.get("results"), "outcome-body.results");
  return results.map((result, i) => {
    const resultMap = asMap(result, `outcome-body.results[${String(i)}]`);
    return asString(resultMap.get("claim"), `outcome-body.results[${String(i)}].claim`);
  });
}

function prevContains(prev: readonly Cid[], target: Cid): boolean {
  return prev.some((p) => p.equals(target));
}

/** One case's accumulated lifecycle state. */
export class CaseLog {
  private readonly caseIdValue: Cid;
  private readonly predictions = new Set<string>();
  private decisionId: Cid | null = null;
  private claimsObjectSeen = false;
  private readonly claimIdSet = new Set<string>();
  private outcomeSeen = false;
  private abandoned = false;
  private retracted = false;

  private constructor(caseId: Cid) {
    this.caseIdValue = caseId;
  }

  /** Starts a new case from its `open` object (C1): its own id *is* the case
   * id. */
  public static open(originalBytes: Uint8Array): CaseLog {
    const object = decodeObjectMap(originalBytes);
    if (objectKind(object) !== "open") {
      throw new ValidateError("E_KIND_CONTENT_MISMATCH", "expected an open object");
    }
    if (objectCase(object) !== null) {
      throw new ValidateError("E_CASE_FIELD_SHAPE", "open must not itself carry a case field");
    }
    return new CaseLog(objectId(originalBytes));
  }

  public get caseId(): Cid {
    return this.caseIdValue;
  }
  public get isAbandoned(): boolean {
    return this.abandoned;
  }
  public get isRetracted(): boolean {
    return this.retracted;
  }
  public get hasDecision(): boolean {
    return this.decisionId !== null;
  }
  public get hasOutcome(): boolean {
    return this.outcomeSeen;
  }

  /** Applies a non-`open` case-event object to this case. */
  public apply(originalBytes: Uint8Array): void {
    const object = decodeObjectMap(originalBytes);
    const objectCid = objectId(originalBytes);
    const caseField = objectCase(object);
    if (caseField === null || !caseField.equals(this.caseIdValue)) {
      throw new ValidateError("E_CASE_FIELD_SHAPE", "object.case does not match this case's id");
    }
    const kind = objectKind(object);
    const prev = objectPrev(object);
    const content = asMap(objectPlainContent(object), "object.body.plain");

    switch (kind) {
      case "open":
        throw new ValidateError("E_DUPLICATE_OPEN", "a case may have only one open object");
      case "prediction":
        this.predictions.add(objectCid.toString());
        return;
      case "decision":
        this.applyDecision(prev, objectCid);
        return;
      case "claims":
        this.applyClaims(prev, content);
        return;
      case "elicitation":
        return;
      case "outcome":
        this.applyOutcome(content);
        return;
      case "amend":
        this.applyAmend(content);
        return;
      case "retract":
        this.retracted = true;
        return;
      case "abandon":
        this.applyAbandon();
        return;
      default:
        throw new ValidateError("E_KIND_CONTENT_MISMATCH", `unexpected case-event kind ${kind}`);
    }
  }

  /** C2: a prediction MUST causally precede the decision it concerns. */
  private applyDecision(prev: readonly Cid[], objectCid: Cid): void {
    if (!prev.some((p) => this.predictions.has(p.toString()))) {
      throw new ValidateError("E_MISSING_PREDICTION", "decision.prev does not reference a prior prediction");
    }
    this.decisionId = objectCid;
  }

  /** C3/C4. */
  private applyClaims(prev: readonly Cid[], content: Map<string, Value>): void {
    if (this.decisionId === null) {
      throw new ValidateError("E_CASE_NOT_OPEN", "claims requires a prior decision");
    }
    if (!prevContains(prev, this.decisionId)) {
      throw new ValidateError("E_CLAIMS_NOT_AFTER_DECISION", "claims.prev does not reference the decision");
    }
    if (this.claimsObjectSeen) {
      throw new ValidateError("E_DUPLICATE_CLAIMS", "a case may have only one claims object");
    }
    for (const { id } of claimIds(content, "claims")) {
      if (this.claimIdSet.has(id)) {
        throw new ValidateError("E_DUPLICATE_CLAIM_ID", `duplicate claim id ${id}`, id);
      }
      this.claimIdSet.add(id);
    }
    this.claimsObjectSeen = true;
  }

  /** C6. */
  private applyOutcome(content: Map<string, Value>): void {
    for (const id of outcomeClaimIds(content)) {
      if (!this.claimIdSet.has(id)) {
        throw new ValidateError("E_UNKNOWN_CLAIM", `outcome resolves unknown claim id ${id}`, id);
      }
    }
    this.outcomeSeen = true;
  }

  /** C5: late claims must be flagged `late: true` and must not reuse an
   * existing claim id. */
  private applyAmend(content: Map<string, Value>): void {
    for (const { id, late } of claimIds(content, "late_claims")) {
      if (!late) {
        throw new ValidateError("E_LATE_CLAIM_NOT_FLAGGED", `late claim ${id} not flagged late:true`, id);
      }
      if (this.claimIdSet.has(id)) {
        throw new ValidateError("E_AMEND_REUSES_CLAIM_ID", `amend reuses existing claim id ${id}`, id);
      }
      this.claimIdSet.add(id);
    }
  }

  /** C8: abandon closes an *unresolved* case. */
  private applyAbandon(): void {
    if (this.outcomeSeen) {
      throw new ValidateError("E_ABANDON_AFTER_OUTCOME", "abandon after outcome");
    }
    if (this.decisionId !== null) {
      throw new ValidateError("E_ABANDON_AFTER_DECISION", "abandon after decision");
    }
    this.abandoned = true;
  }
}
