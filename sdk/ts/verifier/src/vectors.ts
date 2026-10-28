// SPDX-License-Identifier: Apache-2.0
//
// Loads `spec/test-vectors/**/*.vec.json` (spec/test-vectors/README.md's
// format) for the `*.test.ts` files to run against.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export interface VectorFile {
  readonly id: string;
  readonly spec: string;
  readonly description: string;
  readonly input: unknown;
  readonly expected: unknown;
}

const REPO_ROOT = fileURLToPath(new URL("../../../../", import.meta.url));

export function loadVector(id: string): VectorFile {
  const path = `${REPO_ROOT}spec/test-vectors/${id}.vec.json`;
  const text = readFileSync(path, "utf-8");
  return JSON.parse(text) as VectorFile;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error(`odd-length hex string: ${hex}`);
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
