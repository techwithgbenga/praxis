#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
"""Enforce the crate dependency rules in docs/ARCHITECTURE.md §3.

Runs `cargo metadata`, then checks that every first-party `praxis-*` crate only
depends (via a local path dependency) on the other `praxis-*` crates it is
allowed to, per the table below. Fails with a non-zero exit code and a
human-readable diff on any violation (extra or disallowed edge).

This script intentionally does not check external (crates.io) dependencies;
that is `cargo deny`'s job (see deny.toml).
"""

from __future__ import annotations

import json
import subprocess
import sys

# Mirrors docs/ARCHITECTURE.md §3 exactly. Update both together.
ALLOWED: dict[str, set[str]] = {
    "praxis-types": set(),
    "praxis-crypto": {"praxis-types"},
    "praxis-identity": {"praxis-types", "praxis-crypto"},
    "praxis-validate": {"praxis-types", "praxis-crypto", "praxis-identity"},
    "praxis-store": {"praxis-types", "praxis-validate"},
    "praxis-policy": {"praxis-types"},
    "praxis-score": {"praxis-types"},
    "praxis-surprise": {"praxis-types", "praxis-score"},
    "praxis-sync": {"praxis-types", "praxis-validate", "praxis-store"},
    "praxis-core": {
        "praxis-types",
        "praxis-crypto",
        "praxis-identity",
        "praxis-validate",
        "praxis-store",
        "praxis-policy",
        "praxis-score",
        "praxis-surprise",
        "praxis-sync",
    },
    "praxis-cli": {"praxis-core"},
    "praxisd": {"praxis-core"},
    "praxis-wasm": {"praxis-core"},
    "praxis-ffi": {"praxis-core"},
    "praxis-relay": {"praxis-types", "praxis-sync", "praxis-store", "praxis-policy"},
    "praxis-registry": {"praxis-types", "praxis-sync", "praxis-store", "praxis-policy"},
}


def cargo_metadata() -> dict:
    out = subprocess.run(
        ["cargo", "metadata", "--format-version=1", "--no-deps"],
        capture_output=True,
        text=True,
        check=False,
    )
    if out.returncode != 0:
        sys.stderr.write(out.stderr)
        sys.exit("cargo metadata failed")
    return json.loads(out.stdout)


def main() -> int:
    meta = cargo_metadata()
    packages = {p["name"]: p for p in meta["packages"]}

    unknown = sorted(set(packages) - set(ALLOWED) - {"praxis"})
    if unknown:
        print(f"note: workspace crate(s) not in the dep-graph rule table: {unknown}")

    violations: list[str] = []
    for name, rules in ALLOWED.items():
        pkg = packages.get(name)
        if pkg is None:
            violations.append(f"{name}: declared in rules but missing from the workspace")
            continue
        declared = {
            dep["name"]
            for dep in pkg["dependencies"]
            if dep.get("path") and dep["name"].startswith("praxis")
        }
        extra = declared - rules
        if extra:
            violations.append(f"{name}: depends on disallowed crate(s) {sorted(extra)} (allowed: {sorted(rules) or 'none'})")

    if violations:
        print("Dependency-graph check FAILED (docs/ARCHITECTURE.md §3):")
        for v in violations:
            print(f"  - {v}")
        return 1

    print(f"Dependency-graph check OK ({len(ALLOWED)} crates, rules satisfied).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
