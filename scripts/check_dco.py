#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
"""Verify every commit on this branch (vs. the merge base with origin/main) carries a
DCO `Signed-off-by` trailer matching its author (AGENTS.md §2: "Sign off commits
(DCO: `git commit -s`)"). Mirrors what the DCO GitHub App checks on the PR.
"""

from __future__ import annotations

import subprocess
import sys


def run(*args: str) -> str:
    return subprocess.run(args, capture_output=True, text=True, check=True).stdout.strip()


def merge_base() -> str:
    for base in ("origin/main", "main"):
        try:
            return run("git", "merge-base", "HEAD", base)
        except subprocess.CalledProcessError:
            continue
    # Single-commit / first-commit repos: check just HEAD.
    return run("git", "rev-list", "--max-parents=0", "HEAD").splitlines()[0]


def main() -> int:
    try:
        base = merge_base()
    except subprocess.CalledProcessError as exc:
        print(f"note: could not determine merge base, skipping DCO check: {exc}")
        return 0

    commits = run("git", "rev-list", f"{base}..HEAD").splitlines()
    if not commits:
        commits = [run("git", "rev-parse", "HEAD")]

    missing: list[str] = []
    for sha in commits:
        author = run("git", "show", "-s", "--format=%an <%ae>", sha)
        body = run("git", "show", "-s", "--format=%B", sha)
        if f"Signed-off-by: {author}" not in body:
            missing.append(f"{sha[:12]} by {author}")

    if missing:
        print("DCO check FAILED (missing `Signed-off-by` trailer, use `git commit -s`):")
        for m in missing:
            print(f"  - {m}")
        return 1

    print(f"DCO check OK ({len(commits)} commit(s)).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
