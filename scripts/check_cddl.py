#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
"""Lint spec/praxis-v0.1.cddl (M0-04).

Prefers the `cddl` CLI (https://github.com/anweiss/cddl, `cargo install cddl`) when
present, which gives real RFC 8610 grammar validation. Falls back to a conservative
structural smoke-check (balanced braces/brackets, no stray tabs, every `rule =`
left-hand side defined once) so `just ci` still catches gross breakage on a machine
where the `cddl` crate isn't installed yet.

TODO(M0-04): once `cddl` is installed in CI, confirm its exact subcommand/flags
(this script assumes `cddl compile-cddl --cddl <file>`; adjust if the installed
version's CLI differs) and drop the structural fallback down to a hard dependency.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

CDDL_FILE = Path("spec/praxis-v0.1.cddl")


def run_cddl_cli() -> int | None:
    binary = shutil.which("cddl")
    if binary is None:
        return None
    result = subprocess.run(
        [binary, "compile-cddl", "--cddl", str(CDDL_FILE)],
        capture_output=True,
        text=True,
        check=False,
    )
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    return result.returncode


def structural_fallback() -> int:
    text = CDDL_FILE.read_text(encoding="utf-8")
    if "\t" in text:
        print("structural CDDL check FAILED: tab character present (CDDL is whitespace-sensitive)")
        return 1
    for open_c, close_c in (("{", "}"), ("[", "]"), ("(", ")")):
        if text.count(open_c) != text.count(close_c):
            print(f"structural CDDL check FAILED: unbalanced '{open_c}{close_c}'")
            return 1
    rule_names = re.findall(r"^([A-Za-z][A-Za-z0-9-]*)\s*=", text, flags=re.MULTILINE)
    seen: set[str] = set()
    dupes = {n for n in rule_names if (n in seen) or seen.add(n)}  # type: ignore[func-returns-value]
    if dupes:
        print(f"structural CDDL check FAILED: rule(s) defined more than once: {sorted(dupes)}")
        return 1
    print(f"structural CDDL check OK ({len(rule_names)} rules; `cddl` CLI not installed, this is a smoke-check only).")
    return 0


def main() -> int:
    if not CDDL_FILE.exists():
        print(f"CDDL check FAILED: {CDDL_FILE} not found")
        return 1
    cli_result = run_cddl_cli()
    if cli_result is not None:
        return cli_result
    return structural_fallback()


if __name__ == "__main__":
    sys.exit(main())
