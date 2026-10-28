#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
"""Generate a JSON Schema artifact from spec/praxis-v0.1.cddl (M0-04).

Requires the `cddl` CLI (`cargo install cddl`; https://github.com/anweiss/cddl).

TODO(M0-04): confirm the installed `cddl` version's exact JSON-Schema subcommand
and flags against spec/praxis-v0.1.cddl's root rule (`object`) and update the
invocation below; this is intentionally not wired into `just ci` yet so a missing
or mismatched CLI doesn't block the required gate. Once confirmed, commit the
generated schema under spec/praxis-v0.1.schema.json and add a drift check
(`cddl` regen == committed file) to `just ci`.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

CDDL_FILE = Path("spec/praxis-v0.1.cddl")
OUT_FILE = Path("spec/praxis-v0.1.schema.json")


def main() -> int:
    binary = shutil.which("cddl")
    if binary is None:
        print("`cddl` CLI not found on PATH; install with `cargo install cddl`.")
        return 1
    result = subprocess.run(
        [binary, "json-schema", "--cddl", str(CDDL_FILE), "--root", "object"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        print("note: the `cddl` CLI's JSON-Schema subcommand/flags may differ by version; see TODO above.")
        return result.returncode
    OUT_FILE.write_text(result.stdout, encoding="utf-8")
    print(f"wrote {OUT_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
