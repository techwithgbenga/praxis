#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
"""Verify every tracked source file carries an SPDX-License-Identifier header.

See docs/LICENSING.md §1 ("Every source file carries an SPDX-License-Identifier
header"). Apache-2.0 for libraries/CLI/SDKs/schemas, AGPL-3.0-or-later for the
two server crates, CC-BY-4.0 for spec/docs prose.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

CHECKED_SUFFIXES = {
    ".rs", ".toml", ".ts", ".tsx", ".py", ".proto", ".cddl", ".cedar",
}
# Files that are checked but may legitimately have no header (generated, data-only, etc).
EXEMPT_NAMES = {"Cargo.lock", "package-lock.json", "pnpm-lock.yaml", "uv.lock"}
EXEMPT_DIR_PARTS = {"target", "node_modules", ".venv", "dist", "book", "__pycache__"}

EXPECTED = {
    "Apache-2.0": "Apache-2.0",
    "AGPL-3.0-or-later": "AGPL-3.0-or-later",
}

# Server crates ship under AGPL; everything else checked here ships under Apache-2.0.
AGPL_PATH_PREFIXES = ("crates/praxis-relay/", "crates/praxis-registry/")


def tracked_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files"], capture_output=True, text=True, check=True
    )
    return [Path(p) for p in out.stdout.splitlines() if p]


def expected_spdx(path: Path) -> str | None:
    posix = path.as_posix()
    if path.suffix not in CHECKED_SUFFIXES or path.name in EXEMPT_NAMES:
        return None
    if any(part in EXEMPT_DIR_PARTS for part in path.parts):
        return None
    if posix.startswith(AGPL_PATH_PREFIXES):
        return "AGPL-3.0-or-later"
    return "Apache-2.0"


def has_header(path: Path, spdx_id: str) -> bool:
    try:
        head = path.read_text(encoding="utf-8", errors="strict")[:400]
    except (OSError, UnicodeDecodeError):
        return False
    return f"SPDX-License-Identifier: {spdx_id}" in head


def main() -> int:
    missing: list[str] = []
    for path in tracked_files():
        if not path.exists():
            continue  # deleted-but-still-staged edge case
        spdx_id = expected_spdx(path)
        if spdx_id is None:
            continue
        if not has_header(path, spdx_id):
            missing.append(f"{path.as_posix()} (expected `SPDX-License-Identifier: {spdx_id}`)")

    if missing:
        print("SPDX header check FAILED:")
        for m in missing:
            print(f"  - {m}")
        return 1

    print("SPDX header check OK.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
