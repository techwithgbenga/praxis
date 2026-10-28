#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
"""Stage `mdbook/src/` as a mirror of the repo-root-relative paths the project's
Markdown actually cross-links (M0-05).

Why a mirror instead of per-page `{{#include}}` wrappers: README.md, docs/*.md,
spec/*.md etc. all link each other with paths relative to the repo root (e.g.
`docs/VISION.md` from README.md, `../ETHICS.md` from docs/VISION.md). Those links
only resolve if the file sits at the *same relative position* inside `mdbook/src/`
as it does in the repo. Copying (not including) each file into that mirrored
position makes every such link resolve for `mdbook-linkcheck`, with `docs/` and
`spec/` staying the single source of truth: this script's output is generated,
gitignored, and rebuilt by `just docs` (see .gitignore, justfile).

Only `mdbook/src/SUMMARY.md` is hand-written and real; everything else under
`mdbook/src/` is produced by this script.
"""

from __future__ import annotations

import shutil
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEST = REPO_ROOT / "mdbook" / "src"

# Root-relative files and directories the cross-linked docs actually reference
# (see justfile `docs` / `just ci`'s link check). Keep in sync with README.md's
# repository map and docs/AGENTS.md §1 reading order.
FILES = [
    "README.md",
    "AGENTS.md",
    "GOVERNANCE.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "ETHICS.md",
    "LICENSING.md",
    "ROADMAP.md",
    "CODE_OF_CONDUCT.md",
    "scripts/publish.sh",
]
DIRS = ["docs", "spec", "adr", "packs", "LICENSES"]

# mdbook-linkcheck resolves a directory link like `[x](LICENSES/)` to
# `LICENSES/README.md`, but that directory is just license texts (no README
# needed in the real repo). Synthesize one in the staged copy only.
SYNTHETIC_README = {
    "LICENSES/README.md": (
        "# Licenses\n\nFull texts for every SPDX identifier this project uses "
        "(see [LICENSING.md](../LICENSING.md)):\n\n"
        "- [Apache-2.0](Apache-2.0.txt)\n"
        "- [AGPL-3.0-or-later](AGPL-3.0-or-later.txt)\n"
        "- [CC-BY-4.0](CC-BY-4.0.txt)\n"
    ),
}


def clean() -> None:
    for entry in DEST.iterdir():
        if entry.name == "SUMMARY.md":
            continue
        if entry.is_dir():
            shutil.rmtree(entry)
        else:
            entry.unlink()


def main() -> int:
    DEST.mkdir(parents=True, exist_ok=True)
    clean()

    for rel in FILES:
        src = REPO_ROOT / rel
        if not src.exists():
            print(f"warning: {rel} listed but missing, skipping")
            continue
        dest = DEST / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)

    for rel in DIRS:
        src = REPO_ROOT / rel
        if not src.exists():
            print(f"warning: {rel}/ listed but missing, skipping")
            continue
        shutil.copytree(src, DEST / rel)

    for rel, content in SYNTHETIC_README.items():
        (DEST / rel).write_text(content, encoding="utf-8")

    print(f"staged mdbook/src from {len(FILES)} files + {len(DIRS)} directories.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
