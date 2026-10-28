# SPDX-License-Identifier: Apache-2.0
# Praxis task runner. Install `just`: https://github.com/casey/just
# `just ci` is the single source of truth CI runs (AGENTS.md §2); keep it green locally
# before opening a PR.

set shell := ["bash", "-euo", "pipefail", "-c"]

default: ci

# Everything a PR must pass (AGENTS.md §2, §3; EVALUATION.md §5).
ci: spdx-check dco-check fmt-check lint test deny dep-graph cddl-lint docs

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

lint:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
    cargo test --workspace --all-features

deny:
    cargo deny check

audit:
    cargo audit

vet:
    cargo vet check

docs:
    cargo doc --workspace --no-deps --document-private-items=false
    python scripts/gen_mdbook_src.py
    mdbook build mdbook

docs-serve:
    python scripts/gen_mdbook_src.py
    mdbook serve mdbook --open

dep-graph:
    python scripts/check_dep_graph.py

cddl-lint:
    python scripts/check_cddl.py

gen-schema:
    python scripts/gen_json_schema.py

spdx-check:
    python scripts/check_spdx_headers.py

dco-check:
    python scripts/check_dco.py

fuzz-smoke:
    echo "TODO(M1-10): cargo-fuzz targets land with praxis-validate; smoke-run each 60s here."

# Convenience: everything `just ci` runs, plus the nightly-only fuzz smoke.
ci-full: ci fuzz-smoke
