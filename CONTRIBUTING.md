# Contributing to Praxis

Welcome. This project handles people's most valuable asset: their judgment. Quality and care matter more than speed.

## Ways to contribute
Code · spec review (**breaking the spec is a contribution**) · test vectors · domain packs (with real practitioners) · security review · UX research · docs/translations · running the evaluation study.

## Ground rules
1. Read `README.md`, `AGENTS.md` (applies to humans too: it is our engineering standard), and `ETHICS.md`.
2. **DCO sign-off** on every commit (`git commit -s`). No CLA.
3. Conventional Commits (`feat:`, `fix:`, `docs:`, `spec:`, `test:`, `chore:`).
4. One logical change per PR; link the task ID (e.g., `M1-03`) or issue.
5. Tests are required. Spec changes need **test vectors**. Crypto/sync/policy/scoring changes need 2 maintainer approvals.
6. No telemetry, no phone-home, no features that violate ETHICS.md §2. Such PRs are closed.
7. Be kind. See `CODE_OF_CONDUCT.md`.

## Dev setup (after M0)
```bash
git clone https://github.com/techwithgbenga/praxis && cd praxis
just setup      # toolchains, hooks
just ci         # everything CI runs
```

## Proposing spec changes
Open a **PIP** (`spec/pips/NNNN-title.md`) per `GOVERNANCE.md §4`.

## Proposing a domain pack
Open a "Pack proposal" issue with: domain, risk tier, 3+ practitioner co-authors, governance plan.

## Reporting security issues
Do **not** open a public issue. See `SECURITY.md`.

## Recognition
All contributors are credited in `CONTRIBUTORS.md` and release notes. Domain steward and practitioner-reviewer credit is first-class.
