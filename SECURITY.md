# Security Policy

## Reporting a vulnerability
Email **security@<project-domain>** (PGP key published at `/.well-known/security.txt` and in this repo as `SECURITY-KEY.asc`), or use GitHub's private vulnerability reporting. Please do **not** open public issues for vulnerabilities.
- Acknowledgement within **3 business days**; triage within **7**; coordinated disclosure target **90 days** (sooner if actively exploited).
- Good-faith research is welcome; we will not pursue legal action for responsible disclosure within scope.

## Scope
In scope: object parsing/validation, signature/identity logic, sealing/key handling, policy evaluation, sync protocol and relay, apprentice-kernel trust boundary, desktop app IPC, supply-chain and release pipeline.
Out of scope: social engineering of maintainers, physical attacks, third-party model provider issues (report upstream), denial-of-service by volumetric flooding against hosted relays.

## Severity & priorities
Highest: anything enabling **forgery/backdating**, **key compromise**, **plaintext exposure of sealed bodies**, **policy bypass of `forbid` rules**, or **RCE via parsers**.

## Engineering requirements (summary)
- No custom cryptography; only audited libraries (see `docs/TECH_STACK.md`).
- `forbid(unsafe_code)` outside isolated FFI; fuzzing of all parsers; dependency review with `cargo-vet`/`cargo-deny`.
- Secrets never in logs; test keys clearly marked `TEST_ONLY_`.
- Signed releases (Sigstore), SBOM, reproducible-build target.
- **Gate for 1.0:** external cryptography review and penetration test with no open High findings.

## Supported versions
Pre-1.0: only the latest release receives fixes. After 1.0: the latest two minor versions.

## Hall of fame
Researchers who report valid issues are credited (with permission) in `SECURITY-ACKNOWLEDGEMENTS.md`.
