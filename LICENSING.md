# Licensing, Trademark & Data Ownership

## 1. Code & text licenses (SPDX)

| Component | License | Why |
|---|---|---|
| `spec/` and `docs/` (text) | **CC-BY-4.0** | Standards must be freely implementable and quotable, with attribution |
| `spec/praxis-v0.1.cddl`, test vectors | **Apache-2.0** | Machine-readable artifacts; includes patent grant for implementers |
| `crates/praxis-*` libraries, `praxis-cli`, `praxisd`, `praxis-wasm`, `sdk/*`, `apps/desk`, `bench/`, `packs/*` | **Apache-2.0** | Maximizes adoption; patent grant; compatible with most ecosystems |
| `crates/praxis-relay`, `crates/praxis-registry` (servers) | **AGPL-3.0-or-later** | Prevents a hyperscaler from running a closed hosted fork without contributing back (the Elastic/Mongo problem) |

Full texts: [`LICENSES/`](LICENSES/). Every source file carries an `SPDX-License-Identifier` header.
Contributions are accepted under the license of the component they touch, via **DCO** sign-off (no CLA), so the project cannot be relicensed unilaterally.

## 2. Why the ethics are not in the license
Ethical-use clauses (e.g. "no employee surveillance") make a license non-OSI-compliant, are hard to enforce, and fragment the ecosystem.
Instead, ethics are enforced through:
1. **Architecture**: practitioner-owned keys, local-first, sealed bodies, per-case policy, selective disclosure (see `docs/PRIVACY_AND_THREAT_MODEL.md`).
2. **Trademark & certification**: only implementations that pass the conformance suite *including the privacy conformance tests* may use the "Praxis Compatible" mark.
3. **Hosted-service terms**: the official relay/registry terms of service prohibit use for employment evaluation without per-disclosure practitioner consent.
4. **Social contract**: [ETHICS.md](ETHICS.md), the Practitioner Charter.

## 3. Trademark
- The name and logo are held by the project's steward (an interim legal entity, to be transferred to a neutral foundation; see GOVERNANCE.md).
- Anyone may implement the protocol and say it is "compatible with the Praxis protocol".
- The "Praxis Compatible" mark requires passing the conformance suite.
- **Action before launch:** clearance search for the final name; the working name `Praxis` is generic and heavily used.

## 4. Data ownership
- A practitioner **owns** their cases, keys, lineage, and calibration history.
- Default visibility is **Private**. Sharing is per-case, via explicit policy (`spec/POLICY.md`).
- Contributing to a Canon grants the Canon's *declared* license only for the declared uses (retrieval / training / calibration publication). Grants are recorded in-protocol and honored by compliant clients.
- **Honest limit:** once ciphertext or plaintext has been shared with a third party, revocation cannot guarantee deletion. The protocol records revocations, compliant clients and official services honor them, and future key access is withdrawn, but see the threat model.

## 5. Third-party dependencies
Only permissive (MIT/Apache-2.0/BSD/ISC/MPL-2.0 with care) dependencies are allowed in Apache-2.0 components. `cargo deny` enforces an allow-list; GPL/AGPL dependencies are forbidden outside the AGPL servers.
