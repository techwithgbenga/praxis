# Governance

## 1. Goals
Keep the protocol **neutral, long-lived, and un-capturable**, while moving fast enough to ship.

## 2. Phases
| Phase | Trigger | Structure |
|---|---|---|
| **Founding** (now) | project start | Interim **Steward** (the founder) + **Maintainers** (appointed by Steward). Decisions by lazy consensus; Steward breaks ties. |
| **Council** | ≥ 5 non-affiliated active maintainers *or* 12 months | **Technical Steering Committee (TSC)** of 5–7, elected by maintainers; no single employer > 2 seats. |
| **Foundation** | before v1.0 *or* 24 months, whichever first | Transfer trademark, domains, and spec stewardship to a neutral non-profit foundation (candidate hosts: Linux Foundation, Apache Software Foundation, Software Freedom Conservancy, or a purpose-built foundation). Practitioner representatives hold reserved seats. |

## 3. Roles
- **Contributor**: anyone with an accepted PR.
- **Maintainer**: commit rights to a component; nominated by existing maintainers, approved by 2/3.
- **Steward/TSC**: spec stewardship, releases, trademark policy, conflict resolution.
- **Practitioner Council** (from Council phase): elected users with veto over changes touching ETHICS.md or the privacy-conformance suite.

## 4. Praxis Improvement Proposals (PIPs)
Any change to `spec/` or ETHICS.md goes through a PIP in `spec/pips/NNNN-title.md`:
`Draft → Review (≥14 days) → Last Call (7 days) → Accepted/Rejected → Final (shipped in a spec release)`.
A PIP must include: motivation, specification, backward compatibility, security/privacy impact, test vectors, reference implementation status.
Protocol changes that break wire compatibility require a major spec version and a migration path.

## 5. Decision rules
- Routine code: 1 maintainer approval (2 for crypto, sync, policy, scoring).
- Spec / ADR: TSC (or Steward in Founding phase) after Last Call.
- Ethics/privacy-conformance changes: Practitioner Council veto (once constituted).
- Disputes: escalate to TSC; binding after a public rationale is published.

## 6. Anti-capture rules
- No single company may hold >40% of maintainer seats.
- Spec versions are immutable once Final; errata are separate documents.
- The reference implementation may not add *protocol-visible* behavior that is not in the spec.
- A "break-glass" fork right is explicit: all code and spec are open; the community may fork if governance fails.

## 7. Funding principles
Funding (grants, sponsorships, hosted-service revenue) must not buy spec influence. Sponsors may be listed; sponsorship confers no vote. Hosted-service revenue funds the foundation under a published budget.
