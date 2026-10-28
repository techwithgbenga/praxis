# The Practitioner Charter

Praxis records the thing a person values most about their working life: their judgment, including their mistakes.
That is a moral responsibility. This charter binds the project's design.

## 1. Rights of every practitioner
1. **Ownership.** Your cases, keys, lineage, and calibration are yours.
2. **Exit.** Full, lossless export in an open format at any time, with no account needed.
3. **Consent per use.** Retrieval, training, calibration publication, and any third-party disclosure each require explicit, revocable, per-case or per-scope permission.
4. **Dignity of error.** Records of mistakes exist to improve judgment, never to punish. Calibration is about *your reliability in stating uncertainty*, not about being right.
5. **Credit.** Lineage preserves attribution to the people whose judgment shaped an answer.
6. **Silence.** You may decline any elicitation question at no cost. Silence is never penalized or inferred.

## 2. Prohibited uses (enforced by architecture, trademark, and hosted-service terms)
- Ranking, scoring, disciplining, hiring, or firing individuals **without the practitioner's explicit per-disclosure consent**.
- Covert capture (recording decisions without the practitioner's knowledge).
- Reconstructing a practitioner's reasoning for use *against* them.
- Using a practitioner's lineage to train or fine-tune a model after they have withdrawn consent for new builds.
- Presenting an apprentice's output as the practitioner's actual advice without clear labelling.

## 3. Design obligations
- **Calibrated humility:** every apprentice answer states provenance, sample size, calibration, and dissent. No false certainty.
- **Dissent preserved:** minority lineages are surfaced, never averaged away.
- **No autonomous action in high-risk domains:** apprentices advise; humans decide. High-risk domains (medicine, law, critical infrastructure) require domain governance and are out of scope for v1.
- **Community knowledge:** knowledge belonging to communities (including Indigenous knowledge systems) is never extracted by default. It requires community-governed consent and governance, designed *with* those communities (tracked as `Q-007`).
- **Children and vulnerable groups:** no capture of minors' decisions in v1.

## 4. Accountability
- Violations may be reported to `ethics@<project-domain>`; the Steward/TSC publishes a response within 30 days.
- The privacy-conformance suite is part of CI and part of the "Praxis Compatible" mark.
- This charter may be amended only via PIP with Practitioner Council approval.
