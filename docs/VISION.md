# Vision

## 1. The missing substrate
Git, Linux, and the Web share a shape: **a small open protocol that lets strangers build on each other's work with no owner in the middle.**
Civilization has substrates for *storing* knowledge (writing, print, the web) and, recently, *compressing* it (language models).
It has none for **judgment**: the practical wisdom of deciding well under uncertainty.

> *Episteme* is knowing that. *Phronesis* is knowing what to do, here, now, with this much at stake. Aristotle separated them; Polanyi observed we "know more than we can tell."

## 2. Why this has never scaled
| Past mechanism | What it transmitted | Why it stopped scaling |
|---|---|---|
| Guild apprenticeship | craft judgment | one master, a few apprentices |
| Common law / precedent | legal judgment + reasoning | slow, jurisdictional, lawyer-mediated |
| Rabbinic *responsa*, Islamic *fatwa* literatures | ethical/legal rulings *with reasoning* | curated by elites; hard to search/verify |
| Vedic chant, songlines | error-corrected cultural knowledge | needs lifelong human memorization |
| Case method (medicine, business) | worked cases | cases written *after* the fact, by narrators, with hindsight bias |
| Postmortems / lessons-learned | what went wrong | capture outcomes, rarely the *decision-time* reasoning |

Common failure: **human bandwidth** and **hindsight distortion**. Experts can't narrate what they didn't know they knew, and retrospective accounts are rewritten by outcomes.

## 3. The two enabling shifts
1. **Models that can predict an expert's next move.** The gap between prediction and action localizes tacit knowledge.
2. **Cheap, local-first cryptography.** Signed, content-addressed records can make decisions and *pre-registered* predictions tamper-evident without a trusted party.

## 4. The core insight
> **Tacit knowledge is the residual: the part of an expert's decisions that a model of their *stated* knowledge fails to predict.**

When a watching apprentice is surprised *and the stakes were real*, the right 30-second question, asked at the right time, converts a hunch into a speakable observation. Interviews and documentation fail because they ask about knowledge in the abstract, afterward.

## 5. What Praxis is
An open protocol and toolchain for **cases** (decisions with pre-registered claims), **outcomes**, **calibration** (honest, per-domain, uncertainty-aware), **lineage** (who learned from whom, where they diverged), and **canons** (curated, dissent-preserving bodies of judgment), plus **apprentices**: consultable models that answer with provenance.

## 6. What Praxis is *not*
- Not a knowledge base of facts (use docs/wikis).
- Not a performance-management system. (See [ETHICS.md](../ETHICS.md).)
- Not an autonomous decision maker.
- Not a claim that judgment is fully capturable. It is an instrument for capturing *more* of it, measurably, and for admitting what remains uncaptured.

## 7. Why now, why open
- Without open formats, a person's judgment becomes a vendor's asset. Trust requires inspectability; longevity requires no owner; adoption requires zero procurement.
- The same logic made git and the web win.

## 8. Success looks like
- **Year 1:** thousands of engineers keep a personal Praxis journal and *improve measurably in calibration*.
- **Year 2:** the first open Canons exist ("Postgres operations", "Incident command"), with provenance and dissent, and a published study shows elicited reasoning improves held-out prediction.
- **Year 5:** professions beyond software adopt domain packs under their own governance; retiring masters leave living lineages; "show your calibration" is a normal part of expertise.

## 9. What would make us stop
If the pre-registered experiment ([EVALUATION.md](EVALUATION.md)) shows elicited reasoning does **not** improve prediction over decisions-plus-postmortems alone, the project's central promise fails, and we say so publicly. The personal journal/calibration tool may still be valuable on its own; the "transmission" thesis would need rethinking.
