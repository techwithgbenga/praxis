# CLI, Local API, MCP & SDKs

## 1. CLI (`praxis`)
| Command | Purpose |
|---|---|
| `praxis init [--hardware-key] [--recovery shamir:3of5]` | create identity, keystore, store |
| `praxis whoami` / `praxis keys list|rotate|delegate|revoke` | identity management |
| `praxis open --domain <pack>` | create a case (interactive or flags/JSON stdin) |
| `praxis predict <case>` | show apprentice's committed prediction (post-hoc) |
| `praxis decide <case> --chose <opt> [--reasoning …] --claim <text> --p <0..1> [--template <id>] [--resolve-by <time>] [--cel <expr>]` | record decision + claims |
| `praxis claims add|show <case>` | (late claims via `amend`) |
| `praxis close <case> [--auto]` | resolve claims (CEL/auto or manual attested) |
| `praxis abandon <case> --reason …` / `praxis retract <case>` | lifecycle |
| `praxis list [--state open|decided|closed] [--domain …]` / `praxis show <case> [--unseal]` | browse |
| `praxis calibration [--domain …] [--template …] [--json]` | SCORING.md metrics, labels, coverage, caveat |
| `praxis ask "<query>" [--scope self|team:…|canon:…]` | consult apprentice (provenance + dissent) |
| `praxis queue` / `praxis elicit [next]` / `praxis elicit --pause 7d` / `praxis elicit --cap N` | elicitation queue & controls (incl. "ask me less") |
| `praxis share <case> --to <did> --terms …` / `praxis grant|derive|diverge …` | lineage ops |
| `praxis canon create|add|release|show` | canon management |
| `praxis attest calibration [--domain …] [--out file]` | create signed calibration disclosure |
| `praxis verify <attest|bundle>` | verify someone else's disclosure |
| `praxis sync [--relay URL] [--watch]` | PSP/1 sync |
| `praxis export --out archive.car` / `praxis import archive.car` | lossless export/import |
| `praxis pack list|test|install` | domain packs |
| `praxis doctor` | diagnostics (no network unless asked) |
| `praxis privacy audit` | prints what leaves the device (should be nothing by default) |
Global flags: `--json`, `--no-color`, `--store <path>`, `--offline` (default behavior when no remote configured).
Exit codes: 0 ok · 1 generic · 2 usage · 3 validation · 4 policy-denied · 5 integrity failure.

## 2. Local API (praxisd)
gRPC over UDS/named pipe; `proto/praxis.proto` (sketch):
```proto
service Praxis {
  rpc OpenCase(OpenCaseRequest) returns (CaseRef);
  rpc Decide(DecideRequest) returns (DecisionRef);          // enforces rule C2: requires prediction first
  rpc Close(CloseRequest) returns (OutcomeRef);
  rpc Calibration(CalibrationRequest) returns (CalibrationReport);
  rpc Consult(ConsultRequest) returns (Answer);
  rpc NextElicitation(Empty) returns (ElicitationPrompt);
  rpc SubmitElicitation(ElicitationAnswer) returns (ElicitationRef);
  rpc Sync(SyncRequest) returns (stream SyncEvent);
  rpc Export(ExportRequest) returns (stream Chunk);
}
```
Auth: OS file permissions on the socket; per-client capability tokens for integrations (scoped: `draft:write`, `consult:read`, …).

## 3. MCP server tools (human-in-the-loop by design)
| Tool | Behavior |
|---|---|
| `praxis_draft_case` | creates a **draft** (never signed) from provided context; user must confirm in UI/CLI |
| `praxis_consult` | returns apprentice answer with provenance (read-only) |
| `praxis_list_open_cases` | read-only |
| `praxis_calibration_summary` | read-only, practitioner-scoped |
| `praxis_log_agent_decision` | logs an **agent-authored** decision under a distinct *agent identity* (Q-011), never under the human's identity |
Agents **cannot** sign as the human, close cases, share, or retract.

## 4. SDK surface (TS / Python; same shapes)
```ts
const px = await Praxis.open({ store: "~/.praxis" });
const c = await px.cases.open({ domain: "incident-response@0.1", situation, stakes });
const pred = await px.predict(c);                       // committed prediction
await px.cases.decide(c, { chosen: "wait", claims: [{ statement, p: 0.7, resolve, horizon }] });
const rep = await px.calibration({ domain });
const ans = await px.consult({ query, scope: "self" });
```
All SDKs expose: `verifyObject(bytes)`, `cid(bytes)`, `scoring.*` (pure functions, bit-identical to Rust).

## 5. Stability policy
CLI flags and `--json` output schemas are versioned (`schema: "praxis.cli/1"`). Breaking changes require a major version and a deprecation window of ≥ 2 minor releases.
