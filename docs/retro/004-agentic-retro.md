# Agentic retro: how feature 004 was built, and what can be distilled (T051, roadmap 034)

Date: 2026-10-03 | Basis: `docs/retro/004-agentic-notes.md` (kept during the work), the commit history, `docs/review-004-security.md`,
`docs/retro/004.md`. Caveats: one project, one day, and the evaluator took part in the work. Cost figures are not measured yet.

## 1. What we did
One feature (six user stories, 51 tasks, 56 commits) built under an IIKit flow (constitution, spec, plan, testify, tasks) with an
agile layer on top (timebox, WIP 1, working agreement) and four kinds of workers: the orchestrator (Claude Sonnet), Tier C
implementers (Claude Opus), test, step and mechanical workers (Claude Sonnet subagents), and Qwen via opencode (one build task and two
read-only reviews). Result: 8 of 18 demo defects strictly found (6 before), 0 false positives (1 before), 45 BDD scenarios on real code,
935 tests, a signed and verifiable evidence bundle per audit.

## 2. What helped, in order of evidence
1. **A ground truth with a release gate** (the demo): it measured the real effect, exposed a double credit in its own scoring and
   made "better" a number. Everything else was easier to judge because of it.
2. **Red, build, mutate, harden**: tests were written first, an implementer built, the implementer mutated its own code, a second
   worker hardened the tests until the mutations died. Every Tier C module had survivors on the first pass (status 4 of 8, `runTool`
   with `shell:true` and whole-`process.env` surviving, a JSON-escape leak in redaction, a path-trust gap in the lifecycle, signing
   fallbacks). About 150 mutations were run; each survivor became a test. This was the single most productive technical practice.
3. **An independent oracle in the tests** (the hash chain and the signature recomputed with `node:crypto` in the test): the
   implementation could not pass by being wrong in the same way as its own helper.
4. **Contract tests with the real tools**: they proved that hostile ignore files really suppress findings without the probe, and
   that renaming rather than deleting steering files still lets gitleaks see secrets hidden inside them. Mocks would have hidden both.
5. **Tier routing with an explicit Tier C list** (the files that decide what is claimed): the right models spent their effort where a
   mistake means a false claim; diff review was never skipped for those.
6. **Cross-family review**: 2 runs, about 25 items, 3 real findings (corrections could lower severity; the verifier said VERIFIED without
   a checked signature; a plain `Error` in the workflow). Hit rate roughly 15 to 20 percent; every claim needed verification against the
   code. Depth follows from the number of files read, not from model size.
7. **Process rules that were cheap and paid off**: hard timeout per agent run, commit test and implementation as pairs after green,
   ratcheted coverage floors, a deviation list with owner and deadline, claims in documents reduced to measured sources.

## 3. What did not help or cost more than it gave
- **Stage gating and one-question-at-a-time** cost hours of calendar time before any code existed; valuable for the decisions it
  captured (semgrep metrics, signing, retention), but a thinner path (spec and plan in one sitting for a feature this size) would have
  saved a lot without losing the approvals.
- **opencode**: one tiny task worked in 90 seconds; one test-writing task ran 29 minutes with 521 tool calls and exhausted the
  quota. Without a hard timeout it is a risk, and for judgment-heavy work Claude subagents were faster and more reliable.
- **Workers writing code and tests together** skipped the red step once; mutation testing still caught the weakness, but the TDD
  evidence is missing for that task.
- **Automated plugin findings** pointed at code that did not exist, twice.
- **Parallel agents in one working tree** work only with disjoint file ownership, and the pre-commit `verify` makes red tests
  uncommittable; shared scratchpad file names collided once.
- **Verbose agent reports** cost orchestrator context; a fixed short report format would help.

## 4. The opportunity: a distilled method
The reusable core is not IIKit and not a model choice; it is the combination below. Working name: **assured agentic delivery**
(internal handle: the Tessera method).

| Layer | Practice | Evidence from 004 |
|-------|----------|-------------------|
| Intent | Constitution of testable principles; gates enforce them; amendments need the product owner | principles VI to XII drove most design choices |
| Slice | Thin vertical slices, one story in progress, timebox set by the product owner | six stories, each demonstrable |
| Acceptance | Scenarios first, hash-locked; step definitions on real code, quality-checked | 45 scenarios, verify-steps and step-quality pass |
| Routing | Tier A, B, C with a project-specific Tier C list; Tier C is never blind-delegated | invariants went to Opus, plumbing to Sonnet |
| Loop | Red, build, mutate, harden with an independent oracle | ~150 mutations, one real leak and several path and trust gaps caught |
| Truth | Ground-truth demo as release gate; contract tests with real tools | strict recall 6 to 8 of 18, 0 false positives |
| Review | Cross-family review with mandatory verification of each claim; automatic findings are leads | 3 real findings in 25 items |
| Ratchet | Gates and floors only tighten; every deviation has an owner and a deadline | floors 69/40/84/70 to 84/74/90/87 |
| Reflect | Retro with numbers, notes kept during the work | this file |

What is probably new compared with Spec Kit, BMAD and Compound Engineering: the mutation loop as a routine, the ground-truth gate as a
release criterion, the Tier C list per project, and the rule that a computed level, not a claim, goes into the deliverable. What is not
new: spec-first, multi-agent review, plan, work, review cycles.

## 5. Options to package it (decisions for the product owner)
1. **Skills and templates** (smallest step): turn the loop, the tier routing, the cross-family review with triage and the ratchet into
   skills plus prompt templates (a first set is in `docs/method/prompt-templates.md`).
2. **A public playbook**: an article and a repository with the templates, the worked example (this repo) and the measurements.
3. **A consulting offering**: assured agentic delivery for regulated clients, with Tessera as the proof case.
Each option needs a second project to test whether the method generalizes (right now n = 1).

## 6. Proposed next steps
1. Apply the loop and the templates to a second, different project and record the same numbers (defects found per loop, review hit rate,
   time and tokens per task, escapes after release).
2. Measure cost for real: tokens per worker and per task, and quota use; add it to the slice retro.
3. Compare the delta with BMAD and Compound Engineering (roadmap 033) before deciding on packaging.
4. Fix the process findings: fixed short report format for workers, one scratchpad folder per agent, thinner stage path for small features.

## 7. Open questions
- Is the method worth packaging, or is it already covered by existing plugins plus the constitution and ratchet idea?
- Which part is most valuable to clients: the method, the evidence it produces, or the tool?
- How much of the benefit comes from the mutation loop alone (cheap to adopt) versus the whole stack?
