# Tasks: Reliable Scan Core

**Input**: `specs/004-reliable-scan-core/` (spec.md, plan.md, research.md, data-model.md, contracts/, quickstart.md, tests/features/)
**Prerequisites**: plan.md, spec.md; testspecs locked via `/iikit-04-testify` (hash stored)
**Tests**: Mandatory (constitution II, TDD). Every implementation task has a preceding test task that is shown red first.
**Organization**: grouped by user story; each story is an increment that can be demonstrated and released on its own.

## Format: `- [ ] [TaskID] [P?] [Story?] Description with file path`

- **[P]**: parallelizable (different files, no dependency)
- **[USn]**: user story label (story tasks only)
- **Tier** and routing are given per task as a sub-line, with `Files`, `Consumes`, `Produces`.
- Test references are explicit comma-separated lists (no prose ranges).

## Execution rules (agentic-plan-uitvoering, decided 2026-10-03)

**Tier C for this project (never blind-delegated)**: the invariants of constitution principles VI, VII and VIII.
Files: `src/scan/status.ts`, `src/scan/process-runner.ts`, `src/scan/run-tool.ts`, `src/scan/source-probe.ts`,
`src/evidence/redact.ts`, `src/evidence/store.ts`, `src/evidence/manifest.ts`, `src/evidence/verify.ts`,
`src/evidence/sign.ts`, the outcome rule in `src/workflows/index.ts`, and anything that decides what runs on the audited source.
Reason: whether it is right is a judgment about a security or integrity guarantee, not only a test result.

**Routing**:

| Tier | Mechanism | Rule |
|------|-----------|------|
| A mechanical | opencode (Qwen, GLM, Kimi; strictly serial, no parallel) via `opencode-orchestratie` | opencode never commits; the orchestrator commits as vannifr |
| B judgment inside a fixed design | opencode with the strongest available model, or a Claude Sonnet subagent when opencode quota is short | one task at a time, own diff read before commit |
| C high stakes | Claude Opus designs or executes; independent review by a second Opus pass | read the whole changed file; confirm the invariant, not only the tests |

**Verification for every task**: read the actual diff (not the executor's report), run `npm run verify` locally, check for silent
escape normalization in generated code and tests, push, and check the real pipeline (`woodpecker` repo 25) before the next task.
A commit message names the model that produced the change. A retrospective note follows each user story (`docs/retro/`).

**Superseded tests (decided)**: tests that encode the old behavior are replaced in the same commit as the change they conflict with,
each marked `superseded by FR-xxx` in the commit body. No adapters with the old signature.

## Phase 1: Setup

**Purpose**: structure and test harness; nothing here changes behavior.

- [x] T001 Create module folders `src/scan/`, `src/evidence/`, `src/cli/`, `tests/unit/scan/`, `tests/unit/evidence/`, `tests/contract/` (empty `index.ts` or `.gitkeep`)
  - Tier A (mechanical, no judgment). Files: those folders. Produces: layout from plan.md "Project Structure".
- [x] T002 [P] Record tool fixtures in `tests/fixtures/tools/` from real runs on the demo and on a clean app: npm audit (vulnerable, ENOLOCK), gitleaks (clean, leak with exit 42, error), semgrep (clean, results, crash exit 2)
  - Tier B (needs judgment which output is representative). Files: `tests/fixtures/tools/*.json`. Produces: input for policy unit tests.
- [x] T003 [P] Make cucumber load `specs/004-reliable-scan-core/tests/step_definitions/` and add a failing skeleton (undefined steps) in `.cucumber.js`; the `.feature` files stay untouched
  - Tier B. Files: `.cucumber.js`, `specs/004-reliable-scan-core/tests/step_definitions/skeleton.steps.ts`. Produces: BDD runner that executes 004 scenarios.
- [x] T004 [P] Add `test:tools` script and `tests/contract/vitest.config.ts` (real tools, not part of `verify`); document in README
  - Tier A. Files: `package.json`, `tests/contract/vitest.config.ts`, `README.md`.
- [ ] T005 Wire a `test:bdd:done` script (cucumber tag expression listing only finished stories) into `verify:full` when US1 is green (T024), and extend its tags at the end of each story; the full `test:bdd` stays outside `verify:full` until every story is green
  - Tier A. Files: `package.json`. Reason: a new gate must be proven clean before it blocks the trunk (ratchet, constitution XII).

---

## Phase 2: Foundational (blocks all user stories)

**Purpose**: the shared core every story needs: status model, redaction, evidence store, `runTool`, run lifecycle.
**Checkpoint**: unit tests green; coverage per-glob gate proven to fail; no scanner is migrated yet.

- [x] T006 [P] Write failing unit tests for the status model and outcome rule [TS-001, TS-002, TS-003, TS-004, TS-005, TS-006] in `tests/unit/scan/status.test.ts`
  - Tier B. Consumes: `contracts/scanner-status.ts`, quickstart scenario 1. Produces: red tests for FR-001, FR-002, FR-003, FR-004.
- [x] T007 Implement `src/scan/status.ts`: five statuses, `computeOutcome`, `notPerformed`, `mayReportClean`, applicability table to pass [TS-001, TS-002, TS-003, TS-004, TS-005, TS-006]
  - Tier C (guarantee: no clean result without a completed scan). Files: `src/scan/status.ts`, additive types in `src/types/index.ts`. Consumes: R4. Produces: `ScannerStatusEntry`, `computeOutcome`.
- [x] T008 [P] Write failing unit tests for redaction using the demo secret shapes [TS-027, TS-028] in `tests/unit/evidence/redact.test.ts`
  - Tier B. Produces: red tests for FR-012.
- [x] T009 Implement `src/evidence/redact.ts` (do not store, allow-listed fields per tool, pattern backstop) to pass [TS-027, TS-028]
  - Tier C (security: no secret reaches evidence, history or logs). Files: `src/evidence/redact.ts`. Consumes: R11, R12.
- [x] T010 [P] Write failing unit tests for the evidence store and hashing [TS-013, TS-015, TS-017, TS-018, TS-019] in `tests/unit/evidence/store.test.ts` (tmp root)
  - Tier B. Produces: red tests for FR-005, FR-006, FR-011, FR-015.
- [x] T011 Implement `src/evidence/store.ts` and `src/evidence/hash.ts`: staging then exclusive `link()` publish, deterministic record ids, 0600/0400 permissions, `lstat` checks, two hashes per artifact to pass [TS-013, TS-015, TS-017, TS-018, TS-019]
  - Tier C (integrity of stored evidence). Files: `src/evidence/store.ts`, `src/evidence/hash.ts`. Consumes: `contracts/evidence-record.ts`, R8, R10. Produces: `EvidenceStore`.
- [x] T012 [P] Write failing unit tests for `runTool` with a fake `ProcessRunner`: ENOENT, timeout, truncation, env allow-list, no shell, version probe [TS-008, TS-009, TS-010] in `tests/unit/scan/run-tool.test.ts`
  - Tier B. Consumes: `contracts/run-tool.ts`. Produces: red tests for FR-005, FR-006, FR-013.
- [x] T013 Implement `src/scan/process-runner.ts`, `src/scan/run-tool.ts`, `src/scan/env.ts` (execFile, array args, `GIT_TERMINAL_PROMPT=0`, env allow-list incl. `EIO_BACKEND`, output cap 64 MiB, record per step) to pass [TS-008, TS-009, TS-010]
  - Tier C (trust boundary: no shell, nothing from the audited source reaches a command). Files: `src/scan/process-runner.ts`, `src/scan/run-tool.ts`, `src/scan/env.ts`. Consumes: T007, T009, T011. Produces: `runTool`.
- [ ] T014 [P] Write failing unit tests for the run lifecycle: `initAuditRun`, `fetchSource` (clone via `runTool`, `rev-parse`), `cleanupRun` on every exit path, unreachable source [TS-011, TS-014, TS-018] in `tests/unit/scan/lifecycle.test.ts`
  - Tier B. Produces: red tests for FR-008, FR-015 and the edge cases.
- [ ] T015 Implement `src/scan/lifecycle.ts` (private work dir `<tmp>/tessera-<temporalRunId>`, source revision, cleanup guard that refuses paths outside the work dir) to pass [TS-011, TS-014, TS-018]; keep `validateRepoUrl` unchanged
  - Tier C (clones untrusted input). Files: `src/scan/lifecycle.ts`, `src/activities/index.ts` (wire `initAuditRun`, `fetchSource`, `cleanupRun`). Supersedes tests of `cloneRepository` (note in commit).
- [x] T016 Add per-glob coverage thresholds 90/85/90/90 for `src/scan/**` and `src/evidence/**` in `vitest.config.ts` and prove the gate fails (scratch copy with one test disabled, record exit code in the commit body)
  - Tier B. Files: `vitest.config.ts`. Consumes: T007 to T015.

---

## Phase 3: User Story 1 - Honest scan outcome (Priority: P1) MVP

**Goal**: a failed, missing or partial scanner makes the audit INCOMPLETE and visible; never a false clean.
**Independent test**: remove one scanner; the report is INCOMPLETE and names it.
**Checkpoint**: demo with one scanner removed shows INCOMPLETE; release tag `v0.2.0`.

- [ ] T017 [P] [US1] Write failing policy tests per tool using the recorded fixtures [TS-002, TS-004, TS-005, TS-009, TS-010] in `tests/unit/scan/policies.test.ts`
  - Tier B. Consumes: T002, R3. Produces: red tests for exit-code policies (gitleaks 42, semgrep crash, npm exit 1 with JSON).
- [ ] T018 [US1] Migrate `runGitleaks` to `runTool` with framework config, `--exit-code 42`, `--redact`, `--ignore-gitleaks-allow` to pass [TS-002, TS-004, TS-005] in `src/activities/index.ts` and `src/scan/tools/gitleaks.ts`
  - Tier B. Consumes: T013. Produces: `ScanStepResult` for gitleaks. Supersedes old gitleaks tests.
- [ ] T019 [US1] Migrate `runSemgrep` to `runTool` with `--metrics=off`, packs `p/javascript` and `p/nodejs`, `--disable-nosem`, `EIO_BACKEND=posix`, crash classified as failed to pass [TS-002, TS-005, TS-010] in `src/scan/tools/semgrep.ts`
  - Tier B. Consumes: T013, research R6. Produces: `ScanStepResult` for semgrep. Supersedes old semgrep tests.
- [ ] T020 [US1] Replace the `npx license-checker` call by an in-process license check from the lockfile to pass [TS-005] in `src/scan/tools/licenses.ts`
  - Tier C (removes code execution from the audited source). Consumes: R14. Produces: `ScanStepResult` for license check.
- [ ] T021 [P] [US1] Migrate `reviewCriticalPaths`, `detectPII` and `checkToolRequirements` off `exec`; label code review as heuristic, make npm not required in `src/scan/tools/review.ts`
  - Tier B. Consumes: T013. Produces: findings without secrets.
- [ ] T022 [US1] Add `settle`, the outcome guard and additive `AuditResult` fields to the workflow so a failed or missing scanner yields INCOMPLETE, and a source failure ends early [TS-001, TS-002, TS-003, TS-006, TS-011] in `src/workflows/index.ts`
  - Tier C (the outcome rule is the core of principle VII). Consumes: T007, T018, T019, T020. Produces: `AuditResult.outcome`.
- [ ] T023 [US1] Put outcome and scanner status table at the top of the report [TS-007] in `src/activities/index.ts` (`generateReport`) and `src/scan/report.ts`
  - Tier B. Consumes: T022. Produces: report layout per FR-016.
- [ ] T024 [US1] Write step definitions for `honest-scan-outcome.feature` and run them green in `specs/004-reliable-scan-core/tests/step_definitions/honest-scan-outcome.steps.ts` [TS-001, TS-002, TS-003, TS-004, TS-005, TS-006, TS-007, TS-008, TS-009, TS-010, TS-011]
  - Tier B. Consumes: T003. Rule: no tautological steps; each Then asserts on real output.

---

## Phase 4: User Story 2 - Evidence record for every step (Priority: P1)

**Goal**: each finding and each executed step is traceable to a record; the run has a manifest and a source revision.
**Independent test**: pick a finding and follow it to its record, raw-output hash and revision.

- [ ] T025 [P] [US2] Write failing unit tests for the manifest, hash chain, sealing and trace [TS-016, TS-017, TS-020] in `tests/unit/evidence/manifest.test.ts`
  - Tier B. Consumes: `contracts/evidence-manifest.ts`. Produces: red tests for FR-009, FR-017.
- [ ] T026 [US2] Implement `src/evidence/manifest.ts` and the `sealEvidence` activity (entries sorted, chain, retention date, self-verify, root hash in workflow result) to pass [TS-016, TS-017, TS-020]
  - Tier C (integrity chain). Files: `src/evidence/manifest.ts`, `src/activities/index.ts`. Produces: sealed bundle and `rootHash`.
- [ ] T027 [US2] Add `evidenceRef` to every finding in all migrated scan activities [TS-012, TS-013] in `src/scan/tools/*.ts` and `src/types/index.ts`
  - Tier B. Consumes: T018 to T021, T011. Produces: finding to record link (FR-007).
- [ ] T028 [US2] Write step definitions for `evidence-records.feature` and run them green [TS-012, TS-013, TS-014, TS-015, TS-016, TS-017, TS-018, TS-019, TS-020] in `.../evidence-records.steps.ts`
  - Tier B.

---

## Phase 5: User Story 3 - No findings lost when a tool reports issues (Priority: P2)

**Goal**: vulnerable dependencies appear as findings; the demo proves the gain.
**Independent test**: audit the demo; D05, D06, D07 are found.

- [ ] T029 [US3] Migrate `runNpmAudit` to `runTool` in an isolated directory with only `package.json` and the lockfile; exit 1 with valid JSON is completed to pass [TS-021, TS-022] in `src/scan/tools/npm-audit.ts`
  - Tier B. Consumes: R3, R5. Produces: dependency findings with severity and package. Supersedes old npm audit tests ("error gives zero findings").
- [ ] T030 [P] [US3] Extend `demo/run-demo.js` with the release gate: D05, D06, D07 present, strict recall at least 8 of 18, clean-app `complete`, `evidence:verify` exit 0, planted secrets absent from bundle, report and log [TS-023]; `demo/EXPECTED.md` stays unchanged
  - Tier B. Files: `demo/run-demo.js`. Rule: never edit expected values to turn the run green.
- [ ] T031 [US3] Write step definitions for `dependency-findings.feature` and run them green [TS-021, TS-022, TS-023]
  - Tier B.

---

## Phase 6: User Story 4 - Verifiable evidence integrity (Priority: P2)

- [ ] T032 [P] [US4] Write failing tamper-matrix tests (modified, deleted, added, no false alarm) [TS-024, TS-025, TS-026] in `tests/unit/evidence/verify.test.ts`
  - Tier B. Consumes: `contracts/verify-contract.md`.
- [ ] T033 [US4] Implement `src/evidence/verify.ts` and `src/cli/verify-evidence.ts` plus script `evidence:verify` to pass [TS-024, TS-025, TS-026]
  - Tier C (integrity logic). Produces: `VerifyReport`, exit codes.
- [ ] T034 [US4] Write step definitions for `evidence-verification.feature` and run them green [TS-024, TS-025, TS-026]
  - Tier B.

---

## Phase 7: User Story 6 - Signed evidence (Priority: P2)

- [ ] T035 [P] [US6] Write failing tests for signing and verification outcomes, key inside the evidence folder, missing key [TS-031, TS-032, TS-033, TS-035, TS-036] in `tests/unit/evidence/sign.test.ts`
  - Tier B. Consumes: `contracts/evidence-signature.ts`, R19.
- [ ] T036 [US6] Implement `src/evidence/sign.ts`, `src/cli/evidence-keygen.ts`, `signature.json`, and extend `verify.ts` with signature status to pass [TS-031, TS-032, TS-033, TS-035, TS-036]
  - Tier C (key handling). Files: `src/evidence/sign.ts`, `src/cli/evidence-keygen.ts`, `src/evidence/verify.ts`. Rule: key outside `TESSERA_EVIDENCE_ROOT`, 0600, never logged or put in history.
- [ ] T037 [US6] Add computed assurance level, signing time disclaimer and `TESSERA_REQUIRE_SIGNATURE` handling to workflow result and report [TS-034, TS-036]; make the product name configurable (default Tessera) and the report language English with an optional Dutch setting
  - Tier B. Files: `src/workflows/index.ts`, `src/scan/report.ts`, `src/config.ts`.
- [ ] T038 [US6] Write step definitions for `signed-evidence.feature` and run them green [TS-031, TS-032, TS-033, TS-034, TS-035, TS-036]
  - Tier B.

---

## Phase 8: User Story 5 - Evidence without exposed secrets (Priority: P3)

- [ ] T039 [US5] Implement `src/scan/source-probe.ts`: detect and record scanner-steering files (`.gitleaks.toml`, `.gitleaksignore`, `.semgrepignore`, `.npmrc`, markers) and neutralize them in the work copy [TS-029, TS-030]
  - Tier C (trust boundary). Consumes: R5.
- [ ] T040 [P] [US5] Add contract tests with real tools and hostile fixtures in `tests/contract/` (allow-all gitleaks config, `.semgrepignore` hiding `src/`, hostile `.npmrc`, repo-local `license-checker` marker) [TS-029, TS-030]; run via `npm run test:tools`
  - Tier B. Consumes: T004, T039.
- [ ] T041 [US5] Write step definitions for `secret-redaction.feature` and run them green [TS-027, TS-028, TS-029, TS-030]
  - Tier B.

---

## Phase 9: Polish and cross-cutting

- [ ] T042 [P] Migrate remaining `execAsync` calls, batch 1 of 3 (performance and accessibility activities), to `runTool` in `src/activities/index.ts`
  - Tier A, with tests staying green. Supersedes tests per commit.
- [ ] T043 [P] Migrate remaining `execAsync` calls, batch 2 of 3 (reliability, observability, CI/CD checks)
  - Tier A.
- [ ] T044 [P] Migrate remaining `execAsync` calls, batch 3 of 3 (code quality, documentation, privacy, blind spots)
  - Tier A.
- [ ] T045 Forbid `child_process` `exec` and `execSync` with an ESLint restricted-imports rule and prove it fails on a temporary violation in `.eslintrc.json`
  - Tier A. Consumes: T042, T043, T044.
- [ ] T046 Run the structured security review after T013 and after T022 (payloads: workflowId `x;id>...;#`, hostile `.npmrc`, symlink in bundle, key in evidence root) and record findings in `docs/review-004-security.md`
  - Tier C (independent Opus pass).
- [ ] T047 Raise the global coverage floor to the CI-container measurement after T030 and set the SonarQube gate back to blocking when it is green; update README deviations
  - Tier B. Consumes: constitution X, the 2026-11-01 deadline.
- [ ] T048 Document `TESSERA_EVIDENCE_ROOT`, `TESSERA_SIGNING_KEY`, `TESSERA_REQUIRE_SIGNATURE`, `evidence:verify`, `evidence:keygen`, scanner status meanings in README and AGENTS.md
  - Tier A.
- [ ] T049 Update `docs/assurance-roadmap.md` status for item 004, write the retrospective in `docs/retro/004.md` (what worked, what broke, metrics: demo recall, CI red time, deviations), and tag `v0.2.0` per slice
  - Tier B.
- [ ] T050 Create GitHub milestones L1 to L4, labels per level and one issue per roadmap item with a link to its `specs/NNN` folder, using `/iikit-08-taskstoissues`
  - Tier A. Outward-facing; approved by the user on 2026-10-03.

- [ ] T051 Hold a retrospective on the agentic way of working used in this implementation: which approach helped, which did not, and the opportunity to define and distil an own method or system from it (playbook, skills, templates); inputs are `docs/retro/004-agentic-notes.md` (kept running during the work), the numbers per slice and the commit history; output is `docs/retro/004-agentic-retro.md` and a proposal for a distilled approach
  - Tier B for the write-up; the conclusions are decided with the product owner. Files: `docs/retro/004-agentic-notes.md`, `docs/retro/004-agentic-retro.md`. Runs after the last story of the slice, before the next feature starts.
---

## Dependencies and execution order

- **Phase 1** has no dependencies. T001 first; T002, T003, T004 parallel; T005 after T003.
- **Phase 2** depends on Phase 1. Each implementation task follows its test task; pairs (T006, T007), (T008, T009), (T010, T011), (T012, T013), (T014, T015) can run in parallel with each other, except T013 needs T007, T009, T011 and T015 needs T013. T016 closes the phase.
- **Phase 3 (US1, MVP)** depends on Phase 2. T018 to T021 follow T017 and T013; T022 needs T018, T019, T020; T023 needs T022; T024 last.
- **Phase 4 (US2)** depends on Phase 2 and T018 to T021. **Phase 5 (US3)** depends on T029 only for the demo gate (T030). **Phase 6 (US4)** depends on T026. **Phase 7 (US6)** depends on T033. **Phase 8 (US5)** depends on T013 and T018 to T020.
- **Priority order**: US1 and US2 (P1), then US3, US4, US6 (P2), then US5 (P3). Higher priority stories do not depend on lower priority ones.
- **Phase 9** after the stories it touches; T045 after T042 to T044; T046 runs twice (after T013 and after T022); T050 can run right after this file is committed.

### Parallel batches

- Phase 1: T002, T003, T004
- Phase 2 tests: T006, T008, T010, T012, T014
- Phase 3: T017 with T021
- Phase 9: T042, T043, T044 only if executed serially by opencode (opencode never runs tasks in parallel); they are marked [P] because they touch different activities.

### Critical path

T001, T013 (via T007, T009, T011), T015, T018 to T020, T022, T023, T026, T033, T036, T037, T049.

## Implementation strategy

1. **MVP slice**: Phase 1, Phase 2, Phase 3. Stop and demonstrate: remove one scanner and show INCOMPLETE. Tag `v0.2.0`.
2. **Increments**: US2, then US3 and US4, then US6, then US5; each ends with a retro note, a green pipeline and a demo run.
3. **WIP limit**: one story in progress; no new story while the pipeline is red.
4. **Change**: if a demo run or review shows the plan is wrong, amend plan and tasks with a semantic diff before continuing.
