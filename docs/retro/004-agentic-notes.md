# Running notes: agentic way of working in feature 004

Kept during the work, input for the retrospective (tasks T051, roadmap 034). Facts first, interpretation in the retro.
Start of the slice: 2026-10-03 13:48 (timebox: one working day).

## Set-up
- Roles: orchestrator Claude (Sonnet); Tier C implementation Claude Opus; Tier B tests and test hardening Claude Sonnet subagents;
  opencode (Qwen via Alibaba Coding Plan) for Tier A/B while quota lasted; independent review by another family planned.
- Gates: IIKit (spec, plan, testify, tasks), constitution v2.1.0, pre-commit `verify`, CI with pinned images.

## Observations
- Pre-commit runs `npm run verify`, so red TDD tests cannot be committed alone. Test and implementation are committed as a pair after green.
- opencode T004 (tiny mechanical task) worked first time in about 90 s, diff exact.
- opencode T008 (redaction tests) ran 29 minutes with 521 tool calls and exhausted the Alibaba quota (429); the next three tasks failed at once.
  Lesson: hard timeout per run; fall back to Claude subagents; quota is a budget.
- Tests written by a coding model (T006) were too weak: Opus mutation testing on its own implementation let 4 of 8 mutations survive.
  A Sonnet hardening pass killed all of them. Pattern: red, build, mutate, harden.
- The same loop on redaction found a real leak (JSON-escaped password left partly visible) that example-based tests missed.
- T013 (runTool) first pass: 8 of 16 mutations survived, including `shell:true` and passing the whole `process.env`; the invariants that matter most were untested until the hardening pass.
- Builders reporting "all tests pass" were verified by running the exact commands; so far no false report, but weak tests were common.
- Spec 004 test IDs were duplicated in a unit test (TS-004 twice): traceability breaks silently without a check.
- IIKit `status` reported feature 001 "complete" while BDD ran 0 scenarios (config file name never loaded, Gherkin parse errors): file-presence gates are not behavior gates.
- A stale worker from the previous day silently stole tasks from the demo run: environment hygiene needs an explicit check.
- Parallel agents in one working tree work if file ownership is disjoint; shared `npm run verify` is unusable mid-flight (tests red by design).

## Questions for the retro
- Which parts of this loop are reusable as a method (tiering, red-build-mutate-harden, family-diverse review, hard timeboxes)?
- What did the process cost (tokens, quota, wall time) against what it caught?
- Is there a product here: a playbook, a set of skills, or templates others can use?

## More observations (2026-10-03 afternoon)
- Loop that worked repeatedly: Sonnet writes red tests and stubs, Opus implements Tier C, Opus mutates its own code, Sonnet hardens tests until mutations die, Opus fixes what the new tests expose.
  Results: status model 4 of 8 mutations survived first, redaction found a JSON-escape leak, runTool had `shell:true` and whole-`process.env` mutations surviving, lifecycle had a path-trust gap (`fetchSource` trusted `run.workDir`).
- The tests that exposed real defects came from mutation testing, not from the first-pass tests. Unit tests written by the builder family are consistently too weak on the invariants that matter.
- Redaction keeps two documented gaps as `it.fails` (double-escaped slash in a keyed token inside a JSON string; unquoted value containing a double quote). `it.fails` keeps a known gap visible and flips red when fixed.
- Layered defense held: gitleaks findings are redacted as exact known values (including JSON-escaped, base64, percent-encoded); the pattern layer is only the backstop for unknown secrets.
- Parallel Opus and Sonnet agents in one working tree worked without conflicts because each task owned distinct files; the orchestrator never ran the shared `npm run verify` until all were done.
- Time used before the first commit of Phase 2: about 1h20 of the one-day timebox, mostly agent wall time waiting on mutation loops.
