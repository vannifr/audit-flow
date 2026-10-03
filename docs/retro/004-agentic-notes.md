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

## Cross-family review, first real use (2026-10-03 evening)
- A Qwen (`qwen3.7-plus`) read-only review of the Tier C files took about 5 minutes and about 29 tool calls: 15 items, 2 valid and fixed, 5 minor, 5 not applicable, 1 false (Temporal's workflow sandbox makes `Date` deterministic).
  Value: it confirmed a pre-existing risk the Opus builder had already mentioned and found a principle IX gap nobody had looked at. Cost: triage time, because each claim had to be verified against the code.
- Alibaba quota recovered after a few hours; a hard `timeout 900` on the run prevented a repeat of the T008 runaway.
- Output of the day so far: US1 complete (17 of 17 scenarios), demo strict recall 6 of 18 to 8 of 18, severity-correct 3 to 5, false positives on clean-app 1 to 0.
- An automated security plugin flagged a "fail-open" line that did not exist in the code (the line already mapped ENOENT to `unavailable`): automatic findings also need verification before acting.
- Process deviation: one Sonnet agent wrote test and code together and did not show the red step; mutation testing still passed, but the TDD evidence is missing for that task.
- The automated security-review plugin twice reported code that did not exist (an ENOENT mapped to `completed` in run-tool.ts; a loop over an empty array in sign.ts). Both were checked against the file and were false. Rule: an automatic finding is a lead, not a fact; verify the line before acting, and keep the mutation tests that already prove the control works.
- Concurrent agents sharing a scratchpad file name (`mutate.py`) overwrote each other's mutation script. Rule: every agent works in its own named scratchpad subfolder.
- A second cross-family review (qwen3-max, only 14 tool calls) found one real gap (the verifier printed VERIFIED without a checked signature) and nine items that were minor or not applicable: a larger model is not automatically a deeper reviewer; depth follows from how many files it actually reads.

## 2026-10-03 evening: Sonar cleanup (issue 32)
- opencode (qwen3-coder-plus) reverted the uncommitted change of the previous opencode run while restoring its own mutation, the known `git checkout` incident. Rule: one opencode run per commit, never a second run on a dirty tree. The builder also reported a test total (943) that did not match the run (799 in tests/unit); both claims were rechecked by running the commands.
- A differential harness (old against new code on 174k generated inputs) plus mutation-hardened tests made a refactor of Tier C code reviewable; it found zero behavior differences and 40 of 42 mutations were killed, the 2 survivors equivalent.
- The demo gate printed PASSED while the script exited 1 because sealed bundle folders (0500) could not be removed; green output and exit code must be checked together.
- Tier A work this small (about 25 mechanical edits) was faster by script than by an opencode round; route to opencode only when the edit set is large or judgment-free but unspecified.
- Sonar rule S1607 asks for a recorded reason for skipped tests; the constitution already demands cause and owner, so the reason went in a comment.
