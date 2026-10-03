# Review of the project state by GLM (glm-5), triage

Date 2026-10-03, read-only run through opencode (about 3 minutes, 35 tool calls). Builder family: Claude. Every claim was checked against the code; the raw report is not kept as truth.

| # | Claim (GLM) | Verdict | Action |
|---|-------------|---------|--------|
| 1 | README and package version 1.0.0 although the release is 0.2.0 | valid | version set to 0.2.0 (package.json, lock, README). `sonar-project.properties` keeps projectVersion 1.0.0 on purpose: changing it would reset the new-code period and hide existing violations |
| 2 | "Enterprise-grade" tagline contradicts the status line | valid | tagline now says built toward enterprise assurance, level 1 of 4 |
| 3 | 23 shell-string `execAsync` calls remain, contradicting the CHANGELOG | partly valid | the CHANGELOG says "on the workflow path", which is correct; the legacy functions are not called by the workflow, but the worker registers all of them as activities. Roadmap 012 now includes no longer registering legacy activities |
| 4 | review-report.md is stale | valid | banner marks it as the 2026-10-02 baseline |
| 5 | evidence files written without explicit permissions | false | `src/evidence/store.ts` sets 0700 dirs, 0600 staging, 0400 published |
| 6 | signing key on the same host allows forging | known | documented limit of level 1, roadmap 013 |
| 7 | evidence root inside the tmp root could be deleted by cleanup | false | `cleanupRun` removes only `<tmp>/tessera-<runId>` and refuses when that path is inside the evidence root (`src/scan/lifecycle.ts:353`) |
| 8 | error messages leak the bundle path | not applicable | the path is the argument the caller passed |
| 10 | weak assertions in activities-p1 tests | valid | legacy tests; roadmap 012 now lists replacing them |
| 11 | the exec ratchet counts calls but not safety | valid, known | the legacy file is slated for migration in 012; the ratchet stops growth, not existing risk |
| 13 | no security review gate for features at the execution boundary | valid | added to the working agreement |
| 14 | Tier C file list not codified | valid | listed in the working agreement |
| 15 | roadmap 007 depends on 008 | false | the roadmap states 007 depends on 004 only; order inside level 2 follows risk |
| 16 | no circuit breaker for flapping Sonar | not applicable | the gate is deterministic on the same code; a deviation process exists |

Clean areas named by GLM (verify, redact, run-tool, source-probe, coverage thresholds, CI steps) were not independently re-proven by this review; the mutation work covers them. Not verified by GLM: the demo recall figure and the Sonar gate behavior; both were verified by the orchestrator (demo exit 0, gate OK, pipeline 45 green).

Yield: 6 valid of 16 items, 2 known, 4 false or not applicable. Next review of this kind: at the end of the next phase, with a different family (Qwen or Kimi) for a second opinion.
