# Security and correctness review, feature 004 (after T022)

Review 1 of 2 planned (task T046). Reviewer: Qwen `qwen3.7-plus` via opencode (read-only, 15 minutes timeout), a different model
family than the builders (Claude Opus and Sonnet). Triage and verification: the orchestrator, against the actual code.
Date: 2026-10-03. Reviewed: status, run-tool, env, process-runner, lifecycle, activities, safe-walk, redact, store, workflow, licenses.

## Result of the triage

| # | Reviewer severity | Claim | Verdict | Action |
|---|-------------------|-------|---------|--------|
| 1 | high | Plain `Error` in the workflow (P0 timeout, tech stack guardrail) is retried forever by Temporal | **Valid** (also reported by the T022 builder) | Fixed: non-retryable `ApplicationFailure` with typed errors |
| 2 | high | Model corrections can lower severity or drop findings without human approval (principle IX) | **Valid, latent** (`crossValidate` is a placeholder today) | Fixed: corrections are advisory only |
| 3 | high | `code-review` reports `completed` even if no file was examined | Valid but low impact: the scanner is heuristic and not required, so the outcome rule is unaffected | Backlog: status `partial` when no critical path was scanned |
| 4 | high | `GIT_CONFIG_VALUE_<i>` from the worker env is passed to git | Not applicable: the worker environment is operator-trusted (the demo relies on it) | Backlog 006: deny-list dangerous git config keys |
| 5 | high | `PYTHONUSERBASE` from the worker env or HOME is passed to semgrep | Not applicable: operator-trusted; the work-dir variant would break semgrep for user installs | Documented trade-off in `src/scan/env.ts` tests |
| 6 | medium | Cleanup errors are swallowed | Valid, minor | Backlog: log cleanup failures |
| 7 | medium | Seal check in the store is not atomic | Not exploitable: run ids are unique, sealing arrives with T026 | Re-check in T026 |
| 8 | medium | TOCTOU between lstat and open in the safe walker | Not exploitable by the audited source: the clone dir is private (0700) and the post-open fstat check exists | Backlog: drop the redundant lstat |
| 9 | medium | `--git-dir=<path>` as one argument | Unreachable today (run id is validated) | Backlog: pass as separate arguments |
| 10 | medium | `exists()` TOCTOU in the license scan | Cosmetic: ends in a clear failed status | None |
| 11 | low | `TESSERA_MAX_OUTPUT_MB=00001` would truncate everything | Valid, minor | Backlog: enforce a minimum |
| 12 | low | One malformed license entry makes the audit incomplete | By design (unknown must not look clean) | None |
| 13 | low | Short JWTs are not redacted | Valid, minor | Backlog |
| 14 | low | `new Date()` in the workflow is non-deterministic | **False**: the Temporal workflow sandbox makes `Date` deterministic | None |
| 15 | low | Truncation flag edge case | Reviewer concluded it is correct | None |

Areas the reviewer checked and found clean: secrets reaching evidence and logs (redaction at every egress point), path traversal and
symlinks (`O_NOFOLLOW` used consistently), shell injection (`execFile` with argument arrays only), workflow determinism apart from item 14.

## Signal quality of this review

15 items: 2 valid and fixed, 1 confirming an earlier finding, 5 valid but minor or backlog, 5 not applicable or not exploitable, 1 false.
Roughly 20% of the items changed the code. A second pass with a stronger model is planned for the highest-stakes files (redaction, `runTool`, signing).
Not covered: the sandboxing of scanners, Temporal exposure and heartbeats (roadmap items 006 to 008).
