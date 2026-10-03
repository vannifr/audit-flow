# Agent instructions (audit-flow, project Tessera)

## Commands
- `npm run verify`: build, test with coverage, lint (must pass before every commit)
- `npm test`, `npm run lint`, `npm run build`, `npm run test:bdd`
- `npm run evidence:verify -- <bundle-dir> [--expect-root <sha256>] [--pubkey <file|dir>]... [--json] [--trace <recordId>]`: verify a sealed evidence bundle; first word `VERIFIED` (hashes and a valid signature for a `--pubkey` key), `HASHES-OK` (no `--pubkey`, hashes only) or `FAILED` (exit 0 for the first two, 1 issues, 2 usage)
- Never run `git commit`, `git push` or any git command that changes history. The orchestrator commits.

## Code rules
- TypeScript strict, Node 20 or later, no new dependencies unless the task says so.
- No comments in code unless the task asks for them.
- No `any`, no `@ts-ignore`, no shell strings: external commands only through `runTool` once it exists, otherwise `execFile` with an argument array.
- Never write secrets, tokens or real credentials. The demo secrets under `demo/` are fake and stay under `demo/`.

## Tests
- TDD: write the test, run it and see it fail for the right reason, then implement.
- Never skip, empty or weaken a test to get green. Never edit `.feature` files or `demo/EXPECTED.md`.
- Unit tests must be hermetic: no dependence on installed tools or the network. Use the injectable runner and fixtures in `tests/fixtures/tools/`.

## Scope
- Do exactly the task in the prompt. Do not touch other files, reformat files, or refactor unrelated code.
- Files that decide what runs on audited code or what counts as evidence are sensitive (`src/scan/`, `src/evidence/`, the outcome rule in `src/workflows/index.ts`). Change them only when the task names them.
- Report: files changed, test totals, the choices you made that the task did not state.

## Where things are
- Spec, plan, tasks: `specs/004-reliable-scan-core/` (read `tasks.md` for the current task and its Files and Interfaces)
- Constitution: `CONSTITUTION.md`; working agreement: `docs/agile/working-agreement.md`
