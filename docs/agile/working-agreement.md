# Working agreement (Project Tessera)

Minimal agility on top of IIKit: Kanban for flow, XP for technical practice, a weekly review and retro,
and a time budget per slice. IIKit stays the source for spec, plan, tests and tasks.

## Flow

- Board columns: Backlog, Ready, Doing, CI/Review, Done (GitHub Project on the backlog issues).
- **WIP limit**: one feature and one user story in Doing. No new story while the pipeline on `main` is red.
- Work lands on `main` in small, atomic, green commits. Unfinished work stays dark behind a toggle.

## Definition of Ready

- Approved spec and locked scenarios (`/iikit-04-testify`), a task with tier label, files and interfaces.
- An appetite (time budget) for the slice.

## Definition of Done

- Code on `main`, pipeline verified green after the push (not assumed).
- BDD scenarios and unit tests green; no test skipped, emptied or weakened.
- The demo was run and recall and false positives are recorded; claims in docs match measurements.
- Non-functional aspects weighed: performance, security, accessibility, logging, error handling.
- A retro note exists for the slice.

## Appetite and circuit breaker

Each slice gets a time budget when it is pulled (default 2 to 3 working days for a story). When the budget is
spent, stop, say so, and re-slice or amend plan and tasks with a semantic diff. Do not extend silently.

## Cadence (weekly, 30 minutes)

- **Review**: run `npm run demo`, show the report and the computed assurance level.
- **Retro**: what worked, what broke, numbers, actions. Notes in `docs/retro/NNN.md` from `TEMPLATE.md`.
- **Planning**: pull the next story from Ready, set its appetite.

## Numbers per slice

Demo recall and false positives, hours the pipeline on `main` was red, lead time per story, open deviations.

## Roles

Product owner: vannifr (priority by risk times client value). Execution: Claude (Opus for Tier C, Sonnet for Tier B)
and opencode (Qwen, GLM, Kimi; serial) for Tier A and suitable B work. Executors never commit; the orchestrator commits as vannifr.

## When to stop and ask

A new architecture or security decision outside the plan, a destructive or outward-facing action, a gate that cannot be made green,
or a change to the constitution.

## Customer feedback

One design partner reviews the demo and the report. Feedback becomes issues with the label `feedback`.
