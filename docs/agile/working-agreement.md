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

## Timebox and circuit breaker

We do not estimate. The product owner sets a timebox for each slice before it starts: how much time we are willing to
spend, not a prediction. Current timebox: MVP slice of feature 004 (User Story 1, release v0.2.0), one working day,
started 2026-10-03. When the timebox is spent, stop, say so, and re-slice or amend plan and tasks with a semantic diff.
Do not extend silently. Cut scope, not quality: the first things to go are later stories and polish.

## Agent runs and resources

- Every opencode run gets a hard timeout (`timeout 600`) so a runaway cannot burn the quota; an agent run that exceeds it is
  killed and its task is re-cut. After a 429 do not retry in a loop: fall back to a Claude subagent or a free Zen model.
- Quota and tokens are a budget: note exhaustion as an incident and take the next task that does not need that resource.

## Review by another model family

- Builder and reviewer come from different families for Tier B and C work (for example Claude builds and Qwen, GLM or Kimi
  reviews the diff read-only, or the other way round). Tier C also gets a second opinion for the highest-stakes files.
- The commit body names who built, who reviewed and what the review found. Model review never replaces mutation tests,
  property tests or the product owner's judgment on Tier C commits.
- Only the framework's own code goes to external models; client code never, without explicit permission.

## Stop the line

A red pipeline on `main` stops all new work until it is green again. Security fixes from the review (class of service
"expedite") may go first.

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
