# Prompt templates from feature 004 (first step of distilling the method)

Used on 2026-10-03 and kept close to what worked. Replace the placeholders. Every template states scope, forbids side effects,
demands a short report and ends with "do not commit". Agents use their own scratchpad folder.

## 1. Red phase (test writer, Tier B)
Read AGENTS.md, the contract file and the scenarios <TS ids>. Write failing tests plus throwing stubs; types are copied verbatim from the
contract. The test file must LOAD and then fail on assertions or on the thrown "not implemented", never on a missing module. Use an independent
oracle (recompute hashes or signatures with the platform crypto in the test). Change only <files>. Report: number of tests, number failing and
why, choices not stated.

## 2. Implementation (Tier C, strongest model)
Read the principle(s), research notes, contract and the red tests. Implement so the tests pass; do not edit tests (if a test contradicts the
contract, stop and say which). Then run a mutation check yourself: at least N mutations on the invariants (list them), assert the pattern
exists before replacing, restore in place with a hash before and after, report which test kills each mutation, add tests for survivors.
Run the full verify and the BDD gate; thresholds unchanged. Report: changes per file, mutation table, residual risks.

## 3. Test hardening (Tier B, after a survivor list)
Add tests only (never remove or weaken) for the listed survivors with exact-output assertions and order checks; prove each with the
mutation that survived; report any implementation defect the new tests expose (report, do not fix).

## 4. Step definitions (Tier B)
Bind every Gherkin step to the real code with fake runners only at the process boundary; no tautological steps; run the step quality
scripts; run at least four production mutations and show a scenario fails; update only the named gate script.

## 5. Cross-family review (read only)
You did not write this code. Do not edit or run state-changing commands. Hunt for <list of failure classes>. Output a numbered list: severity,
file:line, one-sentence defect, concrete failure scenario, one-line fix; mark anything unverified as UNVERIFIED; at most N items; one line
per clean area. Hard timeout on the run.

## 6. Triage of a review (orchestrator)
For each claim: read the cited line, decide valid, minor, not applicable or false, and record it in a table with the action. Automatic
findings are leads, not facts. Fix the valid ones through template 2 with a mutation that proves the fix.

## 7. Ratchet and deviations
Every gate that tightens stays tightened; every relaxation is a deviation with owner, reason and deadline in the README.
