# Implementation Plan: Reliable Scan Core

**Branch**: `004-reliable-scan-core` (trunk-based, commits op `main`) | **Date**: 2026-10-02 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `specs/004-reliable-scan-core/spec.md`
**Project**: Tessera (internal codename)

## Summary

Een gefaalde of ontbrekende scanner ziet er nu uit als een schoon systeem, bevindingen gaan verloren bij een niet-nul-exitcode, en er is geen bewijs van wat de audit deed (review #4, #5, #10, #22). Deze feature legt een betrouwbare kern onder de bestaande workflow:

1. Eén centrale `runTool`-wrapper (geen shell, array-argumenten, timeout, uitvoergrens, eigen configuratie, env-allowlist) met een exitcode-beleid en parser per tool. Vervangt stapsgewijs alle `promisify(exec)`-aanroepen.
2. Een scannerstatus per scanner en een INCOMPLEET-regel die doorwerkt in workflowresultaat en rapport.
3. Een evidence-record per uitgevoerde stap in een per-run bundel, met manifest, hashketen, bronrevisie en een verificatiecommando; de root-hash wordt buiten de map verankerd.
4. Redactie vóór alles wat history, evidence, logs of rapport bereikt; activities geven referenties terug, geen ruwe uitvoer.
5. Scanner-sturing vanuit de doelrepo wordt geneutraliseerd en vastgelegd.

Beslissingen en metingen: [research.md](./research.md). Typen: [contracts/](./contracts/). Entiteiten: [data-model.md](./data-model.md). Testscenario's: [quickstart.md](./quickstart.md).

## Technical Context

**Language/Version**: TypeScript 5.x (strict), Node.js ≥ 20.3 (CI-image `node:22-alpine`, digest-gepind)
**Primary Dependencies**: bestaand: `@temporalio/*` ^1.24, `pino` ^10, `uuid` ^9. Nieuw: geen. Node-ingebouwd: `crypto` (sha256), `child_process.execFile`, `fs`, `os`, `path`
**Storage**: bestandssysteem. Vluchtige werkmap `<os.tmpdir()>/tessera-<temporalRunId>`; blijvende evidence-bundel onder `TESSERA_EVIDENCE_ROOT`; rapport onder `outputDir` (ongewijzigd). Opslag-niveau-WORM valt buiten deze feature (research R13)
**Testing**: vitest 5 (unit + hermetische integratie met nep-runner en gemockte workflow-module), aparte contracttests met echte tools (`tests/contract/`, eigen vitest-config), cucumber voor de behavior-scenario's uit `/iikit-04-testify`, `npm run demo` als ground-truth-gate
**Target Platform**: Linux worker-host (Temporal worker via `ts-node`), Temporal dev-server of cluster
**Project Type**: single project (`src/`, `tests/`)
**Performance Goals**: evidence-overhead (versieprobe, hashing, schrijven, verzegelen) ≤ 5 % van de scanduur en ≤ 3 s per audit op de demo; verzegelen + verifiëren < 1 s voor een bundel < 100 MB
**Constraints**: geen ruwe tooluitvoer in de Temporal-history; activity-resultaat < 2 MB (≤ 2000 findings per stap); stdout-grens 64 MiB per tool; toolspecifieke timeouts binnen de bestaande `startToCloseTimeout` van 1 uur; geen nieuwe dependencies
**Scale/Scope**: één repo per audit, 4 parallelle scans per worker (`maxConcurrentActivityTaskExecutions: 4`), tientallen records per bundel; 28 `execAsync`-aanroepen in `src/activities/index.ts`, waarvan 6 op het workflowpad, plus de `spawn` in `cloneRepository`

## Constitution Check

*GATE: vóór het onderzoek gecontroleerd en na het ontwerp opnieuw (Step 6). Uitkomst per principe.*

| Principe | Hoe dit plan eraan voldoet | Pre | Post |
|----------|----------------------------|-----|------|
| I Security-First | Shell-injectie (#2) en RCE via `npx` (#1, licentiecheck) verdwijnen op het workflowpad; invoer aan de grens: `validateRepoUrl` blijft, `workflowId` alleen als slug in paden; veilige standaarden (env-allowlist, `--ignore-scripts`, privé mappen). Securityreview van `runTool`, redactie en store als afzonderlijke reviewstap (zie Migratie) | PASS | PASS |
| II TDD | Testspecs eerst via `/iikit-04-testify`, per FR minstens één test (traceerbaarheidstabel). Coveragevloer: zie Teststrategie, inclusief strengere drempel voor de kritieke paden en een aangetoond falende gate. Integratietests voor de workflow (hermetisch). Geen skip zonder oorzaak en eigenaar | PASS | PASS |
| III Enterprise Compliance | Evidence is herleidbaar tot stap, tool, revisie en ruwe-uitvoer-hash; het rapport vermeldt wat niet gescand is. `mapToCompliance` blijft placeholder (#19, buiten scope) en wordt niet als geverifieerd gepresenteerd | PASS | PASS |
| IV Traceability | Spec → plan → tasks → tests → code → evidence: elke FR heeft een ontwerpelement en een testniveau (tabel); de architectuur staat als diagram in dit plan | PASS | PASS |
| V Reliability & Observability | Timeouts per tool; retry alleen voor transiënte netwerkfouten, geen retry voor ongeldige invoer; activities idempotent (deterministische record-ids, exclusieve publicatie); gestructureerde logregel per stap met `runId` als correlatie-id. Heartbeats en kortere `startToClose` (#8) vallen buiten deze feature | PASS | PASS |
| VI Evidence-First | Kern van de feature: record per stap (FR-005/006), finding → record (FR-007), revisie (FR-008), manifest met hashes (FR-009), onveranderlijk na aanmaak (R8). Bewaring ≥ 1 jaar: deels in deze feature, opslaglaag operationeel (R13, beslissing 1) | PASS (FR-011 deels, besloten) | PASS (FR-011 deels, besloten) |
| VII No False Comfort | Vijf statussen, INCOMPLEET-regel, "issues found" ≠ "failed", rapport noemt niet-uitgevoerde checks en niet-gedekte scope-gebieden, code-review gelabeld als heuristiek | PASS | PASS |
| VIII Untrusted Input Isolation | Geen shell; framework-config per scanner; sturingsbestanden uit de bron geneutraliseerd en vastgelegd (R5); werkmap onvoorspelbaar (UUID), privé (0700), verwijderd op elk uitgangspad. Nog niet: groottegrens op de werkmap en sandboxing van de scanners zelf; netwerkbinding van Temporal (#3). Deze feature verergert ze niet en ze staan bij Buiten scope | PASS | PASS |
| IX Human Accountability | Niet geraakt. De goedkeuringsstap blijft ongewijzigd; er is geen modelgestuurde verlaging van ernst | PASS | PASS |
| X Claims Match Reality | Het rapport claimt alleen wat een `completed`-scanner aantoonde; de bewaarclaim verwijst naar de operationele verantwoordelijkheid. Status- en coveragecijfers in docs komen uit de pipeline; deze feature voegt geen handgeschreven statuscijfers toe | PASS | PASS |
| XI Independent Verification | Ground-truth-gate op `demo/EXPECTED.md` (D05–D07 gevonden, recall ≥ 8/18, clean-app `complete`); review door pipeline plus gestructureerde zelfreview; securityreview als aparte stap | PASS | PASS |
| Quality Gates / CI | Alle nieuwe tests draaien in `npm run verify` en dus in de pre-commit-hook en CI. Contracttests met echte tools en de demo draaien niet in CI (tools en Temporal ontbreken in het image); dat is een bestaande, gedocumenteerde lokale release-gate, geen nieuw verschil tussen lokaal en CI omdat ook `npm run verify` ze niet draait | PASS | PASS |

**Gate-uitkomst: PASS** (vóór en na het ontwerp). Geen schendingen, dus Complexity Tracking blijft leeg. De beslissing over FR-011 (deels geleverd) raakt de volledigheid, niet de naleving: de feature doet niets wat principe VI tegenspreekt.

## Architectuur

```
  ┌──────────────┐      start / query       ┌─────────────────┐      history       ┌──────────────────┐
  │ Audit Client │ ───────────────────────▶ │ Temporal Server │ ─────────────────▶ │ Temporal History │
  └──────────────┘                          └────────┬────────┘                    └──────────────────┘
                                                     │ task queue "audit"          (rootHash, statussen,
                                                     ▼                              findings met evidenceRef)
  ┌────────────────────────────────────────────────────────────────────────────────────────────┐
  │ Audit Worker                                                                               │
  │  ┌─────────────────────────────┐  proxyActivities  ┌───────────────────────────────────┐  │
  │  │ applicationAudit Workflow   │ ────────────────▶ │ Scan Activities                   │  │
  │  │ initAuditRun → fetchSource  │ ◀──────────────── │ (createScanActivities(deps))      │  │
  │  │ → 4 scans + code-review     │  ScanStepResult   └───────┬───────────────┬───────────┘  │
  │  │ → computeOutcome → seal     │  (refs, geen       │      │               │              │
  │  │ → approval → report         │   ruwe uitvoer)    ▼      ▼               ▼              │
  │  │ finally: cleanupRun         │        ┌────────────────┐ ┌──────────┐ ┌────────────────┐ │
  │  └─────────────────────────────┘        │ runTool Wrapper│▶│ Redactor │▶│ Evidence Store │ │
  │                                         └───────┬────────┘ └──────────┘ └───────┬────────┘ │
  └─────────────────────────────────────────────────┼──────────────────────────────┼──────────┘
                     execFile, geen shell           │                              │ records, artifacts,
                                                    ▼                              ▼ manifest, SHA256SUMS
  ┌──────────────────┐  clone   ┌──────────────┐  ┌──────────────────┐   ┌─────────────────┐   ┌─────────────┐
  │ Source Repository│ ───────▶ │ Scanner CLIs │─▶│ Private Work Dir │   │ Evidence Bundle │◀──│ Verify CLI  │
  └──────────────────┘          │ git, npm,    │  │ (0700, vluchtig) │   │ (0700→0500)     │   └─────────────┘
  ┌──────────────────┐ advisories│ gitleaks,    │  └──────────────────┘   └─────────────────┘
  │ npm Registry     │ ◀──────── │ semgrep      │                         ┌─────────────────┐
  └──────────────────┘          └──────┬───────┘                          │ Report File     │ ◀── generateReport
  ┌──────────────────┐   rules         │                                  └─────────────────┘
  │ Semgrep Registry │ ◀───────────────┘
  └──────────────────┘
```

Workflowverloop (alleen wat de spec vereist verandert; fasen, signalen en queries blijven):

```
run = initAuditRun()                      ── nieuw (vervangt mapaanmaak in cloneRepository)
try
  checkToolRequirements()                 ── alleen git verplicht; ontbrekende scanner = unavailable
  source = fetchSource(run)               ── clone + rev-parse + probe; faalt → seal → SourceUnavailableError
  detectTechStack / generateScopeDocument ── ongewijzigd (exec-aanroep in detectPII gemigreerd)
  steps = settle(all 4 scans) + settle(reviewCriticalPaths)  ── activity-fout → failed/activity-failed
  decision = computeOutcome(steps, untraced findings)        ── puur, deterministisch
  sealed = sealEvidence(run, usedRecordIds)                  ── manifest, keten, zelfverificatie
  mapToCompliance / crossValidate / P0-approval              ── ongewijzigd
  generateReport(… + outcome, scanners, revision, evidence)  ── statusblok bovenaan
  return AuditResult + outcome, notPerformed, scanners, source, evidence
finally
  cleanupRun(run)                         ── alleen de werkmap
```

## Traceerbaarheid FR → ontwerp → test

| FR | Ontwerpelement | Testniveau |
|----|----------------|-----------|
| FR-001 | `ScannerStatusEntry`, vijf statussen, `ToolPolicy.classify` | unit (policies), integratie (workflow) |
| FR-002 | `computeOutcome`, `notPerformed`, toepasbaarheidstabel (R4) | unit, integratie per scanner (SC-001) |
| FR-003 | `mayReportClean`, rapportformulering | unit (rapport) |
| FR-004 | exitcodebeleid per tool (R3), `issues-found` als oorzaak | unit per tool, contract met echte tools |
| FR-005 | `runTool` schrijft altijd één record; in-process-stappen ook | unit, integratie (aantal records = aantal stappen) |
| FR-006 | velden `EvidenceRecord` | unit (schema-validatie) |
| FR-007 | `evidenceRef` op finding, outcome-guard | unit, integratie |
| FR-008 | `source.revision` (R15) | unit (fetchSource met nep-runner), demo |
| FR-009 | manifest + `SHA256SUMS` (R9) | unit |
| FR-010 | `verifyEvidenceBundle` + CLI | unit (tamper-matrix), demo |
| FR-011 | append-only, 0400/0500, `retainUntil`, cleanup-guard (R8, R13) | unit; opslaglaag buiten scope |
| FR-012 | drie redactielagen, refs in history, pino-redact (R11, R12) | unit, demo-secret-sweep |
| FR-013 | `maxOutputBytes`, `partial/output-truncated`, findings-cap | unit |
| FR-014 | `source-probe` + vlaggen + geïsoleerde npm-map (R5) | unit, contract met vijandige fixtures |
| FR-015 | runId per record, aparte bundel per run, verify `run-mismatch` | unit, integratie (twee runs) |
| FR-016 | statusblok en tabel bovenaan het rapport | unit (rapport) |
| FR-017 | één bundelmap met records, artefacten, manifest | unit, demo |

## Migratiepad

Elke stap is één commit volgens constitutie, Development Workflow (Branch Strategy) en Quality Gates, met testspecs uit `/iikit-04-testify` die vooraf lokaal rood zijn aangetoond (principe II). Verificatie per stap: `npm run verify` lokaal en de CI-status na push. Nieuwe modules zijn ongebruikt tot ze in de workflow worden aangesloten; zo blijft onaf werk donker zonder runtime-toggle. De Tier-kolom is een voorstel voor `/iikit-05-tasks` (A mechanisch, B oordeel binnen vastgelegd ontwerp, C architectuur of hoge blast radius).

| # | Commit (conventional) | Inhoud | Verificatie | Tier |
|---|-----------------------|--------|-------------|------|
| 1 | `feat(scan): scanner status model and outcome rule` | `src/scan/status.ts`, additieve typen | unit FR-001..004 | B |
| 2 | `feat(evidence): redaction module` | `src/evidence/redact.ts` | unit FR-012, fixtures met de demo-secretvormen | C (security) |
| 3 | `feat(evidence): evidence store with atomic publish` | `src/evidence/store.ts`, `hash.ts` | unit FR-005/006/011/015 (tmp-root) | C |
| 4 | `feat(evidence): manifest, hash chain and verify CLI` | `manifest.ts`, `verify.ts`, `src/cli/verify-evidence.ts`, script `evidence:verify` | unit FR-009/010/017, tamper-matrix SC-004 | B |
| 5 | `feat(scan): runTool wrapper with injectable process runner` | `process-runner.ts`, `run-tool.ts`, `env.ts` | unit: ENOENT, timeout, afkapping, env-allowlist, geen shell | C (security) |
| 6 | `refactor(workflow): run lifecycle with initAuditRun, fetchSource and cleanupRun` | vervangt `cloneRepository`; clone + rev-parse + probe via `runTool`; cleanup in `finally`; scans krijgen `source.repoPath` | unit fetchSource (nep-runner), integratie workflow; FR-008, FR-014 (deels) | B |
| 7 | `fix(scan): npm audit via runTool with isolated config` | `runNpmAudit(run, source)`, policy, `settle` in workflow | unit FR-004; **demo: D05–D07 gevonden** | B |
| 8 | `fix(scan): gitleaks via runTool with framework config and redaction` | `--config`, `--exit-code 42`, `--redact`, `--ignore-gitleaks-allow` | unit; contract met vijandige `.gitleaksignore` | B |
| 9 | `fix(scan): semgrep via runTool with exit-code policy` | crash → failed, errors → partial, `--disable-nosem`, `/tmp`-regels weg | unit met opgenomen crash-JSON; demo: D09 en D10 blijven; D11 vervalt bewust (beslissing 2) | B |
| 10 | `fix(security): license check from lockfile instead of npx` | in-process (R14) | unit; RCE-fixture voert niets uit | B |
| 11 | `fix(scan): code review and tool checks without exec, no secrets in findings` | `reviewCriticalPaths`, `detectPII`, `checkToolRequirements` via runTool/in-process; npm niet meer verplicht | unit FR-012 | B |
| 12 | `feat(workflow): seal evidence and report INCOMPLETE outcome` | `sealEvidence`, outcome-guard, `AuditResult`-uitbreiding, bronfoutpad | integratie: elke scanner om beurten unavailable/failed (SC-001), twee runs (FR-015) | C |
| 13 | `feat(report): outcome and scanner status table at the top` | rapport (FR-003/016), evidence-sectie met root-hash en verify-commando | unit rapport | B |
| 14 | `test(demo): ground-truth gate and secret sweep` | `demo/run-demo.js`: minimumeisen, verify op bundels, zoekactie naar geplante secrets; `EXPECTED.md` ongewijzigd | `npm run demo` | B |
| 15–17 | `refactor(security): migrate remaining exec calls to runTool` | 22 aanroepen buiten het workflowpad, in drie batches | bestaande tests groen, hermetisch | A |
| 18 | `ci: forbid child_process exec` | ESLint `no-restricted-imports`/`no-restricted-properties` op `exec`/`execSync` | gate aangetoond falend op een tijdelijke overtreding | A |
| 19 | `docs: evidence bundle, verify command and scanner status` | README/AGENTS: `TESSERA_EVIDENCE_ROOT`, `evidence:verify`, statusbetekenis | doc-review | A |

Securityreview (principe I, Pre-Merge Checks): na stap 5 en na stap 12 een gestructureerde review van `runTool`, env-allowlist, redactie, store en padcontroles, inclusief de payloads uit de securityreview (`x;id>…;#` als workflowId, vijandige `.npmrc`).

Achterwaartse compatibiliteit: `Finding` en `AuditResult` alleen additief; `evidencePath` wijst voortaan naar de bundel; bestaande rapportsecties blijven en schuiven onder het nieuwe statusblok; queries ongewijzigd. Lopende workflows: worker leeglopen vóór uitrol van stap 6 en 12 (workflowcode wijzigt; research R17).

## Teststrategie

Per constitutie II (testspecs eerst, aantoonbaar rood, dan implementatie):

- **Per FR minstens één test** (tabel hierboven); SC-001 als geparametriseerde integratietest over alle scanners en de statussen `unavailable` en `failed`.
- **Hermetisch**: unit- en integratietests gebruiken de nep-`ProcessRunner` en opgenomen tooluitvoer in `tests/fixtures/tools/` (npm audit van de demo, npm ENOLOCK, npm double-loading, gitleaks schoon/lek/fout, semgrep schoon/resultaten/crash exit 2). Geen test in `npm run test:coverage` roept een geïnstalleerde tool aan. Daarmee is de coveragemeting lokaal en in de CI-container gelijk (les uit `e9cbbc1`).
- **Workflow-integratie** zonder Temporal-server: gemockte `@temporalio/workflow` (research R16).
- **Contracttests met echte tools** in `tests/contract/` met eigen vitest-config (`npm run test:tools`): vijandige fixtures per neutralisatie (R5) en de exitcodes (R3). Ontbrekende tool: skip met vastgelegde oorzaak en eigenaar (`vannifr`), zoals `scripts/ci/gate.sh` lokaal doet.
- **Ground-truth-gate** `npm run demo` vóór "done": D05, D06, D07 gevonden; strikte recall ≥ 8/18 (baseline 6/18 plus D05–D07 min D11; research R6); geen nieuwe vals-positieven op clean-app ten opzichte van de baseline (1); clean-app-uitkomst `complete`; `evidence:verify` op beide bundels exit 0; geplante secretwaarden nergens in bundel, rapport of worker-log.
- **Coveragevloer**: globaal blijft minimaal 69/40/84/70 (statements/branches/functions/lines); deze feature verlaagt hem niet. Kritieke paden `src/scan/**` en `src/evidence/**`: 90/85/90/90 via per-glob-drempels in `vitest.config.ts`. Bij invoering wordt aangetoond dat de per-glob-gate faalt (tijdelijk een test uitschakelen in een scratch-kopie, exitcode ≠ 0 vastleggen). Na stap 14 wordt de globale vloer opnieuw gemeten in de CI-container en naar die meting (naar beneden afgerond) opgetrokken.
- **Vervangen tests**: bestaande tests die de oude signaturen of het oude foutgedrag vastleggen, worden in dezelfde commit vervangen door de 004-tests, per test vermeld als "superseded by FR-xxx" (open vraag 3). Het lege, geskipte `cloneRepository`-succestest (#14) verdwijnt doordat `fetchSource` echte tests krijgt.

## Niet-functionele afweging

| NFR | Afweging en maatregel |
|-----|------------------------|
| Performance | sha256 haalt honderden MB/s; met uitvoer van tientallen KB is hashing verwaarloosbaar. De grootste extra kost is de versieprobe per stap (semgrep ~1 s Python-start); acceptabel binnen ≤ 3 s per audit, cache per worker als het meten anders uitwijst. Geheugen: tot 64 MiB stdout per tool × 4 parallel. Verzegelen leest elk bestand één keer. Duur per stap staat in elk record en in de logregel, dus de overhead is meetbaar in de demo. |
| Security | Geen shell, env-allowlist (geen `NODE_OPTIONS`, `npm_config_*`, tokens naar tools), privé werkmap en bundel met `lstat`-controles, geen symlinks volgen in in-process-lezers, exclusieve publicatie, framework-config per scanner, redactie in drie lagen, padtokens in plaats van host-paden in evidence. Restrisico's: scanners zelf draaien niet in een sandbox; semgrep draait met metrics uit; een eigen regelset volgt als vervolgfeature (beslissing 2). |
| Observability | Eén gestructureerde logregel per stap: `runId`, `stepId`, `scanner`, `status`, `cause`, `exitCode`, `durationMs`, `outputBytes`, `truncated`, `recordId`; nooit tooluitvoer. `state`-query toont scannerstatussen live. Metrics-backend bestaat niet; buiten scope. |
| Foutafhandeling | Toolproblemen worden status, geen exception; alleen transiënte netwerkfouten worden retryable. Een activity die na retries toch faalt, wordt in de workflow `failed/activity-failed`. Fail-closed: als de evidence-store niet kan schrijven, faalt de stap (geen bewering zonder bewijs). Bronfout: evidence verzegeld, geen rapport, `SourceUnavailableError` met uitkomst en bundelpad in de details. |
| Toegankelijkheid rapport | Uitkomst als tekst in de eerste regels ("Audit outcome: INCOMPLETE") en niet alleen via kleur of symbool; tabellen met kopregel; statuswoorden uit één vaste lijst; oorzaken in gewone taal; verify-CLI zonder kleurcodes, eerste woord `VERIFIED` of `FAILED`. |

## Buiten scope

- Opslag-niveau-onveranderlijkheid, back-up en verwijderbeleid van evidence (R13, beslissing 1); digitale handtekening of tijdstempel van de root-hash.
- Heartbeats en kortere `startToClose` (#8), Temporal-netwerkbinding (#3), sandboxing van scanners, groottegrens op de werkmap.
- Aansluiten van de overige domeinen (#9), SQL-injectiedetectie (D08), juiste ernst voor D04/D11, placeholder `crossValidate`/`mapToCompliance` (#19).
- Evidence voor de goedkeuringsbeslissing (feature 002) en het rapport zelf in het manifest.

## Beslissingen van de gebruiker (2026-10-02)

1. **Bewaring (FR-011)**: deels geleverd in deze feature (append-only schrijven, read-only permissies, `retainUntil`, verankerde root-hash). WORM-opslag voor `TESSERA_EVIDENCE_ROOT` is een aparte operationele stap en het rapport claimt niet meer dan dat.
2. **Semgrep**: geen `--config auto`; `--metrics=off` met vaste packs (`p/javascript`, `p/nodejs`) en een eigen, versiebeheerde regelset als aparte vervolgfeature. Verwacht effect op recall: D11 eraf, D05–D07 erbij (research R6).
3. **Bestaande tests**: vervangen per migratiecommit door de 004-testspecs, elk gemarkeerd als "superseded by FR-xxx"; geen adapters met de oude signatuur.

## Project Structure

### Documentation (this feature)

```text
specs/004-reliable-scan-core/
  spec.md
  plan.md              # dit bestand
  research.md          # beslissingen, metingen, alternatieven
  data-model.md        # entiteiten, validatie, toestandsovergangen
  quickstart.md        # testscenario's per user story
  contracts/
    scanner-status.ts
    evidence-record.ts
    evidence-manifest.ts
    run-tool.ts
    scan-activities.ts
    verify-contract.md
  tasks.md             # /iikit-05-tasks (niet door deze fase)
```

### Source Code (repository root)

```text
config/scanners/
  gitleaks.toml                 # [extend] useDefault = true
src/
  scan/
    status.ts                   # puur; ook door de workflow geïmporteerd
    process-runner.ts           # enige plek met child_process
    run-tool.ts
    env.ts
    source-probe.ts             # sturingsbestanden en inline markers
    license-lockfile.ts
    policies/
      git.ts  npm-audit.ts  gitleaks.ts  semgrep.ts  version.ts
  evidence/
    redact.ts  hash.ts  store.ts  manifest.ts  verify.ts
  activities/
    index.ts                    # exporteert de factory-instantie; overige activities blijven
    run-lifecycle.ts            # initAuditRun, fetchSource, sealEvidence, cleanupRun
    scans.ts                    # createScanActivities(deps)
  cli/
    verify-evidence.ts
  workflows/index.ts            # aangepast volgens het workflowverloop hierboven
  types/index.ts                # additieve typen
tests/
  unit/scan/  unit/evidence/  unit/report/
  integration/workflow-outcome.test.ts
  contract/                     # echte tools, eigen vitest-config
  fixtures/tools/               # opgenomen tooluitvoer
```

**Structure Decision**: bestaand single project. Nieuwe kernlogica komt in `src/scan/` en `src/evidence/` in plaats van in de monoliet `src/activities/index.ts` (2920 regels, #20); de monoliet wordt niet verder opgesplitst dan wat deze feature raakt.

## Complexity Tracking

Geen schendingen van de constitutie; niet van toepassing.
