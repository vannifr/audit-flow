# Quickstart: Reliable Scan Core

**Feature**: 004-reliable-scan-core | **Datum**: 2026-10-02
Testscenario's per user story, herleidbaar naar FR en SC. Bestandsnamen van tests zijn voorstellen; definitieve test-IDs komen uit `/iikit-04-testify`. Hermetisch = nep-`ProcessRunner`, tijdelijke evidence-root, geen geïnstalleerde tools nodig.

## Voorbereiding

```bash
npm ci
npm run verify                         # build, hermetische tests met coverage, lint
export TESSERA_EVIDENCE_ROOT="$HOME/.local/share/tessera/evidence"
npm run test:tools                     # contracttests met echte tools (gitleaks, semgrep, npm, git)
npm run demo                           # end-to-end met Temporal dev-server en ground truth
```

---

## US1 Honest scan outcome (P1)

| # | Scenario | Niveau | Verwacht | Herleiding |
|---|----------|--------|----------|-----------|
| 1.1 | Workflow met nep-activities; per scanner om beurten `spawnErrorCode: ENOENT` | integratie (`tests/integration/workflow-outcome.test.ts`) | `outcome = incomplete`, `notPerformed` noemt precies die scanner met `unavailable/not-installed`; rapport toont geen "no findings" voor dat gebied | FR-001, FR-002, FR-003, SC-001 |
| 1.2 | Nep-runner geeft timeout resp. semgrep-crash (exit 2, `results: []`, `errors[0]` uit fixture) | unit policy + integratie | status `failed`, oorzaak `timeout` resp. `tool-error`, `causeDetail` gevuld; audit incomplete | FR-001, FR-002, FR-004, SC-001 |
| 1.3 | Alle scanners `completed`, nul findings | integratie + unit rapport | `outcome = complete`; rapport: "No findings" plus lijst van voltooide scanners | FR-002, FR-016 |
| 1.4 | npm audit exit 1 met demo-JSON; gitleaks exit 42 | unit policy | status `completed`, oorzaak `issues-found`, findings aanwezig | FR-004 |
| 1.5 | Rapport bij incomplete audit | unit (`tests/unit/report/`) | eerste regels: "Audit outcome: INCOMPLETE" en "Not performed: …"; daarna de statustabel; risiconiveau vermeldt "based on completed scanners only" | FR-016, FR-003 |
| 1.6 | Bron niet op te halen (nep-runner: `git clone` exit 128, "Repository not found") | integratie | workflow faalt met `SourceUnavailableError`, details `outcome: incomplete` en bundelpad; geen rapportbestand; bundel verzegeld met het clone-record | edge case bron, FR-002, FR-005 |
| 1.7 | `package.json` zonder lockfile | integratie | npm-audit en license-check `skipped/no-lockfile`, verplicht, audit incomplete | FR-001, FR-002 |

Handmatig (demo): `PATH` zonder semgrep, `npm run demo` → rapport van vulnerable-app begint met INCOMPLETE en noemt semgrep `unavailable`.

## US2 Evidence record for every step (P1)

| # | Scenario | Niveau | Verwacht | Herleiding |
|---|----------|--------|----------|-----------|
| 2.1 | Volledige hermetische run | integratie | aantal records = aantal uitgevoerde stappen (clone, revision, probe, 4 scans + code-review, versieprobes in het record zelf); ook stappen zonder findings en gefaalde stappen | FR-005, SC-002 |
| 2.2 | Elk record tegen het schema | unit | alle velden uit `contracts/evidence-record.ts` aanwezig en geldig; geen absolute host-paden | FR-006 |
| 2.3 | Elke finding in het resultaat | integratie | `evidenceRef.recordId` bestaat, `recordSha256` klopt met het bestand, `locator` wijst een bestaand element in het artefact aan | FR-007, SC-002 |
| 2.4 | Finding zonder `evidenceRef` geïnjecteerd | unit `computeOutcome` | `incomplete`, `notPerformed` bevat `untraced-findings` | FR-007 |
| 2.5 | Revisie | unit fetchSource | `source.revision` = uitvoer van `rev-parse` uit de nep-runner, in elk later record en in het manifest; ongeldig formaat → failed | FR-008 |
| 2.6 | Retry: eerste poging schrijft record en crasht | unit store + integratie | twee records `<step>.a1`, `<step>.a2`; a1 `used: false` in het manifest; niets overschreven | FR-005, edge case hervatting |
| 2.7 | Lege uitvoer met exit 0 | unit runTool | status `completed`, artefact van 0 bytes met de sha256 van de lege string | edge case lege uitvoer |

Handmatig (SC-006, < 2 minuten): open het rapport, kies een finding, zoek de record-id in de Evidence-kolom, open `records/<id>.json`, lees `tool.version`, `source.revision` en `output.rawSha256`, volg `evidenceRef.locator` in het artefact.

## US3 No findings lost when a tool reports issues (P2)

| # | Scenario | Niveau | Verwacht | Herleiding |
|---|----------|--------|----------|-----------|
| 3.1 | Opgenomen npm audit-uitvoer van de demo (exit 1) | unit policy | één finding per (pakket, advisory); lodash, minimist en express/body-parser/qs/path-to-regexp aanwezig met ernst volgens de mapping (critical → P0, high → P1, moderate → P2, low → P3) | FR-004, SC-003 |
| 3.2 | Nep-runner met `stdoutTruncated: true` | unit runTool | status `partial`, oorzaak `output-truncated`, artefact `truncated: true` | FR-013 |
| 3.3 | Parser levert 2500 findings | unit | resultaat bevat 2000 findings, status `partial/findings-truncated`, artefact bevat alles | FR-013 |
| 3.4 | Demo | e2e | D05, D06, D07 gevonden; strikte recall ≥ 8/18 | SC-003 |

## US4 Verifiable evidence integrity (P2)

| # | Scenario | Niveau | Verwacht | Herleiding |
|---|----------|--------|----------|-----------|
| 4.1 | Ongewijzigde bundel | unit verify | `ok: true`, geen issues; CLI exit 0, eerste woord `VERIFIED` | FR-010, SC-004 |
| 4.2 | Tamper-matrix: één byte wijzigen in een record, in een artefact; een record verwijderen; een bestand toevoegen in `records/`, in `artifacts/` en in de root | unit verify | precies één issue per manipulatie (`modified`, `missing`, `extra`) met het juiste pad; CLI exit 1 | FR-010, SC-004 |
| 4.3 | Manifest volledig herberekend door een aanvaller, verify met `--expect-root` van het rapport | unit verify | `rootMatches: false`, `ok: false` | FR-010 |
| 4.4 | Record uit een andere run in de bundel geplaatst | unit verify | issue `run-mismatch` | FR-015 |
| 4.5 | Twee gelijktijdige hermetische runs | integratie | twee bundels, elk record met de eigen runId, beide verifiëren | FR-015, edge case parallel |
| 4.6 | Na verzegelen | unit store | bestanden 0400, mappen 0500; schrijven of overschrijven faalt; `cleanupRun` weigert een pad onder de evidence-root | FR-011 |
| 4.7 | Bundel als geheel | unit + demo | één map met `records/`, `artifacts/`, `manifest.json`, `SHA256SUMS`; `sha256sum -c SHA256SUMS` slaagt | FR-009, FR-017 |

```bash
npm run evidence:verify -- "$TESSERA_EVIDENCE_ROOT/<slug>-<runId>" --expect-root <rootHash uit het rapport>
```

## US5 Evidence without exposed secrets (P3)

| # | Scenario | Niveau | Verwacht | Herleiding |
|---|----------|--------|----------|-----------|
| 5.1 | Redactor op fixtures met de demo-secretvormen (AWS-voorbeeldsleutels, wachtwoord, signeergeheim, hex-API-sleutel, PEM, JWT, `user:pass@`) | unit | geen enkele waarde blijft over; type staat in `[REDACTED:<type>]` | FR-012 |
| 5.2 | gitleaks- en semgrep-fixtures met `Secret`, `Match`, `extra.lines`, `extra.metavars` | unit sanitize | opgeslagen artefact bevat die velden niet; `File` en `StartLine` blijven | FR-012 |
| 5.3 | `reviewCriticalPaths` op een fixture met `password = "…"` | unit | finding met bestand en regel, `content` zonder de waarde | FR-012 |
| 5.4 | Logs en history | integratie | vastgelegde pino-uitvoer en alle activity-resultaten bevatten geen fixture-secret | FR-012 |
| 5.5 | Demo secret sweep | e2e | zoeken naar de letterlijke waarden uit `demo/vulnerable-app/src/config.js` en `auth.js` in bundel, rapport en worker-log: 0 treffers; locatie en type wel in het rapport | SC-005 |

## FR-014 Scanner-sturing uit de bron (edge case)

| # | Fixture in de doelrepo | Niveau | Verwacht |
|---|------------------------|--------|----------|
| 6.1 | `.gitleaksignore` met de fingerprint van een geplant lek | contract (gitleaks) + unit probe | lek wordt gerapporteerd; bestand uit de werkkopie verwijderd; `OverrideAttempt` met pad en sha256 |
| 6.2 | `.gitleaks.toml` met allowlist voor alles | contract | lek wordt gerapporteerd (`--config` van het framework) |
| 6.3 | `// gitleaks:allow` en `# nosemgrep` | contract | beide alsnog gerapporteerd; markers geteld in de probe |
| 6.4 | `.semgrepignore` dat `src/` uitsluit | contract (semgrep) | `eval` in `src/` wordt gevonden; poging vastgelegd |
| 6.5 | `.npmrc` met `registry=http://127.0.0.1:9/` en `audit=false` | unit (args) + contract (npm) | npm audit draait in de geïsoleerde map, geen verbinding met de vijandige registry, kwetsbaarheden gerapporteerd |
| 6.6 | `node_modules/.bin/license-checker` dat een markerbestand schrijft | unit | markerbestand bestaat na de audit niet |

## Scenario 7: handtekening (User Story 6)

| # | Gegeven | Dan | Testniveau | Verwacht |
|---|---------|-----|------------|----------|
| 7.1 | voltooide audit, publieke sleutel | `evidence:verify --pubkey` | unit + demo | `valid`, sleutel genoemd, exit 0 |
| 7.2 | record gewijzigd en manifest met de hand herberekend | verify | unit | `invalid`, exit ≠ 0 (SC-007) |
| 7.3 | geen handtekening / andere sleutel | verify | unit | `unsigned` / `unknown-key`, nooit `verified` (SC-008) |
| 7.4 | rapport van een ondertekende audit | lezen | unit | sleutel, tijdstip en de regel "tijdstip niet onafhankelijk getijdstempeld" |
| 7.5 | sleutelpad binnen de bundelroot | `signEvidence` | unit | geweigerd |
| 7.6 | geen sleutel, `TESSERA_REQUIRE_SIGNATURE=1` | audit | integratie | uitkomst INCOMPLEET, niveau 0 |

## Release-gate (Definition of Done voor deze feature)

1. `npm run verify` groen lokaal en in CI, inclusief de per-glob-coveragedrempels.
2. `npm run test:tools` groen lokaal met alle tools aanwezig.
3. `npm run demo`: D05–D07 gevonden, strikte recall ≥ 8/18, clean-app `complete` zonder nieuwe vals-positieven, `evidence:verify` exit 0 op beide bundels, secret sweep 0 treffers.
4. Resultaten van punt 3 vastgelegd in de commit van stap 14 (principe X: gemeten, niet beweerd).
