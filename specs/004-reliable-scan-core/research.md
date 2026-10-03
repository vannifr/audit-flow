# Research: Reliable Scan Core

**Feature**: 004-reliable-scan-core | **Datum**: 2026-10-02
**Bronnen**: `spec.md`, `CONSTITUTION.md` v2.0.0, `docs/review-report.md` (#1, #2, #4, #5, #6, #7, #10, #16, #17, #22, §2), code op `main` (`e9cbbc1`).

Empirische controles zijn op 2026-10-02 lokaal gedraaid in de sessie-scratchpad (gitleaks 8.30.1, semgrep 1.178.0, npm 10.9.8), tegen een git-kopie van `demo/vulnerable-app`. Ze zijn reproduceerbaar met de commando's hieronder; de uitkomst geldt voor deze versies en wordt per versie in de evidence vastgelegd.

---

## R1 Procesuitvoering zonder shell

**Beslissing**: één `ProcessRunner` op basis van `child_process.execFile` met `shell: false`, `encoding: 'buffer'`, array-argumenten, `cwd`, `timeout`, `killSignal: 'SIGKILL'` en `maxBuffer` (stdout standaard 64 MiB, instelbaar met `TESSERA_MAX_OUTPUT_MB`; stderr 1 MiB). De runner verwerpt nooit: spawn-fouten, timeouts en buffer-overschrijding komen terug als velden van `ProcessOutcome`. `runTool` legt daarbovenop beleid, redactie en evidence.

**Rationale**: dekt #2 (shell-injectie via `workflowId`/`repoPath`) structureel: zonder shell bestaat er geen interpretatie van metatekens. Bufferen in geheugen houdt de code klein; `maxBuffer`-overschrijding is een expliciet signaal dat we als `partial/output-truncated` rapporteren (FR-013). Met de demo-uitvoer (npm audit 15 KB, semgrep ~30 KB) zit er een factor > 2000 tussen typische uitvoer en de grens.

**Alternatieven**:
- `spawn` met streaming naar een bestand en incrementele hash: geheugenbegrensd tot willekeurige grootte, maar ~3× meer code (streams, backpressure, foutpaden) voor een probleem dat nu niet bestaat. Herzien als een echte audit de grens raakt; de status `partial` maakt dat zichtbaar.
- `exec` behouden met escaping: verworpen, escaping is per shell verschillend en foutgevoelig; principe VIII vraagt argumenten als data.

## R2 Testbaarheid: injecteerbare runner en activity-factory

**Beslissing**: `createScanActivities(deps)` bouwt alle nieuwe en gemigreerde activities uit `{ runner, clock, evidenceRoot, tmpRoot, frameworkVersion, workerEnv }`. `src/activities/index.ts` exporteert de instantie met standaard-deps; de worker registreert die ongewijzigd. Unittests roepen de factory aan met een nep-runner die vooraf opgenomen tool-uitvoer teruggeeft (fixtures in `tests/fixtures/tools/`).

**Rationale**: de bestaande skip-lessen (§4 review: `vi.mock('child_process')` met timeouts, spawn niet injecteerbaar, tests die echte tools aanroepen) en de CI-parity-les (commit `e9cbbc1`: coverage verschilt tussen lokaal en CI-container omdat tools lokaal wél en in CI niet aanwezig zijn) hebben dezelfde oorzaak: tests hangen af van de omgeving. Met injectie zijn unit- en integratietests hermetisch en is coverage in beide omgevingen gelijk.

**Alternatieven**: `vi.mock('child_process')` (verworpen: breekbaar, oorzaak van de huidige skips); globale setter `setProcessRunner()` (verworpen: verborgen toestand tussen tests).

## R3 Exitcode-beleid per tool

**Beslissing**: elke tool krijgt een `ToolPolicy` met `parse` (uit stdout, of uit het rapportbestand waar de tool dat vereist), `classify` en `sanitize`. De tabel staat in `contracts/run-tool.ts`. Kernpunten:

| Tool | Waarneming (lokaal, 2026-10-02) | Beleid |
|------|----------------------------------|--------|
| npm audit | Demo: exit 1 met geldige JSON (9 kwetsbare pakketten, 1 critical, 5 high). Zonder lockfile: exit 1 met `{"error":{"code":"ENOLOCK"}}`. Zelfde bestand als user- en globalconfig: exit 1 met lege stdout ("double-loading config"). | Exit 0/1 met `vulnerabilities`+`metadata` → completed (1 = issues-found). JSON met `error` → failed (ENOLOCK wordt vooraf afgevangen als skipped/no-lockfile). Geen JSON → failed/parse-error. |
| gitleaks | Schoon: 0. Lek: de waarde van `--exit-code`. Ongeldig pad: 1. | `--exit-code 42`: 0 → completed, 42 → completed/issues-found, 1 of anders → failed. Zo zijn "lek gevonden" en "tool faalde" niet meer dezelfde code. |
| semgrep | `--config auto`: exit 0, 8 resultaten, twee runs identiek. `p/secrets`, `p/security-audit`, `p/default`: exit 2 zonder `EIO_BACKEND=posix` (io_uring-crash van `semgrep-core`, zie R6), exit 0 mét. Bevindingen zonder `--error`: exit 0. | Exit 0/1 + JSON: completed, of partial als `errors[]` niet leeg is. Exit ≥ 2 met resultaten → partial; zonder resultaten → failed. Dit is precies het patroon van review-bevinding #10 en het niet-determinisme in §2.4: een crash die eerder als "0 bevindingen" verscheen, wordt nu `failed`. |
| git | `clone` faalt met 128; oorzaak alleen in stderr. | 128 + stderr met "Could not resolve host", "timed out", "early EOF" → retryable `TransientSourceError`; anders non-retryable `SourceUnavailableError` (#17). |

Toolversie: per stap via `versionArgs` (gitleaks gebruikt `version`, de rest `--version`), eerste regel, geredigeerd, maximaal 200 tekens.

**Alternatieven**: één generieke regel "exit ≠ 0 is fout" (de huidige bug, #4/#10); uitvoer altijd naar bestand (gitleaks en semgrep kunnen naar stdout: `--report-path -` resp. `--json`, dus niet nodig).

## R4 Statusmodel, verplichte scanners en INCOMPLEET-regel

**Beslissing**: vijf statussen (FR-001) met een vaste oorzaakenumeratie (`contracts/scanner-status.ts`). De verplichte set wordt per run bepaald door toepasbaarheid:

| Scanner | Verplicht als | Anders |
|---------|---------------|--------|
| gitleaks | altijd | — |
| semgrep | altijd | — |
| npm-audit | `package.json` aanwezig | skipped/not-applicable, `required=false` |
| license-check | `package.json` aanwezig | skipped/not-applicable, `required=false` |
| code-review | nooit (heuristiek, principe VII) | status wel getoond, label "heuristic" |

`package.json` zonder npm-lockfile: npm-audit en license-check krijgen `skipped/no-lockfile` (of `unsupported-lockfile` bij alleen yarn/pnpm) en blijven verplicht, dus INCOMPLEET. `computeOutcome` is een pure functie in `src/scan/status.ts` die ook de workflow gebruikt; de regel staat in het contract. `npm` wordt uit de verplichte tools van `checkToolRequirements` gehaald: een ontbrekende `npm` maakt de audit INCOMPLEET in plaats van hem af te breken, zodat het rapport de scanner kan noemen (SC-001). `git` blijft verplicht: zonder bron is er geen audit (edge case "source cannot be retrieved").

Scope-gebieden zonder aangesloten check (performance, reliability, observability, testing, CI/CD; review #9) komen in een aparte rapportregel "Niet gedekt door deze audit". Ze tellen niet mee in de uitkomst, omdat ze buiten de door deze feature uitgevoerde scanners vallen; ze worden ook niet als schoon getoond (FR-003).

**Alternatieven**: alle 13 domeinen verplicht (elke audit INCOMPLEET, de status verliest betekenis; aansluiten is #9, buiten scope); `skipped` nooit INCOMPLEET (verworpen: een Node-project zonder lockfile zou zonder dependency-audit als volledig gelden).

## R5 Scannerconfig uit de doelrepo neutraliseren (FR-014)

**Beslissing**: per tool het sterkste beschikbare middel, empirisch gecontroleerd:

| Sturing vanuit doelrepo | Waarneming | Neutralisatie |
|-------------------------|------------|---------------|
| `.gitleaks.toml` | `--config` heeft voorrang (gitleaks help, volgorde 1–4) | `--config config/scanners/gitleaks.toml` (`[extend] useDefault = true`) |
| `.gitleaksignore` | Wordt uit de bronmap geladen, **ook als `-i` elders heen wijst** (lek gesuppressed: exit 0 i.p.v. 42) | Verwijderen uit de wegwerp-werkkopie vóór elke scan; pad + sha256 in het `source.probe`-record |
| `gitleaks:allow` | `--ignore-gitleaks-allow` meldt de regel alsnog (2 i.p.v. 1 resultaat) | Vlag altijd aan; markers worden ook in de probe geteld |
| `.semgrepignore` | Wordt vanaf de git-root gehonoreerd (0 i.p.v. 1 resultaat), geen vlag om het uit te zetten; `--project-root` helpt niet | Verwijderen uit de werkkopie (alle diepten); vastleggen |
| `nosemgrep` / `nosem` | `--disable-nosem` meldt ze alsnog (2 i.p.v. 1) | Vlag altijd aan; markers geteld in de probe |
| `.npmrc`, `.yarnrc*` (registry, proxy, `strict-ssl`, `audit=false`) | Project-`.npmrc` wordt gelezen als cwd de repo is (#6, SSRF) | `npm audit` draait in `<WORK>/npm-audit/` met alleen `package.json` en de lockfile, plus `--userconfig` en `--globalconfig` naar twee **verschillende** lege framework-bestanden (één bestand voor beide geeft een npm-fout), `--registry https://registry.npmjs.org/`, `--ignore-scripts`, `--no-update-notifier`. Lokaal gecontroleerd: met een vijandige `.npmrc` (`registry=http://127.0.0.1:9/`, `audit=false`) in dezelfde map gaf de audit toch de 9 kwetsbaarheden. |
| `npx <tool>` in de repo | RCE (#1) | Geen `npx` op de doelrepo; licentiecheck wordt in-process (R14) |
| Omgevingsvariabelen van de worker | `NODE_OPTIONS`, `npm_config_*` sturen tools | Env-allowlist (`contracts/run-tool.ts`), `HOME`/`TMPDIR` naar de privé werkmap |

Elke gevonden poging komt als `OverrideAttempt` in het record van de stap die hem neutraliseert en in een rapportregel "Scanner-instellingen uit de bron genegeerd: …".

**Alternatieven**: de scan op een gefilterde kopie draaien (verworpen: dubbele schijfruimte, zelfde effect als verwijderen in de werkkopie, die al van ons is); poging alleen melden zonder te neutraliseren (voldoet niet aan "MUST NOT change scanner behavior").

**Restrisico**: nieuwe of onbekende sturingsbestanden van toekomstige toolversies. Mitigatie: de lijst staat in één module (`src/scan/source-probe.ts`) en de contracttests met echte tools (R16) bevatten een vijandige fixture per regel.

## R6 Semgrep-ruleset

**Beslissing** (gebruiker, 2026-10-02): geen `--config auto`. Semgrep draait met `--metrics=off` en vaste registry-packs `p/javascript` en `p/nodejs`, aangevuld met `--disable-nosem`, `--disable-version-check`, `--json`. Een eigen, versiebeheerde regelset vervangt de packs in een aparte vervolgfeature. Het gedeelde `/tmp/sql-injection-rules.yaml` (#16) vervalt; een framework-regelmap `config/scanners/semgrep/` wordt alleen meegegeven als die in de framework-repo bestaat. De gebruikte packs en de semgrep-versie staan in het record.

**Rationale**: `auto` vereist dat semgrep pseudonieme metrics naar semgrep.dev stuurt (met `--metrics off` weigert semgrep `auto`). Bij klantcode is dat niet verdedigbaar zonder toestemming (principe I, VIII). Gemeten op de demo met metrics uit en `EIO_BACKEND=posix` (kopie buiten de repo, 2026-10-02): `p/javascript` en `p/nodejs` vinden elk 4 resultaten (D09 op regel 15, D10 op regel 19, plus dubbele meldingen); `p/security-audit`, `p/secrets`, `p/command-injection` vinden 0; `p/owasp-top-ten` gelijk aan `p/javascript`. D11 (MD5) en D18 (generieke sleutel) vindt Semgrep zonder `auto` niet. D18 blijft gevonden door gitleaks.

**Gevolg voor recall (SC-003)**: baseline 6 van 18 (D03, D04, D09, D10, D11, D18). Verwacht na deze feature: D05, D06, D07 erbij door de npm-audit-fix, D11 eraf door het uitzetten van `auto`: 8 van 18, dus boven de baseline. Het verlies van D11 is een geaccepteerde afweging en wordt in de vervolgfeature met eigen regels hersteld.

**Correctie op eerdere meting**: de crash `semgrep-core exit code: 2` bij vaste packs (R3) was geen eigenschap van die packs maar van de omgeving: io_uring in `semgrep-core` op deze host. Met `EIO_BACKEND=posix` draaien alle packs met exit 0. `runTool` zet `EIO_BACKEND=posix` voor semgrep expliciet in de env-allowlist; de crashclassificatie (exit ≥ 2 zonder resultaten → `failed`) blijft nodig, want het niet-determinisme uit review #10 is hiermee verklaard maar niet uitgesloten.

**Alternatieven**: `--config auto` behouden (hogere recall, metrics naar derde partij: afgewezen); per opdracht configureerbaar (extra werk, later te overwegen); regels vendoren (juridische controle van de licentie van registryregels en onderhoud: de vervolgfeature).

## R7 Locaties: werkmap en evidence-bundel

**Beslissing**:
- **Werkmap** (vluchtig): `<os.tmpdir()>/tessera-<temporalRunId>`, aangemaakt met `mkdir` mode 0700, met `lstat`-controle (geen symlink, eigenaar = worker-uid, mode 0700) als hij al bestaat. Bevat de clone, de geïsoleerde npm-map, `home/`, `tmp/` en onbewerkte tooluitvoer. `cleanupRun` verwijdert hem in een `finally` van de workflow, op elk uitgangspad (principe VIII, #16).
- **Bundel** (blijvend): `<TESSERA_EVIDENCE_ROOT>/<workflowSlug>-<temporalRunId>/`, mode 0700, bestanden 0600 bij aanmaken. `workflowSlug` = `workflowId` met alles buiten `[A-Za-z0-9._-]` vervangen door `_`, maximaal 64 tekens. `TESSERA_EVIDENCE_ROOT` is verplicht in productie (`NODE_ENV=production` zonder waarde: worker start niet); daarbuiten standaard `~/.local/share/tessera/evidence` met een waarschuwing in de log dat dit geen bewaaropslag is.

**Rationale**: de Temporal-runId is een UUIDv4, dus net zo onvoorspelbaar als een `mkdtemp`-suffix, maar deterministisch per run. Daardoor is `initAuditRun` idempotent bij een retry (geen verweesde mappen) en vindt een herhaalde poging dezelfde map terug. `workflowId` alleen is niet uniek: de review toonde dat een id na afloop opnieuw gebruikt kan worden. Twee gelijktijdige audits hebben altijd verschillende runIds (FR-015).

**Alternatieven**: `mkdtemp` per aanroep (de opdracht noemde het; verworpen omdat een retry van `initAuditRun` dan een tweede map maakt en de eerste verweest); bundel onder `input.outputDir` (verworpen: client-gekozen pad op de worker-host; blijft alleen gebruikt voor het rapport, zoals nu).

**Aanname**: scans, seal en cleanup draaien op dezelfde host als de clone (zoals nu; één worker of gedeeld bestandssysteem). Multi-host-scheduling valt buiten deze feature.

## R8 Atomisch schrijven, onveranderlijkheid, idempotentie

**Beslissing**: record-id = `<stepId>.a<attempt>` (attempt uit `Context.current().info.attempt`). Publiceren: schrijven naar `records/.staging/<id>.json` (0600), `fsync`, `link()` naar `records/<id>.json`, staging verwijderen. `link()` faalt met `EEXIST` als het record al bestaat; de store geeft dan de hash van het bestaande record terug en overschrijft nooit. Artefacten idem met `wx`. Een poging die crasht vóór `link()` laat alleen een stagingbestand na; `sealEvidence` vermeldt dat als `abandoned` in het manifest. De workflow geeft de gebruikte record-ids mee aan `sealEvidence`; records van pogingen waarvan het resultaat niet gebruikt is, krijgen `used: false` maar blijven bewijs (FR-005: ook gefaalde stappen).

**Rationale**: dekt de edge case "run onderbroken en hervat": voltooide activities worden door Temporal niet opnieuw uitgevoerd, records worden nooit overschreven, en een herhaalde poging krijgt een eigen id.

**Alternatieven**: direct `wx` naar de eindnaam (een crash halverwege laat een half record achter dat als echt record oogt); `rename()` (overschrijft stil een bestaand doel).

## R9 Manifest, hashketen en verankering

**Beslissing**: `sealEvidence` sorteert alle bestanden onder `records/` en `artifacts/` op pad, kent `seq` toe en berekent `chainHash_i = sha256(chainHash_{i-1} + "\n" + seq + "\n" + path + "\n" + sha256)` vanaf `genesis = sha256("tessera:" + runId)`. `rootHash = chain.head`. Daarna `manifest.json` en `SHA256SUMS`, permissies naar 0400 (bestanden) en 0500 (mappen), en een zelfcontrole met `verifyEvidenceBundle`. De `rootHash` gaat terug naar de workflow, komt in `AuditResult`, in de Temporal-history en bovenaan het rapport.

**Rationale**: een manifest in dezelfde map bewijst alleen interne consistentie; wie de map bezit, kan alles herberekenen. Pas de vergelijking met een anker buiten de map (de root-hash in de history van de Temporal-server en in het afgeleverde rapport) maakt manipulatie aantoonbaar (US4, SC-004). De keten wordt bij het verzegelen berekend en niet bij het schrijven, omdat de vier scans parallel lopen; een schrijftijd-keten zou serialisatie over activities heen vereisen.

**Alternatieven**: schrijftijd-keten (verworpen, zie boven); Merkle-boom (geen voordeel bij tientallen bestanden); digitale handtekening met Ed25519 via Node `crypto` (geen nieuwe dependency, maar vereist sleutelbeheer: buiten deze feature, als vervolgstap genoteerd); RFC 3161-tijdstempel (externe dienst, buiten scope).

## R10 Fingerprint van ruwe versus opgeslagen uitvoer

**Beslissing**: per artefact twee hashes: `rawSha256` over de exacte bytes die de tool gaf, `sha256` over de opgeslagen, gesanitiseerde bytes. De verificatie gebruikt `sha256`.

**Rationale**: FR-006 vraagt een fingerprint van de ruwe uitvoer; FR-012 verbiedt secrets in evidence. Beide tegelijk kan alleen als de ruwe bytes niet bewaard worden maar wel hun hash. Wie de scan op dezelfde revisie en toolversie herhaalt, kan `rawSha256` vergelijken; de ontvanger van de map kan `sha256` controleren. Een sha256 over een volledige tooluitvoer onthult geen secret.

**Alternatief**: alleen de opgeslagen hash (dan is er geen bewijs over wat de tool werkelijk gaf); ruwe uitvoer versleuteld bewaren (sleutelbeheer, buiten scope).

## R11 Redactie (FR-012)

**Beslissing**: drie lagen, alle in `src/evidence/redact.ts` en de policies:
1. **Bronvermijding**: gitleaks met `--redact`; findings bevatten nooit broncode of gematchte tekst, alleen regel, bestand, regelnummer en een korte beschrijving. Dit raakt ook `reviewCriticalPaths`, dat nu `matches` (inclusief wachtwoorden) als `content` opslaat.
2. **Structurele whitelist per tool** in `sanitize`: gitleaks behoudt `RuleID, Description, File, StartLine, EndLine, Fingerprint`; semgrep `check_id, path, start, end, extra.message, extra.severity, extra.metadata`, plus `errors[].message` en `paths`; `extra.lines`, `extra.metavars` en `extra.fix` vallen weg. npm audit blijft volledig (bevat geen broncode).
3. **Patroonredactie** op alle vrije tekst die evidence, logs, foutmeldingen of het rapport bereikt (stderr, `causeDetail`, `message`, titels): AWS-sleutels (`AKIA`/`ASIA`), toewijzingen aan `secret|token|password|passwd|api[_-]?key`, PEM-blokken, JWT, GitHub- en Slack-tokens, `user:pass@` in URL's, en hex/base64 ≥ 32 tekens na een toewijzing. Vervanging: `[REDACTED:<type>]`.

Logs: pino krijgt `redact`-paden (`*.secret`, `*.Secret`, `*.Match`, `stdout`, `stderr`) en de regel dat tooluitvoer nooit gelogd wordt; alleen stap, status, oorzaak, aantallen en record-id. Temporal-history: activities geven alleen `ScanStepResult` terug (R12); foutmeldingen in `ApplicationFailure` gaan door laag 3.

**Rationale**: whitelisting maakt redactie onafhankelijk van het herkennen van elke secretvorm; patronen zijn het vangnet. Een gedeelde lijst van gevonden secretwaarden over activities heen is niet mogelijk zonder die waarden zelf op te slaan.

**Alternatieven**: alleen patronen (mist onbekende vormen); na afloop gitleaks over de bundel draaien als zelfcontrole (goede extra laag, maar herschrijven na detectie botst met onveranderlijkheid; als mogelijke vervolgstap genoteerd).

## R12 Wat de Temporal-history in gaat

**Beslissing**: activities retourneren `ScanStepResult` (status, gesanitiseerde findings met `evidenceRef`, record-ref), nooit ruwe uitvoer. `Evidence.content` in een finding wordt een korte samenvatting (≤ 500 tekens, bv. "npm advisory 1097678 (minimist, critical)") in plaats van de volledige JSON. Maximaal 2000 findings per stap in het resultaat; daarboven `partial/findings-truncated`, de volledige set staat in het artefact.

**Rationale**: FR-012 voor de history, en de payloadgrens van Temporal (standaard 2 MB per payload). 2000 × ~600 bytes ≈ 1,2 MB.

## R13 Bewaartermijn en onveranderlijkheid (FR-011)

Besloten door de gebruiker op 2026-10-02: FR-011 wordt in deze feature deels geleverd; WORM-opslag is een aparte operationele stap.

**Beslissing binnen deze feature**: append-only schrijven (R8), read-only permissies na verzegelen, `retainUntil = sealedAt + 365 dagen` in het manifest, geen enkel codepad dat onder `TESSERA_EVIDENCE_ROOT` verwijdert (`cleanupRun` weigert paden buiten `os.tmpdir()/tessera-*`, met test), en een verplichte `TESSERA_EVIDENCE_ROOT` in productie.

**Buiten deze feature** (expliciet, principe X): opslag-niveau-onveranderlijkheid (WORM, bv. object lock in compliance-modus, of `chattr +i`), back-up en het verwijderbeleid na de bewaartermijn. Permissies beschermen niet tegen root of de worker-gebruiker zelf; dat kan alleen de opslaglaag. Het rapport vermeldt: "Bewaring ≥ 1 jaar is een operationele verantwoordelijkheid van de beheerder van `<EVIDENCE_ROOT>`".

## R14 Licentiecheck zonder code van de doelrepo

**Beslissing**: `runLicenseCheck` leest `package-lock.json`/`npm-shrinkwrap.json` (lockfileVersion 2 of 3) in-process en beoordeelt het `license`-veld per pakket. De demo-lockfile (v3) bevat 53 `license`-velden. Lockfile v1 of ontbrekende velden → `partial` met het aantal pakketten zonder licentie-informatie. Bestanden worden met `lstat` geweigerd als ze symlinks zijn of groter dan 50 MB.

**Rationale**: verwijdert de bevestigde RCE (#1, `npx license-checker` in de repo) zonder nieuwe dependency en zonder `npm install`. `license-checker` las bovendien `node_modules`, dat in een verse clone niet bestaat, waardoor de check nu in de praktijk niets deed.

**Alternatieven**: `license-checker` als vastgepinde dependency van het framework met absoluut pad (nieuwe dependency, vereist nog steeds `node_modules` van de doelrepo); `npm install --ignore-scripts` vóór de check (netwerk, schijf, en nog steeds doelrepo-gestuurd via `.npmrc`).

## R15 Bronrevisie (FR-008)

**Beslissing**: `fetchSource` draait na de clone `git -C <repo> rev-parse HEAD` via `runTool` (eigen record `source.revision`), valideert het formaat (40 of 64 hex) en zet de revisie in `SourceRef`, in elk volgend record (`source.revision`) en in het manifest. Clone-argumenten: `git -c core.hooksPath=/dev/null clone --depth 1 --no-tags --single-branch -- <url> <WORK>/repo`.

## R16 Teststrategie en ground-truth-gate

**Beslissing**:
- **Unit** (hermetisch, nep-runner): policies per tool met opgenomen uitvoer (inclusief de waargenomen semgrep-crash, npm ENOLOCK en double-loading), `computeOutcome`, redactie, store, manifest, verify.
- **Integratie workflow** (hermetisch): de workflowfunctie draait met een gemockte `@temporalio/workflow` (`proxyActivities` levert nep-activities, `workflowInfo` een vaste runId). Zo worden de INCOMPLEET-paden, de bronfout en het verzegelen getest zonder Temporal-server en zonder nieuwe dependency.
- **Contract met echte tools** (`tests/contract/`, eigen config, niet in `npm run test:coverage`): per tool de vijandige fixtures uit R5 en de exitcodes uit R3. Ontbreekt een tool, dan wordt de test overgeslagen met vastgelegde oorzaak en eigenaar (principe II).
- **End-to-end ground truth**: `npm run demo` met Temporal en alle tools, als release-gate voor deze feature: D05, D06 en D07 gevonden, strikte recall ≥ 6/18, clean-app met uitkomst `complete`, `evidence:verify` op beide bundels geslaagd, en een zoekactie naar de geplante secretwaarden (D01–D04, D18) in bundel, rapport en worker-log zonder treffers (SC-005).

**Rationale**: principe II vraagt integratietests voor workflows; de bestaande "workflowtests" zijn tautologisch. Mocken van de workflow-module is de kleinste stap die echte orkestratielogica test.

**Alternatieven**: `@temporalio/testing` met time-skipping (nieuwe devDependency die bij de eerste run een testserver-binary downloadt; in de Alpine-CI-container onzeker; als vervolgstap genoteerd); de demo in CI (vereist een image met Temporal, gitleaks en semgrep plus netwerk; buiten scope, blijft lokale release-gate).

## R17 Migratie en achterwaartse compatibiliteit

**Beslissing**:
- `Finding` en `AuditResult` worden alleen uitgebreid (optionele velden); `evidencePath` behoudt zijn naam en wijst naar de bundel.
- De vier scan-activities en `reviewCriticalPaths` krijgen de signatuur `(run, source, …) → ScanStepResult`, elk in een eigen commit samen met de aanroep in de workflow. `cloneRepository` wordt vervangen door `initAuditRun` + `fetchSource`; `validateRepoUrl` blijft.
- Bestaande tests die de oude signaturen of het oude foutieve gedrag vastleggen (bv. "npm audit errors → 0 findings", tests die echte tools aanroepen) worden in dezelfde commit vervangen door de testify-tests van 004, per test genoteerd als "superseded by FR-xxx". Besloten door de gebruiker op 2026-10-02: vervangen en markeren, geen adapters.
- Workflow-codewijzigingen breken het replayen van lopende workflows. Uitrol: worker leeglopen (geen lopende audits) vóór de nieuwe versie; geen `patched()`-versionering, omdat er geen langlopende productie-audits zijn.

## R18 Tessl-tiles

Overgeslagen: geen nieuwe externe technologie. Alle bouwstenen zijn Node-ingebouwd (`crypto`, `fs`, `child_process`, `os`, `path`) of al aanwezig (Temporal SDK, pino, vitest). Geen nieuwe dependencies.

## R19 Handtekening van het manifest (FR-018, FR-019, FR-020)

**Beslissing** (gebruiker, 2026-10-02: lokale sleutel voor de eerste versie):
- Ed25519 via Node `crypto` (geen nieuwe dependency). `npm run evidence:keygen` maakt een sleutelpaar op `TESSERA_SIGNING_KEY` (standaard `~/.config/tessera/signing/ed25519.pem`, map 0700, bestand 0600) en exporteert de publieke sleutel met een `keyId` (sha256 van de SPKI-DER).
- De sleutel staat nooit onder `TESSERA_EVIDENCE_ROOT`: `sealEvidence` weigert te tekenen als het sleutelpad (na `realpath`) binnen de bundelroot ligt, en de sleutel komt niet in env-doorgifte naar scanners, logs, history of rapport.
- Ondertekende payload: `tessera-sig/v1\n<runId>\n<rootHash>\n<sha256(manifest.json)>\n<signedAt>`. `signature.json` in de bundel (0400) bevat `schema`, `alg`, `keyId`, `signedAt`, `signature` (base64) en de payload-velden. De handtekening wordt gezet nadat `manifest.json` is geschreven; de bundel wordt daarna verzegeld.
- Ontbrekende sleutel: de audit krijgt `signature: unsigned` en assurance-niveau 0. Met `TESSERA_REQUIRE_SIGNATURE=1` (verplicht in productie) wordt de uitkomst INCOMPLEET. Een handtekening mislukt nooit stil.
- Verificatie (`evidence:verify <bundel> --pubkey <bestand|map>`): `valid`, `invalid`, `unsigned`, `unknown-key`. Exit 0 alleen bij `valid` én schone hash-controle. `verified` verschijnt nooit bij `unsigned` of `unknown-key` (FR-019).
- `signedAt` is de klok van de ondertekenaar. Rapport en verificatie zeggen dat expliciet: "tijdstip niet onafhankelijk getijdstempeld".
- Assurance-niveau (FR-020) wordt berekend, niet ingevuld: 0 = geen geldige handtekening; 1 = geldige handtekening met lokale sleutel. Hogere niveaus staan in `docs/assurance-roadmap.md` en zijn niet in deze feature.
- Sleutelrotatie: `keyId` staat in elke handtekening; oude publieke sleutels blijven in de vertrouwde map staan om oude bundels te verifiëren.

**Rationale**: een manifest met alleen hashes kan door iedereen met schrijfrechten opnieuw worden berekend. Een handtekening bindt het bewijs aan een sleutel die de ontvanger kan controleren en maakt "manifest herberekenen" detecteerbaar (SC-007). Ed25519 is klein, snel en ingebouwd.

**Bekende beperking, bewust benoemd**: de sleutel staat op dezelfde host. Wie als de workergebruiker of root kan schrijven, kan ook de sleutel gebruiken en dus een geldige handtekening zetten. Dit is assurance-niveau 1. Sleutelbeheer buiten het beheerdomein (KMS of HSM, aparte ondertekenaar), onafhankelijke tijdstempel (RFC 3161), externe verankering en scanner-attestatie zijn niveau 2 en 3 in de roadmap. Aanbevolen al in v1: de sleutel onder een andere OS-gebruiker dan de worker laten staan en alleen de ondertekenstap laten aanroepen.

**Alternatieven**: handtekening achteraf door een aparte tool (extra stap, kans op vergeten); sigstore of KMS nu (infrastructuur en kosten, niet nodig voor niveau 1); GPG (externe binary en keyring-gedrag).

## R14 addendum (2026-10-03): packages without a license field

Decided during implementation: a package without a `license` field in the lockfile does not make the license check `partial`. The scan stays `completed`, and one summary P3 finding lists the count and the first names, and `causeDetail` repeats the count. Unknown is shown as a finding, not as clean. A lockfileVersion 1 file has no license fields and gives `partial/unsupported-lockfile`; an unknown lockfileVersion gives `failed/unsupported-lockfile`. Reason: marking every audit incomplete over a few unlabeled packages would make the outcome rule meaningless.

## Implementation addendum (2026-10-03): bundle location, seal coverage, permissions

- **Bundle folder**: one bundle per run at `<TESSERA_EVIDENCE_ROOT>/<temporalRunId>` (not `<workflowSlug>-<temporalRunId>` as R7 describes). Reason: source evidence and scan evidence must live in one folder with one run id; the slug added nothing but a second naming rule. The workflow id is recorded in the manifest.
- **What the root hash covers**: only `seq`, `path` and `sha256` of each entry feed the hash chain. The manifest fields `used`, `kind`, `recordId`, `source` and `sealedAt` are not covered by the root hash and can be altered undetected until the signature over the manifest bytes (US6, FR-018) exists. The report therefore says `Integrity: hashes only; the manifest is not signed`.
- **Permissions**: the bundle folder is 0500 and `manifest.json` 0400 after sealing; `records/` and `artifacts/` stay 0700 because test teardown needs to remove them. Files in them are 0400. Verification reports any extra file. This is weaker than R9; the storage-level fix belongs to roadmap item 010.
- **Seal on retry**: sealing an already sealed bundle verifies and returns the existing result (idempotent), it never rewrites the manifest.

## R5 addendum (2026-10-03): neutralize by renaming, names match case-insensitively

- **Rename, not delete.** Steering files found in the audited source (`.gitleaks.toml`, `gitleaks.toml`, `.gitleaksignore`, `.semgrepignore`, `.semgrep.yml`, `.semgrep.yaml`, `.semgrep/`, `.npmrc`, `.nsprc`, `.snyk`, `.yarnrc`, `.yarnrc.yml`) are renamed in the private working copy to `<name>.tessera-neutralized` instead of being removed. Reason: deleting would also hide their content from gitleaks, so a secret hidden inside a `.gitleaksignore` would never be found. A contract test with the real gitleaks proves the rename catches it. The evidence record keeps `neutralizedBy: removed-from-working-copy` and names the new file in `detail`.
- **Names match case-insensitively** (case-insensitive filesystems). `.npmrc` and `.yarnrc*` are hashed and recorded as `isolated-working-dir` (npm audit already runs in an isolated directory).
- **Proof that steering works without the probe**: the contract tests first show that a hostile `.gitleaksignore` and `.semgrepignore` suppress the finding when the probe is switched off, and that it is reported again with the probe.
- **Known limit**: with the source's own `.semgrepignore` neutralized, semgrep falls back to its built-in default ignore list, which skips `tests/` directories. Code under `tests/` is therefore not scanned by semgrep. That is ruleset policy (R6), not steering by the source, but it is a recall gap to decide on in the own-ruleset feature (roadmap 005).
- **Fail closed**: if the probe itself fails, no scan runs on an unprobed source; the fetch stops with a non-retryable failure and a failed record.

