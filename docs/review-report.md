# Reviewrapport Tessera (voorheen audit-flow)

Datum: 2026-10-02. Basis: `main` op `9827a23` plus de demo-commits `20aad99`, `345e3f8`, `daf45af`.
Reviewer: Claude (Sonnet 5.5), met Opus-subagent voor de securityanalyse. Bewijs en ruwe logs: scratchpad van de sessie (`fase1-checks.md`, `fase1-ci.md`, `fase3-security.md`, `fase34-static.md`, `fase2-scenarios.log`, `demo-run3.log`).
Label: **B** = bevestigd met bewijs, **V** = vermoedelijk.

## 1. Oordeel

**No-go voor "Production Ready".** Het systeem draait end-to-end (Temporal, worker, 4 scanners, P0-goedkeuring, rapport), maar het is geen betrouwbaar auditsysteem.

- Op de demo vindt het 6 van 18 geplante defecten (strikt gescoord), 3 met de juiste ernst. De drie CVE's, SQL-injectie en PII in logs ontbreken.
- Een ontbrekende of crashende scanner levert stil 0 bevindingen op en het rapport toont geen waarschuwing (`Risk Level: CRITICAL` bleef staan door een regex-bevinding, zonder vermelding van de ontbrekende tools).
- Een scan kan code van de doelrepo uitvoeren (RCE bevestigd) en workflowId/repoPath lopen onge-escaped door ~25 shell-strings.
- De kwaliteitsgates zijn deels schijn: de coverage-drempel wordt niet afgedwongen, BDD draait 0 scenario's, meerdere CI-stappen zijn `echo`.
- De pipeline op `main` was rood vanaf #16 (Sonar-gate) en is sinds #24 groen doordat Sonar en SAST non-blocking zijn gemaakt, niet doordat de oorzaken zijn opgelost.
- De statusdocumenten spreken de werkelijkheid en elkaar tegen.

De architectuur (Temporal, signalen, queries, vaste rapportstructuur) is een goede basis. Zie §7 en §8.

## 2. Functionele runresultaten

### 2.1 Demo `vulnerable-app` (grondwaarheid `demo/EXPECTED.md`)

Run: `npm run demo` (schone run na het stoppen van een oude worker), `demo-run3.log`. Strikte scoring: de runner gaf 7/18, maar D02 kreeg onterecht crediet via de generieke gitleaks-bevinding van D18. Hieronder de strikte lezing.

| ID | Defect | Gevonden | Ernst verwacht → gerapporteerd | Opmerking |
|----|--------|----------|--------------------------------|-----------|
| D01 | AWS access key (voorbeeld) | nee | P0 → - | gitleaks negeert het officiële voorbeeld bewust (B, lokaal gereproduceerd) |
| D02 | AWS secret key (voorbeeld) | nee | P0 → - | runner telde D18-bevinding mee; strikt gemist |
| D03 | Hardcoded wachtwoord | ja | P1 → P0, P1 | code-review-regex |
| D04 | Hardcoded signeergeheim | ja | P1 → P0 | ernst te hoog |
| D05 | lodash 4.17.15 CVE's | nee | P1 → - | `runNpmAudit` gooit uitkomst weg (S4) |
| D06 | minimist 1.2.0 (kritiek) | nee | P0 → - | idem |
| D07 | express 4.17.1 transitief | nee | P1 → - | idem |
| D08 | SQL-injectie | nee | P0 → - | geen enkele detector; Semgrep-regel `code-string-concat` gaat over `eval` |
| D09 | Reflected XSS | ja | P1 → P1 | Semgrep, 3 bevindingen (duplicaten) |
| D10 | `eval` op invoer | ja | P0 → P0, P1 | Semgrep |
| D11 | MD5 voor wachtwoorden | ja | P2 → P1 | ernst te hoog |
| D12 | Prototype pollution `_.merge` | nee | P2 → - | |
| D13 | PII in logregel | nee | P1 → - | `checkPrivacy` zit niet in de workflow |
| D14 | Geen README | nee | P3 → - | `checkDocumentation` zit niet in de workflow |
| D15 | Geen CI-config | nee | P3 → - | `checkCicd` zit niet in de workflow |
| D16 | Geen tests | nee | P2 → - | niet in de workflow |
| D17 | Geen foutafhandeling/health | nee | P3 → - | `checkReliability` zit niet in de workflow |
| D18 | Interne API-sleutel (verzonnen) | ja | P1 → P0, P0 | gitleaks + Semgrep |

**Recall (strikt): 6/18 = 33%. Juiste ernst: 3/18 = 17%.** Alle 11 bevindingen zijn op één na herleidbaar tot een geplant defect.

### 2.2 Demo `clean-app`

1 bevinding: Semgrep `express-check-csurf-middleware-usage` (P2). De app gebruikt geen cookies of sessies, dus dit is een vals-positief. **Precisie op de schone repo: 0 van 1 correct (1 vals-positief).**

### 2.3 Overige runs

| Run | Resultaat |
|-----|-----------|
| `scripts/test-audit-run.ts` (zonder Temporal) | Exit 0, 3 bevindingen (alle secrets), 0 npm-vulnerabilities, 0 code- en licentiebevindingen. Draait op vaste fixtures, niet op een echte repo. |
| Temporal-route `npm run demo` | Beide audits voltooid. |

### 2.4 Faalscenario's (`fase2-scenarios.log`)

| Scenario | Resultaat |
|----------|-----------|
| P0-goedkeuring: goedkeuren | Werkt: workflow bereikt `awaiting-approval`, na signaal rapport (B). |
| P0-goedkeuring: afwijzen (`false`) | **Genegeerd.** Na 25 s nog `awaiting-approval`; de workflow wacht tot de timeout (B). |
| P0-timeout (7 dagen) | Niet getest: dev-server heeft geen time-skipping. Code: `condition(..., 7d)` → fout, geen rapport, geen cleanup (V). |
| Kwaadaardige URL's direct in workflow (`;id`, `file://`, `--upload-pack=`, `ext::`) | Allemaal afgewezen (Activity task failed). De foutsoort komt niet terug in het clientresultaat; alleen via de history (B). |
| Niet-bestaande repo | Faalt (Activity task failed), geen retry-voordeel; geen `GIT_TERMINAL_PROMPT=0` (B/V). |
| Twee audits tegelijk | Geen botsing: verschillende paden en state (B). |
| Herhaald workflow-id | Tijdens lopen `WorkflowExecutionAlreadyStarted`; na afronding wordt een tweede run met hetzelfde id toegestaan (B). |
| Worker midden in audit gekilld | Na herstart van de worker niet hersteld binnen 400 s: er zijn geen heartbeats en `startToClose` is 1 uur, dus Temporal wacht tot de activity afloopt (B voor gedrag, V voor oorzaak). |
| Ontbrekende tools (gitleaks en semgrep uit PATH) | Audit slaagt met 2 bevindingen, geen vermelding van ontbrekende tools in het rapport (B). |
| Semgrep faalde in een run | `semgrep encountered issues`: exit ≠ 0 terwijl `semgrep-report.json` (30 KB) is geschreven; de activity gooit het resultaat weg. Dezelfde audit gaf in de demo-run wél 11 bevindingen: niet-deterministisch (B voor feit, V voor oorzaak). |
| Activity-timeout en retry | Niet getest zonder code te wijzigen; code-analyse: scans slikken alle fouten, dus het retrybeleid wordt nooit geraakt (B). |

Observability: pino-logs zijn bruikbaar (137 regels in één worker-run, geen secrets in de log). De Temporal-history bevat wel secrets in klare tekst (S7). Semgrep-evidence heeft als `content` de tekst `requires login` in plaats van een codefragment (B, `demo/last-run.json`). `/tmp/audit-<id>/` wordt na een run niet volledig opgeruimd (8 mappen bleven staan).

## 3. Bevindingen

| # | Ernst | Dimensie | Bevinding | Bestand:regel | Bewijs | Fix | Inspanning |
|---|-------|----------|-----------|---------------|--------|-----|-----------|
| 1 | Kritiek | Security | RCE via doelrepo: `cd <repo> && npx license-checker` voert een meegecommitte tool uit; `npx eslint` en `npx tsc` hebben hetzelfde latente patroon | activities/index.ts:538, 1703, 1763 | `pwned-npx.txt` = "RCE via repo-local license-checker" (B) | Tools vooraf installeren, absoluut pad, sandbox | M/L |
| 2 | Kritiek | Security | Shell-injectie via `workflowId` en `repoPath` in ~25 `exec`-template-strings | activities/index.ts:31 e.a. | `uid=1000` in output bij payload `x;id>…;#` (B) | `execFile` met array-args, id valideren | M |
| 3 | Kritiek | Security | Temporal 7233/8233 op alle interfaces zonder auth | docker-compose.yml:7-8, 37-38 | Config (B), exploit extern (V) | Binden op 127.0.0.1, mTLS | S/M |
| 4 | Hoog | Correctheid | `npm audit` exit 1 → catch → `[]`: 0 bevindingen bij kwetsbaarheden | activities/index.ts:332-387 | Demo: 9 CVE's, 0 gerapporteerd (B) | `error.stdout` parsen | S |
| 5 | Hoog | Betrouwbaarheid | Ontbrekende/crashende scanner → 0 bevindingen, rapport zonder waarschuwing | activities/index.ts:46-47 | Scenario S9 en E4/E5 (B) | Status per scanner, rapport "INCOMPLEET" | M |
| 6 | Hoog | Security | Doelrepo stuurt scanners aan (`.gitleaks.toml`-allowlist, `.npmrc` met eigen registry → SSRF) | scanactiviteiten | Findings 1→0; luisterpoort ving `/-/npm/v1/security/advisories/bulk` (B) | Eigen config forceren, `--ignore-scripts` | S/M |
| 7 | Hoog | Security | Secrets in klare tekst in Temporal-history, evidence-JSON en gitleaks-rapport (0644) | activities/index.ts:431 | Bestanden gelezen (B) | `--redact`, 0600, geen secret in output | S/M |
| 8 | Hoog | Betrouwbaarheid | Worker-kill: geen heartbeats, 1 uur timeout; herstel binnen 400 s uitgebleven | workflows/index.ts:38-46 | Scenario S8 (B/V) | Heartbeats, korte `startToClose`, `heartbeatTimeout` | M |
| 9 | Hoog | Functioneel | De workflow gebruikt 9 van 32 activities; privacy, documentatie, CI, reliability en 15 andere zijn dode code | workflows/index.ts:25-37 | Demo D13–D17 niet gevonden (B) | Domeinen aansluiten of claim schrappen | L |
| 10 | Hoog | Correctheid | Semgrep: exit ≠ 0 met geschreven rapport wordt weggegooid; niet-deterministisch | activities/index.ts (runSemgrep) | Scenario S1: 3 vs 11 bevindingen (B/V) | Exitcode 1 als "bevindingen" behandelen, rapport altijd parsen | S |
| 11 | Hoog | Governance | Coverage-drempel dode config (`threshold` i.p.v. `thresholds`): `verify` groen bij 71,4%/43,5% | vitest.config.ts:10 | Kopie-config met `thresholds` geeft exit 1 (B) | Sleutel corrigeren, drempel realistisch | S |
| 12 | Hoog | Testen | BDD actief in naam: `test:bdd` draait 0 scenario's, stepdefinities in `specs/` worden niet geladen, deels tautologisch | .cucumber.js:3 | "0 scenarios, 0 steps" (B) | Pad corrigeren, tautologische stappen herschrijven, in CI | M |
| 13 | Hoog | CI | Pipeline rood #16–#22 op Sonar-gate; groen in #24 alleen doordat Sonar en SAST non-blocking zijn gemaakt (commits `ecbdb69`, `62ed87d`) | .woodpecker.yml | #21 `sonarqube` exit 3, rest skipped; #24 success (B) | Gates terugzetten op blocking nadat coverage en SAST-bevindingen zijn opgelost | M |
| 14 | Middel | Governance | Test leeggemaakt en geskipt: `should clone repository successfully` zonder body of asserts, commit zegt het niet | tests/… (zie §4), commit 9827a23 | `git log -p` (B) | Testen herstellen | S |
| 15 | Middel | Security | Reject-signaal genegeerd; `skipApproval` niet in rapport; elke client kan het zetten | workflows/index.ts:152-160, client.ts:71 | Scenario S2 (B) | Reject-handler, rapportvermelding | S |
| 16 | Middel | Security | Voorspelbare paden `/tmp/audit-<id>` en gedeeld `/tmp/sql-injection-rules.yaml`; cleanup alleen op succespad | activities/index.ts:130, 469, 1135 | Code (B), exploit (V) | `mkdtemp` 0700, cleanup in `finally` | S |
| 17 | Middel | Betrouwbaarheid | Clone zonder timeout en `GIT_TERMINAL_PROMPT=0`; alle clone-fouten non-retryable | activities/index.ts:136-155 | Code (B) | Timeout, onderscheid netwerk/invoer | M |
| 18 | Middel | Correctheid | `measureThroughput`: `parseInt('5m')` = 5; `checkBlindSpots` busfactor altijd 1; `checkCodeQuality` maakt nooit lint-finding; `assessStability` omgekeerde logica | activities/index.ts:2500, 2229, 1673-1755, 2603 | Code (B) | Per functie corrigeren + test | M |
| 19 | Middel | Eerlijkheid | `crossValidate` is placeholder met "Automated review completed"; `mapToCompliance` altijd 0%; geen enkele LLM-aanroep | activities/index.ts:745, mapToCompliance | Code (B) | Implementeren of uit rapport halen | M/L |
| 20 | Middel | Onderhoud | Monoliet van 2920 regels, ~35× kopie van het finding-literal, `as any` 11× | activities/index.ts | `wc -l`, tellingen (B) | Splitsen per domein, helper | L |
| 21 | Middel | Config | `TEMPORAL_ADDRESS`, `ALLOWED_ORGS`, `GITHUB_TOKEN` worden nergens toegepast | config.ts, worker.ts | Worker negeert `TEMPORAL_ADDRESS` (B) | Doorvoeren of verwijderen | S |
| 22 | Middel | Evidence | Evidence zonder commando, toolversie, repo-SHA, hash en scannerstatus; Semgrep-evidence = "requires login" | activities/index.ts:2402 | `demo/last-run.json` (B) | `EvidenceRecord` per stap, manifest | M |
| 23 | Middel | Installeerbaarheid | `npm ci` faalt lokaal (ERESOLVE vitest 5 ↔ `@types/node` ^20), CI gebruikt `--legacy-peer-deps` | package.json, .woodpecker.yml:14 | Exit 1 (B) | `@types/node` ^22 | S |
| 24 | Middel | Overdraagbaarheid | Dockerfile: root, geen healthcheck, `:latest`/niet-gepinde basis, `--only=production` gevolgd door `tsc` | Dockerfile | Statisch (B/V) | USER, pin, multi-stage | S |
| 25 | Middel | CI | `coverage-check` en `nfr-*` zijn `echo`; `failure: ignore` op dependency-audit en 3 NFR-stappen; images `:latest` | .woodpecker.yml:59, 77-80, 88-109 | Statisch (B) | Echte checks, pinnen | M |
| 26 | Laag | Test | `measureThroughput`-test faalt zodra k6 geïnstalleerd is (omgevingsafhankelijk) | tests/unit/new-nfr-activities.test.ts | Gereproduceerd (B) | k6 mocken | S |
| 27 | Laag | Doc | `.gitleaksignore` gebruikt regelnummer-fingerprints die bij elke edit breken; entries zelf zijn legitieme fixtures | .gitleaksignore | 4 entries gecontroleerd (B) | Padgebaseerde allowlist | S |
| 28 | Laag | Governance | Specs 001–003 niet in `.spec.md`-formaat (geen frontmatter, 0 `[@test]`), geen assertion-hashes, IIKit-pre-commit niet geïnstalleerd | specs/, .specify/context.json | Statisch (B) | `/iikit-04-testify` | M |

## 4. Overgeslagen tests

23 skips (11 `it.skip`, 10 tests in 4 `describe.skip`, 2 `skipIf(!TEST_URL)`). Gedraaid in een kopie in de scratchpad: 14 van de 71 geskipte/aanverwante tests falen, 57 slagen.

| Test | Gemelde reden | Echte oorzaak | Advies |
|------|---------------|---------------|--------|
| `generateReport`, `generateScopeDocument` (activities-p1.test.ts:117, 202) | mock infrastructure | **Testprobleem**: verkeerde signatuur/input (B) | Test corrigeren, skip weghalen |
| `runLicenseCheck` GPL-test | idem | Vermoedelijk **productiebug**: schrijft naar niet-bestaande `/tmp/audit-*/licenses.json` (V) | Onderzoeken, pad aanmaken |
| `cloneRepository` success (9827a23) | "ensure all test skips are committed" | Body en asserts verwijderd, lege skip (B) | Terugzetten, spawn injecteerbaar maken |
| `cloneRepository` failure, `runNpmAudit`, semgrep, timeouts | mock timeout | Testbaarheid/infra (spawn niet injecteerbaar) (B) | Dependency-injectie of integratietest met fixture |
| `describe.skip` (4×) in activities-p1 | vanaf 23e33b0 skip | Zie boven | Per blok herstellen |
| `new-domains.test.ts:22,40` (Lighthouse/axe, `TEST_URL`) | geen URL | Omgeving | Lokale fixture-site in CI |

Verzwakking van assertions: bevestigd voor `cloneRepository` (9827a23). Andere commits verwijderen geen `expect`-regels; nieuwe tests zijn zwak (`toBeDefined`, `Array.isArray`). Dit botst met de assertion-integrity-regels.

## 5. NFR-matrix (ISO 25010)

7 van 17 subkenmerken hebben code, 0 hebben CI-bewijs. De README-lijst is geen ISO 25010 (Durability, Robustness, Resilience, Exploitability zijn geen subkenmerken).

| Kenmerk | Geclaimd | In code | Aangetoond (demo/CI) | Gat |
|---------|----------|---------|----------------------|-----|
| Functional suitability | ja | gedeeltelijk (9/32 activities in workflow) | Demo: recall 33% | Aansluiten, recall verhogen |
| Performance efficiency | ja | Lighthouse/k6-activities, niet in workflow | Nee; CI-stappen zijn `echo` | Echte meting, tijden per activity |
| Compatibility | planned | nee | nee | Co-existence niet gemeten |
| Interaction capability / usability | ja | axe-activity, niet in workflow | Nee | Rapporttoegankelijkheid niet getoetst |
| Reliability | ja | regexchecks, niet in workflow | Scenario S8 faalt | Heartbeats, herstel, retry |
| Security | ja | scanners | Demo: SQL, CVE's gemist; 3 kritieke eigen kwetsbaarheden | #1–#7 |
| Maintainability | ja | monoliet 2920 regels | Nee | Splitsen |
| Portability | planned | Dockerfile/compose | Niet gebouwd (statisch beoordeeld) | #24 |
| Safety | ja | heuristisch | Nee | n.v.t. voor dit domein |

## 6. Claim versus realiteit

| Claim | Bron | Oordeel |
|-------|------|---------|
| "Production Ready" | README, STATUS.md | **Weerlegd** |
| "171 tests passing" | README:149, STATUS:15,103, COVERAGE:7, ENTERPRISE:93,159 | **Weerlegd**: 228 geslaagd, 23 overgeslagen (251) |
| "17 test files" | idem | **Weerlegd**: 21 |
| "64% coverage" | README:150, STATUS:104, COVERAGE:5 | **Weerlegd**: 71,4% statements, 43,5% branches |
| Coverage-drempel 65% / 80% afgedwongen | README:266, STATUS:117, ENTERPRISE:156,164, vitest.config | **Weerlegd**: dode config, niet afgedwongen |
| "Alle 14 domeinen actief" | README | **Weerlegd**: 13 domeinen, 56 checks, 20 geïmplementeerd (36%) |
| "19 activities" | opdracht, README (20), STATUS (21) | **Weerlegd**: 32 geëxporteerd |
| "4 .feature-bestanden", "BDD active" | ENTERPRISE:159 | **Weerlegd**: 3 bestanden, 22 scenario's, 0 draaien |
| "Implements ISO 25010" | README | **Weerlegd** (zie §5) |
| "95% enterprise score" | review-instructie | **Niet gevonden** in de 5 docs; AUDIT-COVERAGE zegt 88% |
| "Dependency-audit blocking" | ENTERPRISE | **Weerlegd**: `failure: ignore` |
| CI groen op `main` | STATUS | **Weerlegd** voor #16–#22; #24 groen met verzachte gates |
| `npm run verify` dekt CI | hooks | **Weerlegd**: mist BDD, audit, license, gitleaks, Sonar, semgrep |
| Pad `temporal-security-audit-framework` | STATUS.md:4, README | **Weerlegd**: verkeerd pad |

Dubbel bijhouden is schuld: README, STATUS.md, ENTERPRISE-STATUS.md, COVERAGE.md en AUDIT-COVERAGE.md bevatten tegenstrijdige getallen.

## 7. Wat is goed

- Temporal-architectuur: workflow, signalen (`p0-approval`), queries (`status`, `findings`, `state`) werken in de run.
- `validateRepoUrl` is solide: newline, `--upload-pack`, `ext::`, `file://`, lokale paden, ssh, userinfo en `..` zijn afgewezen; `spawn` met array-args bij de clone.
- Hooks en CI delen één basis (`npm run verify`), en de hooks draaien (`core.hooksPath=.githooks`).
- Geen secrets in de git-historie (gitleaks, 32 commits) en geen secrets in de pino-logs.
- Parallelle audits botsen niet; een lopend workflow-id wordt geweigerd.
- Gitleaks en Semgrep vonden de meeste code-defecten die ze behoren te zien (XSS, `eval`, MD5, generieke API-sleutel).

## 8. Herstelvolgorde

Kleine atomaire trunk-commits, elke met `npm run verify` en de demo als verificatie.

1. `fix(security): replace exec with execFile and drop npx on target repos` (#1, #2). Verificatie: payloadtests uit de securityreview slagen niet meer.
2. `fix(scan): parse npm audit stdout on non-zero exit` (#4). Verificatie: demo D05–D07 verschijnen.
3. `fix(scan): treat scanner exit codes correctly and report scanner status` (#5, #10). Verificatie: scenario S9 toont "INCOMPLEET".
4. `fix(test): coverage thresholds key and realistic gate` (#11, #23). Verificatie: `verify` faalt zolang coverage onder de drempel zit.
5. `fix(infra): bind Temporal to localhost` (#3).
6. `fix(workflow): handle reject signal and report skipApproval` (#15).
7. `fix(workflow): heartbeats and shorter startToClose` (#8, #17).
8. `test: restore skipped tests and activate BDD` (#12, #14, #26).
9. `feat(scan): wire privacy, docs, CI, reliability checks into the workflow` (#9). Verificatie: demo D13–D17.
10. `feat(evidence): per-step evidence records with manifest` (#22).
11. `docs: single status source, correct counts` (§6).
12. `ci: restore Sonar gate, pin images, real NFR steps` (#13, #25).

## 9. Open vragen voor een menselijke beslissing

1. Wordt het systeem bedoeld voor het scannen van niet-vertrouwde repo's (dan is sandboxing verplicht) of alleen eigen repo's?
2. Moeten de 13 domeinen allemaal in de workflow, of wordt de scope teruggebracht tot wat bewezen werkt?
3. Is GenAI-review beoogd (nu geen enkele aanroep)? Zo ja, welk model en welke dataregels?
4. Welke coverage-drempel is realistisch na de herstelronde (nu 71,4%/43,5% tegen 80%/60%)?
5. Mag de Sonar-gate tijdelijk versoepeld worden of moet eerst de coverage omhoog?

## Bijlage: afwijkingen en beperkingen van deze review

- **Demo-aanpassingen vóór de eerste auditrun:** D18 (verzonnen API-sleutel) toegevoegd omdat gitleaks de AWS-voorbeeldsleutel negeert.
- **Na de eerste proefrun:** `category`-filter toegevoegd aan D05–D07 en D13–D17 omdat de tekstmatch onterecht crediet gaf. Dat maakt de scoring strenger; defecten en verwachte ernst zijn niet gewijzigd. Daarnaast bleek D02 achteraf onterecht gecrediteerd (runner 7/18, strikt 6/18); `EXPECTED.md` en runner zijn niet aangepast om dat te verbergen.
- **Demo en cloning:** `validateRepoUrl` accepteert alleen `https://github.com/owner/repo`, dus de demo gebruikt `url.<base>.insteadOf` via `GIT_CONFIG_*`. De getoetste clone-route is daarmee dezelfde code, maar het netwerkpad (echte GitHub) is alleen in S5 gedekt.
- **Verstoring:** een oude worker (PID 750512, draaide sinds de dag ervoor) pakte taken van de eerste demo-runs af. Met toestemming gestopt; daarna draaide de schone run (`demo-run3.log`). Alleen die run en de scenario-run zijn gebruikt.
- **Tools:** `temporal` en `k6` waren afwezig en zijn zonder sudo in `~/.local` geïnstalleerd (k6 buiten de standaard-PATH, omdat `measureThroughput` anders `verify` breekt). gitleaks, semgrep, lighthouse, axe, node en docker waren aanwezig. Geen Lighthouse-, axe- of k6-run tegen de demo: er is geen draaiende demosite.
- **CI na de demo-commits:** #21 (`daf45af`) faalde op `sonarqube` (exit 3), net als #16–#20. Daarna zijn buiten deze review om twee commits op `main` gekomen (`ecbdb69` "make SonarQube non-blocking", `62ed87d` "make SAST non-blocking and exclude demo directory"). Pipeline #24 (`62ed87d`) is daardoor **groen, maar doordat gates zijn verzacht, niet doordat de oorzaken zijn opgelost**: de Sonar-gate faalt nog steeds op coverage en SAST blokkeert niet meer. #23 (mijn rapportcommit) is `killed` (vervangen door #24). Eigen fout: ik sloot `demo/` uit van gitleaks en vitest maar niet van Semgrep; de SAST-stap vond 5 bevindingen in `demo/` (de bewust geplante defecten), wat de sast-stap liet falen. De uitsluiting is door de latere commit toegevoegd. Mijn eigen uitsluitingen voor gitleaks zijn lokaal geverifieerd; in CI draait `secrets-scan` pas sinds #24 weer.
- **Niet uitgevoerd:** P0-timeout (7 dagen), activity-timeout/retry zonder codewijziging, docker build en `docker compose up`.
