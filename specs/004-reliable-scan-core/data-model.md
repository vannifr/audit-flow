# Datamodel: Reliable Scan Core

**Feature**: 004-reliable-scan-core | **Datum**: 2026-10-02
Typen staan in `contracts/`; dit document beschrijft velden, relaties, validatie en toestandsovergangen. Alle tijden zijn ISO-8601 in UTC; alle hashes zijn sha256 in kleine hex (64 tekens).

## Relaties

```
AuditRun 1 ──── 1 EvidenceManifest
   │                  │ lists
   │ 1..*             ▼
   ├──── ScannerStatus 1 ──── 1..* EvidenceRecord ──── 0..2 Artifact (output, stderr)
   │                                  ▲
   │ 0..*                             │ evidenceRef (recordId + recordSha256 + locator)
   └──── Finding ─────────────────────┘
```

---

## AuditRun

Eén uitvoering van `applicationAudit` tegen één bronrevisie. Bestaat in de workflowtoestand (`AuditState`), in `AuditResult` en, via `runId`, in elk record en het manifest.

| Veld | Type | Validatie |
|------|------|-----------|
| runId | string | `${workflowId}/${temporalRunId}`; uniek per uitvoering |
| workflowId | string | 1–255 tekens; wordt alleen als slug in paden gebruikt |
| temporalRunId | string | UUID |
| repoUrl | string | `validateRepoUrl` (bestaand; geen userinfo) |
| revision | string \| null | 40 of 64 hex; null alleen als de bron niet opgehaald kon worden |
| workDir | string | `<tmp>/tessera-<temporalRunId>`, mode 0700, geen symlink |
| bundleDir | string | `<EVIDENCE_ROOT>/<slug>-<temporalRunId>`, mode 0700 → 0500 na verzegelen |
| outcome | `complete` \| `incomplete` | volgens `computeOutcome` |
| notPerformed | NotPerformed[] | leeg ⇔ outcome = complete |
| scanners | ScannerStatusEntry[] | precies één entry per ScannerId |
| rootHash | string \| null | gelijk aan `manifest.rootHash` |

**Toestandsovergangen** (bestaande `currentPhase` blijft; `run` is de nieuwe, orthogonale toestand):

```
initialized ──fetchSource ok──▶ source-fetched ──scans settled──▶ scanned ──seal ok──▶ sealed ──report ok──▶ reported
     │                              
     └──fetchSource failed──▶ source-failed ──seal ok──▶ sealed-failed   (geen rapport; workflow faalt met SourceUnavailableError, outcome incomplete)
elke toestand ──finally──▶ workDir verwijderd (cleanupRun)
```

- `initialized`: werkmap en bundel bestaan; nog geen records behalve eventueel `run.init`.
- `scanned`: elke scan heeft een terminale status (ook als de activity zelf faalde: de workflow zet dan `failed/activity-failed`).
- `sealed`: manifest geschreven en zelf geverifieerd; daarna wordt er niets meer aan de bundel toegevoegd.
- Een run gaat nooit terug naar een eerdere toestand; een hervatting na een crash gaat verder vanaf de laatste voltooide activity.

## ScannerStatus (`ScannerStatusEntry`)

| Veld | Type | Validatie |
|------|------|-----------|
| scanner | ScannerId | `npm-audit`, `gitleaks`, `semgrep`, `license-check`, `code-review` |
| required | boolean | volgens toepasbaarheidstabel (research R4) |
| status | ScannerStatusValue | `completed`, `partial`, `failed`, `skipped`, `unavailable` |
| cause | StatusCause? | verplicht als status ≠ completed; `issues-found` alleen bij completed |
| causeDetail | string? | geredigeerd, ≤ 500 tekens |
| heuristic | boolean | true alleen voor `code-review` |
| toolVersion | string \| null | null bij unavailable of in-process zonder versie |
| findingCount | number | ≥ 0; 0 verplicht bij failed/unavailable/skipped |
| evidenceRecordIds | string[] | ≥ 1 als de stap is uitgevoerd; leeg alleen bij `skipped/not-applicable` vóór uitvoering |

**Toestandsovergangen** (per scanner, per run):

```
pending ──spawn ENOENT──────────────▶ unavailable
pending ──niet toepasbaar / geen lockfile──▶ skipped
pending ──running──┬─ exit volgens beleid ok ──────────────▶ completed
                   ├─ tool meldt fouten, wel resultaten / afgekapt ──▶ partial
                   └─ timeout, crash, onparseerbaar, activity faalt ─▶ failed
```

Alle eindtoestanden zijn terminaal. Bij retries geldt de status van de laatste poging; eerdere pogingen blijven als records met `used: false`.

**Afgeleide regels**: FR-002 (`required && status ≠ completed` ⇒ run incomplete), FR-003 (`mayReportClean(entry) ⇔ status = completed`), FR-004 (`issues-found` is een oorzaak bij completed, nooit bij failed).

## EvidenceRecord

Bewijs van één uitgevoerde stap (één procesaanroep of één in-process-stap, per poging). Bestand `records/<id>.json`.

| Veld | Type | Validatie |
|------|------|-----------|
| schema | `tessera.evidence/v1` | vast |
| id | string | `<stepId>.a<attempt>`, `/^[a-z0-9][a-z0-9.-]{0,95}$/`, uniek in de bundel |
| runId | string | gelijk aan `manifest.runId` (FR-015) |
| stepId / attempt | string / integer | attempt ≥ 1 |
| kind | `tool-run` \| `in-process` \| `source-probe` \| `lifecycle` | |
| action.command / args / cwd | | geen absolute host-paden: vervangen door `<WORK>`, `<SOURCE>`, `<CONFIG>`; args geredigeerd |
| action.envOverrides / envPassthrough | | overrides met waarde, passthrough alleen met naam |
| action.inputs | map | bv. lockfile-sha256, gebruikte semgrep-config |
| tool.name / tool.version | | version ≤ 200 tekens of null |
| source.repoUrl / source.revision | | revision null alleen in records vóór of tijdens een mislukte clone (FR-008) |
| startedAt / endedAt / durationMs | | endedAt ≥ startedAt; durationMs = verschil |
| result.exitCode / signal / exitClass / timedOut / spawnErrorCode | | exitCode null ⇔ niet gestart of beëindigd door signaal |
| status / cause / causeDetail | | zie ScannerStatus |
| output / stderr | ArtifactRef \| null | output null alleen als er niets is geproduceerd (lege uitvoer krijgt wél een artefact van 0 bytes met zijn hash; edge case) |
| findingIds | string[] | elk id komt voor in de findings van de run of in het artefact (bij afkapping) |
| overrideAttempts | OverrideAttempt[] | FR-014 |

**Toestandsovergangen**: `staged` (in `.staging/`, 0600) → `published` (`link()` naar eindnaam; vanaf hier onveranderlijk) → `sealed` (opgenomen in manifest, 0400). Een `staged` bestand dat nooit gepubliceerd wordt, eindigt als `abandoned` in het manifest.

## Artifact (`ArtifactRef`)

Gesanitiseerde tooluitvoer: `artifacts/<recordId>.<suffix>` (`stdout.json`, `stderr.txt`, `report.json`).

| Veld | Validatie |
|------|-----------|
| path | relatief, posix, zonder `..` |
| bytes / sha256 | over de opgeslagen bytes |
| rawBytes / rawSha256 | over de ongesanitiseerde bytes (research R10) |
| redactions | aantal vervangingen |
| truncated | true ⇒ record-status is `partial/output-truncated` (FR-013) |

## Finding (uitbreiding)

Bestaande velden blijven ongewijzigd. Nieuw en optioneel in het type, maar binnen `applicationAudit` verplicht (afgedwongen door de outcome-guard):

| Veld | Type | Validatie |
|------|------|-----------|
| id | string | deterministisch: `<PREFIX>-<eerste 10 hex van sha256(stabiele sleutel)>`, bv. `NPM-` op (pakket, advisory-id), `LEAK-` op (bestand, regel, ruleId), `SEMGREP-` op (check_id, pad, startregel) |
| evidenceRef | EvidenceRef | `recordId` bestaat in de bundel; `recordSha256` = hash van dat recordbestand; `locator` is een JSON-pointer in het output-artefact |
| scanner | ScannerId | |
| heuristic | boolean | true voor code-review |
| evidence[].content | string | korte samenvatting ≤ 500 tekens, door redactielaag 3; nooit broncode of gematchte secret |
| evidence[].file / line | | behouden (nodig voor locatie, US5, en voor de demo-scoring) |

**Regel FR-007**: een finding zonder `evidenceRef` maakt de run `incomplete` met `notPerformed` = `{ scanner: 'evidence', status: 'untraced-findings' }`.

**Volgorde bij aanmaken**: findings (met id) → record met `findingIds` → hash van het gepubliceerde record → `evidenceRef` op elke finding.

## EvidenceManifest

Bestand `manifest.json` (0400) plus `SHA256SUMS`. Velden: zie `contracts/evidence-manifest.ts`.

| Regel | |
|-------|-|
| entries | precies alle bestanden onder `records/` en `artifacts/` (staging uitgezonderd), gesorteerd op pad, `seq` 1..n |
| chainHash | `sha256(prev + "\n" + seq + "\n" + path + "\n" + sha256)`, prev van entry 1 = `genesis` |
| rootHash | = `chain.head`; wordt buiten de map verankerd (workflowresultaat, history, rapport) |
| retainUntil | = sealedAt + 365 dagen |
| used | false voor records die niet in `usedRecordIds` staan |
| abandoned | stagingbestanden met hun hash; niet gepubliceerd, wel vermeld |

**Toestandsovergangen**: `absent` → `sealed` (geschreven en door `verifyEvidenceBundle` gecontroleerd) → bij de ontvanger `verified` of `failed` (per verificatie, niet opgeslagen). Er is geen her-verzegeling: een tweede `sealEvidence` op een verzegelde bundel geeft het bestaande resultaat terug als de bundel nog verifieert en faalt anders.

## Signature

| Veld | Type | Regel |
|------|------|-------|
| schema | `tessera.signature/v1` | vast |
| alg | `ed25519` | vast |
| keyId | sha256 hex | van de SPKI-DER van de publieke sleutel |
| runId, rootHash, manifestSha256 | string | moeten overeenkomen met manifest en bundel |
| signedAt | ISO-8601 UTC | klok van de ondertekenaar; niet extern getijdstempeld |
| signature | base64 | over de payload uit `contracts/evidence-signature.ts` |

Toestanden bij verificatie: `valid`, `invalid`, `unsigned`, `unknown-key`. Het assurance-niveau (0 of 1) wordt berekend uit hashcontrole en handtekeningstatus en staat in het rapport; het wordt nergens met de hand gezet.

## Toestandsvelden in de workflow (`AuditState`, additief)

`scanners: ScannerStatusEntry[]`, `outcome?: AuditOutcome`, `revision?: string`, `evidenceRootHash?: string`. De bestaande queries (`status`, `findings`, `state`) blijven werken; `state` toont de nieuwe velden mee.
