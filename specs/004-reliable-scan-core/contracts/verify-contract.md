# Contract: evidence verification (FR-010, FR-015, FR-017, SC-004)

Doelmodule: `src/evidence/verify.ts` (bibliotheek) en `src/cli/verify-evidence.ts` (CLI).
Dezelfde functie draait aan het eind van `sealEvidence` (zelfcontrole) en bij de ontvanger van de map.

## Bibliotheek

```ts
export interface VerifyOptions {
  expectRootHash?: string;   // anker van buiten de map: workflowresultaat, Temporal-history of rapport
}

export interface VerifyIssue {
  path: string;              // relatief pad in de bundel
  problem: 'modified' | 'missing' | 'extra' | 'run-mismatch' | 'invalid-record' | 'chain-broken';
  expected?: string;         // sha256 of runId uit het manifest
  actual?: string;
}

export interface VerifyReport {
  ok: boolean;               // true alleen als issues leeg is en (geen expectRootHash of rootMatches)
  bundlePath: string;
  runId: string | null;
  rootHash: string | null;   // herberekend uit de entries
  manifestRootHash: string | null;
  rootMatches: boolean | null; // null als expectRootHash ontbreekt
  checkedEntries: number;
  issues: VerifyIssue[];     // gesorteerd op path; elk gewijzigd/ontbrekend/extra bestand precies één keer
}

export function verifyEvidenceBundle(bundleDir: string, opts?: VerifyOptions): Promise<VerifyReport>;
```

## Regels

1. `manifest.json` ontbreekt of is geen geldig `tessera.manifest/v1`: `ok=false`, één issue `invalid-record` op `manifest.json`.
2. Voor elke entry: bestand ontbreekt → `missing`; sha256 wijkt af → `modified`.
3. Elk bestand onder `records/` en `artifacts/` dat niet in `entries` of `abandoned` staat → `extra`. `manifest.json` en `SHA256SUMS` zijn de enige toegestane bestanden buiten die mappen; elk ander bestand → `extra`.
4. Elk record moet als JSON te parsen zijn met `schema = tessera.evidence/v1` en `runId` gelijk aan `manifest.runId`; anders `invalid-record` of `run-mismatch` (FR-015).
5. De keten wordt herberekend vanaf `sha256("tessera:" + runId)`; wijkt een `chainHash` of `chain.head` af → `chain-broken` op die entry.
6. `expectRootHash` gegeven en ongelijk aan de herberekende root → `ok=false`, `rootMatches=false`.
7. Symlinks in de bundel worden niet gevolgd en tellen als `extra`.
8. De functie leest alleen; ze wijzigt niets en heeft geen netwerk nodig.

## CLI

```
npm run evidence:verify -- <bundle-dir> [--expect-root <sha256>] [--json]
```

| Exitcode | Betekenis |
|----------|-----------|
| 0 | Alle controles geslaagd |
| 1 | Minstens één issue of root-mismatch; elk issue op één regel: `<problem> <path>` |
| 2 | Gebruiksfout of map onleesbaar |

Tekstuitvoer is zonder kleur en begint met `VERIFIED` of `FAILED`, gevolgd door runId, root-hash en het aantal gecontroleerde entries (toegankelijk voor schermlezers en logs). `--json` geeft het `VerifyReport` op stdout.

## Controle zonder framework

`SHA256SUMS` in de bundel volgt het coreutils-formaat. `sha256sum -c SHA256SUMS` in de bundelmap detecteert gewijzigde en ontbrekende bestanden zonder deze software. Extra bestanden, de keten en de root-hash vereisen de CLI. Dit verschil staat in de evidence-sectie van het rapport.
