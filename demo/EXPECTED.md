# Grondwaarheid van de demo

Dit bestand is de bron voor recall en precisie van `npm run demo`. Het is vastgelegd vóór de
eerste auditrun en wordt niet aangepast om een run groen te krijgen. Een gemist defect is een
bevinding in het auditsysteem, geen fout in deze lijst.

Ernstschaal van audit-flow: P0 = kritiek, P1 = hoog, P2 = middel, P3 = laag.

## `demo/vulnerable-app` (verwacht: alle defecten gevonden)

| ID | Domein | Defect | Bestand:regel | Verwachte ernst |
|----|--------|--------|---------------|-----------------|
| D01 | secret-scanning | AWS access key (documentatievoorbeeld `AKIAIOSFODNN7EXAMPLE`, geen echte sleutel) | src/config.js:2 | P0 |
| D02 | secret-scanning | AWS secret key (documentatievoorbeeld) | src/config.js:3 | P0 |
| D03 | secret-scanning | Hardcoded beheerderswachtwoord | src/auth.js:4 | P1 |
| D04 | secret-scanning | Hardcoded signeergeheim voor tokens | src/auth.js:3 | P1 |
| D05 | dependency-vulns | `lodash@4.17.15`: prototype pollution en command injection (CVE-2020-8203, CVE-2021-23337) | package.json:12 | P1 |
| D06 | dependency-vulns | `minimist@1.2.0`: prototype pollution (CVE-2021-44906, kritiek) | package.json:13 | P0 |
| D07 | dependency-vulns | `express@4.17.1` met kwetsbare transitieve afhankelijkheden (o.a. body-parser, qs, path-to-regexp) | package.json:11 | P1 |
| D08 | input-validation / sast | SQL-injectie door stringconcatenatie | src/server.js:10 | P0 |
| D09 | sast | Reflected XSS: ongeëscapete invoer in HTML-respons | src/server.js:15 | P1 |
| D10 | sast | `eval()` op gebruikersinvoer (remote code execution) | src/server.js:19 | P0 |
| D11 | data-encryption | Zwakke hash (MD5) voor wachtwoorden en tokens | src/auth.js:7 | P2 |
| D12 | sast | Prototype pollution via `_.merge` op request-body | src/server.js:29 | P2 |
| D13 | privacy | Wachtwoord, e-mail en telefoonnummer in logregel | src/server.js:23 | P1 |
| D18 | secret-scanning | Hardcoded interne API-sleutel (verzonnen hex-waarde met hoge entropie, niet in gitleaks-stopwoordenlijst) | src/config.js:4 | P1 |
| D14 | documentation | Geen README | (repo-root) | P3 |
| D15 | cicd | Geen CI-configuratie | (repo-root) | P3 |
| D16 | testability | Geen tests | (repo-root) | P2 |
| D17 | reliability | Geen foutafhandeling-middleware en geen health-endpoint | src/server.js | P3 |

Bewust niet geplant: licentieschendingen, toegankelijkheid, performance en load (vereisen een
draaiende site of een externe afhankelijkheid). Dat is een beperking van de demo, geen bewering
dat die domeinen werken.

## `demo/clean-app` (verwacht: geen bevindingen)

Heeft README, CI-configuratie, test, geëscapete uitvoer, health-endpoint, foutmiddleware,
`npm audit` zonder kwetsbaarheden en geen geheimen. Elke bevinding op deze repo telt als
vals-positief.

## Matchregels voor de vergelijking

Een defect telt als gevonden als minstens één bevinding in het rapport voldoet aan de
`match`-regex (hoofdletterongevoelig) op titel, beschrijving, bewijs en bestand, en, waar
`file` is opgegeven, het bewijsbestand op dat pad eindigt. Ernst wordt apart gescoord:
Waar `category` is opgegeven, moet de bevindingcategorie ook voldoen aan die regex.
Na de eerste proefrun is `category` toegevoegd aan D05–D07 en D13–D17 omdat de tekstmatch onterecht
crediet gaf (D07 matchte op het woord `express` in Semgrep-regelnamen). Dat maakt de meting
strenger, niet soepeler. Ernstverwachtingen en defecten zijn niet gewijzigd.
Recall telt zowel "gevonden" als "gevonden met juiste ernst".

Aanscherping van de meting (release-gate, geen versoepeling): `run-demo.js` wijst bevindingen
strikt één-op-één aan defecten toe (maximale bipartiete toewijzing) en gebruikt het optionele
veld `line` (de regel in `evidence.line` van de bevinding, waar bekend; een bevinding zonder
regelnummer blijft toegestaan). D01 (2), D02 (3), D18 (4), D03 (4) en D04 (3) hebben een `line`.
De eerdere run crediteerde D02 onterecht: de enige bevinding op src/config.js:4 (generic-api-key,
D18) dekte via de brede tekstmatch ook D02 (regel 3). Ernstverwachtingen, defecten en de
minimumeis van 8 van 18 zijn niet gewijzigd; de ruime recall blijft ter vergelijking zichtbaar.

```json
{
  "vulnerable-app": [
    {"id":"D01","file":"src/config.js","line":2,"severity":"P0","match":"AKIA|aws.*(access|key)"},
    {"id":"D02","file":"src/config.js","line":3,"severity":"P0","match":"aws.*secret|wJalr|generic-api-key|secret"},
    {"id":"D03","file":"src/auth.js","line":4,"severity":"P1","match":"password"},
    {"id":"D04","file":"src/auth.js","line":3,"severity":"P1","match":"secret|token|jwt"},
    {"id":"D05","file":null,"category":"security-dependencies","severity":"P1","match":"lodash"},
    {"id":"D06","file":null,"category":"security-dependencies","severity":"P0","match":"minimist"},
    {"id":"D07","file":null,"category":"security-dependencies","severity":"P1","match":"express|body-parser|qs|path-to-regexp"},
    {"id":"D08","file":"src/server.js","severity":"P0","match":"sql.?inj|sql"},
    {"id":"D09","file":"src/server.js","severity":"P1","match":"xss|cross-site|innerhtml|res\\.send"},
    {"id":"D10","file":"src/server.js","severity":"P0","match":"eval"},
    {"id":"D11","file":"src/auth.js","severity":"P2","match":"md5|weak.*(hash|crypt)"},
    {"id":"D12","file":"src/server.js","severity":"P2","match":"prototype|merge"},
    {"id":"D13","file":"src/server.js","category":"privacy|observability|security-data","severity":"P1","match":"pii|privacy|log.*(password|email)|sensitive"},
    {"id":"D18","file":"src/config.js","line":4,"severity":"P1","match":"api.?key|generic|secret"},
    {"id":"D14","file":null,"category":"documentation|compliance|code-quality","severity":"P3","match":"readme|documentation"},
    {"id":"D15","file":null,"category":"cicd","severity":"P3","match":"ci/cd|cicd|pipeline|ci config"},
    {"id":"D16","file":null,"category":"testab|code-quality|functional","severity":"P2","match":"no tests|test"},
    {"id":"D17","file":null,"category":"reliability","severity":"P3","match":"error.?handl|health|reliab"}
  ],
  "clean-app": []
}
```
