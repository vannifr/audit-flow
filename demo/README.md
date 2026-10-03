# Tessera demo

Reproduceerbare end-to-end run van het auditsysteem tegen twee kleine apps, met een vaste
grondwaarheid.

| Map | Doel |
|-----|------|
| `vulnerable-app/` | Bewust geplante defecten (nep-secrets, kwetsbare dependencies, SQL-injectie, XSS, `eval`, PII in logs, ontbrekende docs/CI/tests) |
| `clean-app/` | Schone controle-repo: elke bevinding hierop is een vals-positief |
| `EXPECTED.md` | Per defect de verwachte bevinding (domein, ernst, bestand:regel) en de matchregels |
| `run-demo.js` | Start Temporal dev-server en worker, draait beide audits, vergelijkt met `EXPECTED.md`, ruimt op |

Alle secrets zijn nep: de AWS-waarden zijn de officiële documentatievoorbeelden, de overige waarden zijn verzonnen.

## Draaien

```bash
npm ci --legacy-peer-deps
npm run demo
```

Vereist: `node` ≥ 20, `git`, `temporal` (CLI met dev-server), `gitleaks`, `semgrep`. Poorten 7233 (gRPC) en
8233 (UI) moeten vrij zijn; er mag geen andere worker op taskqueue `audit` draaien, anders pakt die
taken van de demo af.

De demo clonet niets van GitHub: `validateRepoUrl` accepteert alleen `https://github.com/owner/repo`, dus het script
bouwt van beide apps een tijdelijke git-repo en laat git `https://github.com/audit-demo/<app>` herleiden
naar die lokale repo (`url.<base>.insteadOf` via `GIT_CONFIG_*` in de worker-omgeving). De audits draaien met
`skipApproval: true`.

## Wat je ziet

Een tabel per app: voor `vulnerable-app` per defect `gevonden` en de gerapporteerde ernst naast de verwachte,
met recall (gevonden en gevonden met juiste ernst); voor `clean-app` het aantal vals-positieven.

Exitcode 0 betekent: alle geplande defecten gevonden en nul bevindingen op `clean-app`. Exitcode 1 is een afwijking,
2 een omgevingsfout (bijvoorbeeld ontbrekende tool of bezette poort). De ruwe resultaten staan na afloop in
`demo/last-run.json` (niet gecommit). `DEMO_KEEP_WORKDIR=1` bewaart logs en rapporten in `/tmp/tessera-demo-*`.

## Kwaliteitsgates

`demo/` is uitgesloten van vitest (tests en coverage) en van gitleaks (`.gitleaks.toml`, met reden). `tsc` en ESLint
dekken alleen `src/`, en de Sonar-scope is `src`. De demo telt niet mee in `npm run verify`.
