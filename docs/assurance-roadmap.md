# Tessera: assurance-roadmap

Project Tessera (commerciële naam buiten dit document) is een audit-framework voor grote enterprise-opdrachten.
Dit document is het product goal en de geordende backlog. Het beschrijft hoe elke versie sterker en strikter wordt,
en hoe een versie bewijst welk niveau zij haalt.

## Product goal

Een audit die een klant, een toezichthouder of een tweede auditor kan nalopen zonder de uitvoerder te vertrouwen:
elke bewering is herleidbaar tot een uitgevoerde stap, elke stap tot bewijs, en elk bewijs tot een controleerbare sleutel.
Het systeem zegt altijd wat het niet kon scannen en wat het niet kan bewijzen.

## Werkwijze

- **Eén bron**: dit bestand voor niveaus en volgorde; de constitution voor onwrikbare regels; per backlog-item een
  IIKit-feature (`specs/NNN-…`: spec, plan, testify, tasks).
- **Ratchet**: een bereikt niveau wordt nooit verlaagd. Een gate die strenger wordt, wordt niet teruggezet.
  Afwijkingen staan met eigenaar en deadline in de README (`Known deviations`).
- **Niveau wordt berekend, niet beweerd**: elk auditrapport toont het niveau dat uit de verificatie volgt (FR-020 van
  feature 004). Een klant leest dus "assurance niveau 1", nooit "enterprise grade" zonder bewijs.
- **Meting tegen grondwaarheid**: per release recall en vals-positieven op `demo/EXPECTED.md` (en later uitgebreide
  sets). Een capability zonder gemeten recall wordt niet geclaimd (constitution XI).
- **Claimregel in klantcommunicatie**: alleen het niveau noemen waarvan alle exitcriteria groen zijn.

## Niveaus

| Niveau | Naam | Belofte | Exitcriteria (allemaal meetbaar) |
|--------|------|---------|-----------------------------------|
| 0 | Heuristisch (start, 2026-10-02) | Er draait een audit; uitkomst niet betrouwbaar | Referentie: demo-recall 6/18, scannerfouten worden "geen bevindingen" |
| 1 | Eerlijk en controleerbaar | Wat gescand is staat vast, wat niet gescand is wordt gemeld, bewijs is manipulatie-*zichtbaar* | Feature 004 klaar: scannerstatus en INCOMPLEET (SC-001), bewijsrecord per stap (SC-002), demo-recall ≥ 8/18 met D05–D07 (SC-003), verificatie van hashketen (SC-004), geen secrets in bewijs (SC-005), ondertekend manifest met lokale sleutel (SC-007, SC-008) |
| 2 | Geïsoleerd en herstelbaar | Niet-vertrouwde doelcode raakt het framework niet; een crash kost bewijs noch tijd | Sandbox voor scanners, Temporal alleen op localhost met authenticatie, heartbeats en kort herstel (review #8), hermetische tests in CI, BDD-scenario's actief in CI, eigen versiebeheerde Semgrep-regelset (recall ≥ niveau 1), WORM-opslag voor bewijs, ondertekenaar onder aparte OS-gebruiker, aangetoond met aanvalsfixtures |
| 3 | Geattesteerd | Bewijs is onafhankelijk verifieerbaar, ook tegen een kwaadwillende beheerder | Sleutelbewaring buiten het beheerdomein (KMS of HSM, aparte ondertekenaarservice), RFC 3161-tijdstempel, externe verankering van de root-hash, scanner-binary- of image-digest in elk record, rolscheiding (worker schrijft, ondertekenaar tekent, auditor verifieert), reproduceerbare tweede run op dezelfde revisie, SBOM van het framework |
| 4 | Geborgd | Een derde partij kan de claims onderschrijven | Onafhankelijke verificatie of externe penetratietest met gesloten bevindingen, afbeelding op ISO 27001, SOC 2 en ASVS-controls met echte (geen placeholder) mapping, goedkeuringsbesluiten ondertekend met de identiteit van de goedkeurder, per release gepubliceerde recall en vals-positieven op uitgebreide grondwaarheid, GenAI-advies alleen met vastgelegde prompts en menselijke goedkeuring |

## Backlog (geordend)

Elk item wordt een IIKit-feature wanneer het aan de beurt is. `Bron` verwijst naar de bevindingen in `docs/review-report.md`.

| # | Item | Niveau | Bron | Afhankelijk van | Status |
|---|------|--------|------|-----------------|--------|
| 004 | Betrouwbare scankern (status, evidence, redactie, manifest, handtekening lokale sleutel) | 1 | #4, #5, #6, #7, #10, #16, #22, #1, #2 | n.v.t. | v0.2.0 (2026-10-03): zes stories, 45 BDD-scenario's, demo-gate groen; open: T042 tot T045, T046, T050, T051 |
| 005 | Eigen Semgrep-regelset met gemeten recall (vervangt vaste packs) | 2 | beslissing 004-R6 | 004 | niet gestart |
| 006 | Beveiligde uitvoering: sandbox, scannerconfig geforceerd, groottegrens werkmap | 2 | #1, #6, #16 | 004 | niet gestart |
| 007 | Herstelbaarheid: heartbeats, korte timeouts, retrybeleid, worker-kill-test | 2 | #8, #17 | 004 | niet gestart |
| 008 | Netwerk en toegang: Temporal op localhost met authenticatie, mTLS-pad | 2 | #3 | n.v.t. | niet gestart |
| 009 | Testbetrouwbaarheid: hermetische tests, BDD actief in CI, `.spec.md`-formaat en assertion-hashes | 2 | #11, #12, #14, #26, #28 | n.v.t. | niet gestart |
| 010 | Bewijsopslag: WORM, bewaarbeleid, back-up | 2 | 004 FR-011 (deels) | 004 | niet gestart |
| 011 | Goedkeuring: reject-signaal, vastgelegde besluiten, `skipApproval` zichtbaar | 2 | #15 | 004 | niet gestart |
| 012 | Domeinen aansluiten (privacy, documentatie, CI, reliability, SQL-injectie D08) met recall per domein | 2 | #9, D08, D12–D17 | 005 | niet gestart |
| 013 | Evidence Attestation: externe sleutelbewaring, RFC 3161, verankering, scanner-attestatie, rolscheiding | 3 | 004 R19, review §7 | 004, 010 | niet gestart |
| 014 | Reproduceerbare tweede run en vergelijking | 3 | review §7 | 013 | niet gestart |
| 015 | Compliance-mapping echt (ISO 27001, SOC 2, ASVS) | 4 | #19 | 012 | niet gestart |
| 016 | GenAI-advies onder controle (triage, herstelplan, kruisvalidatie) | 4 | #19, constitution IX | 013, 015 | niet gestart |
| 017 | Onafhankelijke verificatie en externe penetratietest | 4 | n.v.t. | 013 | niet gestart |
| 018 | Flowmetrics-script (demo-recall, uren CI rood, doorlooptijd, deviaties) naar `docs/metrics/` | 1 | `docs/agile/working-agreement.md` | 004 | niet gestart |
| 019 | Hernoemen van `audit-flow` naar `tessera` (package, README, CLI, daarna GitHub-repo, Woodpecker-koppeling en Sonar-sleutel; uitgaand deel alleen na bevestiging) | 1 | naamsbeslissing 2026-10-03 | 004 MVP (v0.2.0) | goedgekeurd 2026-10-03, uitvoering direct na v0.2.0 |
| 020 | Mutation testing op Tier C-modules als gate | 1 | praktijkanalyse 2026-10-03 | 004 | niet gestart |
| 021 | Threat model (STRIDE) voor framework en bronkant, als basis voor aanvalsfixtures | 1 | idem | n.v.t. | niet gestart |
| 022 | Architectuurregels als test (zuivere modules, `child_process` alleen in de process-runner) en complexiteits- en groottelint | 1 | idem | 004 | niet gestart |
| 023 | Risicoregister (RAID) `docs/agile/raid.md` | 1 | idem | n.v.t. | niet gestart |
| 024 | Leerlus met ontwerppartner: hypothese en riskiest-assumption-test per slice | 1 | Lean Startup | 004 MVP | niet gestart |
| 025 | Incidentnotities (blameless, 5x waarom): stale worker, quota-uitputting | 1 | idem | n.v.t. | niet gestart |
| 026 | Glossary en ADR's | 1 | idem | n.v.t. | niet gestart |
| 027 | Release en supply chain: tags, changelog, SBOM, gesigneerde releases | 2 | idem | 004 MVP | niet gestart |
| 028 | Property-based tests voor redactie, manifest en verify (nieuwe dev-dependency, eerst akkoord) | 2 | idem | 004 | niet gestart |
| 029 | Performance-budget als test (evidence-overhead) en fault injection | 2 | idem | 004, 007 | niet gestart |
| 030 | DPIA en privacy by design voor bewijs met klantcode, runbook en SLO's voor het framework | 2 | idem | 010 | niet gestart |
| 031 | Evalueer in-toto, Witness en Sigstore als evidence-attestatieformaat boven een eigen formaat (onderdeel van 013) | 3 | zoekresultaten 2026-10-03 | 004 | niet gestart |
| 032 | DefectDojo-export van Tessera-bevindingen en bewijsverwijzingen (afnemer, geen vervanger) | 3 | idem | 004 | niet gestart |
| 033 | Beoordeel de Compound Engineering-plugin (multi-agent review, lessen vastleggen) op licentie, onderhoud en rechten | 1 | idem | n.v.t. | niet gestart |
| 034 | Distilleer uit de agentic retro van 004 een eigen ontwikkelaanpak (playbook, skills, templates) en beoordeel of die als product of open-source bijdrage taugt | 1 | verzoek 2026-10-03 | 004 klaar (T051) | niet gestart |

Gevolg voor de volgorde: niveau 2 bestaat uit items 005–012 en is pas af als alle exitcriteria groen zijn.
Volgorde binnen een niveau volgt risico (RCE en toegang eerst: 006 en 008), niet de nummering.

## Governance van dit document

- Een wijziging van een exitcriterium of niveau is een bewuste beslissing met vermelding van datum en reden in de
  commit; criteria worden strenger, niet soepeler.
- De status in de backlog komt uit de IIKit-voortgang (`/iikit-core status`) en de pipeline, niet uit dit bestand alleen.
- Bij elke release: demo-run, recall en vals-positieven vastleggen en het behaalde niveau noteren.
