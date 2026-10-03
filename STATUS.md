# Status

This file used to hold hand-written status figures. Several of them were wrong (test counts, coverage, "Production Ready"),
and a status that is written by hand drifts from the code. It now only points to the sources that are produced or measured:

- Current claims, deviations, coverage floors and how to run everything: `README.md`
- Product goal, assurance levels and the ordered backlog: `docs/assurance-roadmap.md`
- Independent review with every claim checked: `docs/review-report.md` and `docs/review-004-security.md`
- Test and coverage numbers: the output of `npm run verify` and the pipeline on `main` (not repeated here)
- Domain and check coverage (generated from the config): `AUDIT-COVERAGE.md`
