# Temporal Security Audit Framework

> Enterprise-grade application security audit framework powered by Temporal.io

**Version:** 1.0.0
**Status:** Production Ready
**Last Updated:** 2026-10-02

---

## Overview

Durable workflow orchestration for comprehensive application security audits. Performs security, performance, accessibility, and compliance audits with human-in-the-loop approval for critical findings.

### Key Features

- **Security Scanning** - npm audit, gitleaks (secrets), semgrep (SAST), SQL injection detection
- **Performance** - Lighthouse Core Web Vitals (LCP, FID, CLS)
- **Accessibility** - WCAG 2.2 AA compliance via axe-cli
- **Quality Gates** - ESLint, TypeScript, complexity analysis
- **Reliability** - Error handling, retry logic, health checks
- **Observability** - Logging, metrics, tracing validation
- **CI/CD** - Pipeline configuration and security gates
- **Compliance** - ISO27001, OWASP-ASVS, GDPR mapping

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Temporal Server                          │
│            (Workflow Engine + State Persistence)             │
└─────────────────────────────────────────────────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
┌───────┴──────┐   ┌───────┴──────┐   ┌───────┴──────┐
│  Audit Client │   │ Audit Worker │   │  Temporal UI │
│  (CLI/API)    │   │ (Activities) │   │  (Monitoring)│
└──────────────┘   └──────────────┘   └──────────────┘
```

---

## Quick Start

### Prerequisites

- Node.js 20 LTS
- Temporal CLI: `curl -sSL https://temporal.download/cli.sh | sh`
- gitleaks, semgrep (optional for local testing)

### Installation

```bash
# Install dependencies
npm install

# Build
npm run build

# Start Temporal server (development)
temporal server start-dev

# Start worker (in another terminal)
npm run start
```

### Run Audit

```bash
# E2E test (without Temporal server)
npx ts-node scripts/test-audit-run.ts

# View Temporal UI
open http://localhost:8233
```

---

## Audit Domains

| Domain | Tool | Checks |
|--------|------|--------|
| Security - Dependencies | npm audit | CVE scanning |
| Security - Secrets | gitleaks | Hardcoded credentials |
| Security - SAST | semgrep | XSS, CSRF, injection |
| Security - SQL Injection | semgrep custom | 5 SQL patterns |
| Performance | lighthouse | Core Web Vitals |
| Accessibility | axe-cli | WCAG 2.2 AA |
| Reliability | Pattern check | Error handling, retry |
| Observability | Pattern check | Logging, metrics, tracing |
| CI/CD | Config check | Pipeline validation |
| Code Quality | ESLint, tsc | Linting, types, complexity |
| Documentation | File check | README, API docs |
| Privacy | Pattern check | GDPR compliance |
| Functional | Test check | Acceptance criteria |
| Blind Spots | Repo check | Bus factor, on-call |

---

## Workflow Phases

```
Discovery → Scanning → Review → Approval → Reporting → Cleanup

Activities (19):
  - validateRepoUrl, cloneRepository, detectTechStack
  - runNpmAudit, runGitleaks, runSemgrep, runLicenseCheck
  - runLighthouse, runAxeAccessibility, runSqlInjectionCheck
  - checkReliability, checkObservability, checkCicd
  - checkCodeQuality, checkDocumentation, checkPrivacy
  - checkFunctionalRequirements, checkBlindSpots
  - generateReport, waitForHumanApproval
```

---

## Output

```
/tmp/audit-<workflow-id>/
├── audit-report.md        # Full audit report
├── npm-audit.json         # npm audit results
├── gitleaks-report.json   # Secret scan results
├── semgrep-report.json    # SAST results
├── lighthouse-report.json # Performance results
├── axe-report.json        # Accessibility results
└── evidence/              # Evidence per finding
```

---

## Testing

```bash
# Unit tests
npm run test

# Coverage (enforced floor, see Coverage Thresholds)
npm run test:coverage

# Fast gate: build, coverage, lint
npm run verify

# Everything CI checks (needs network, gitleaks, semgrep)
npm run verify:full
```

Status figures (tests, coverage) come from the pipeline output, not from this file.

---

## Guardrails

See `docs/assurance-roadmap.md` for the product goal, the assurance levels and the ordered backlog.

### CI and local parity

Each CI step calls the same npm script or `scripts/ci/*.sh` as local verification.

| CI step | Local command | Notes |
|---------|---------------|-------|
| build, lint, test | `npm run verify` | Coverage gate fails when a threshold is breached |
| secrets-scan | `npm run security:secrets` | Needs `gitleaks`; skipped with a warning locally, fails in CI if missing |
| dependency-audit | `npm run security:deps` | Production dependencies, high and above, needs network |
| license-check | `npm run security:licenses` | Needs network |
| sast | `npm run security:sast` | Needs `semgrep` and network for rulesets |
| sonarqube | none | Needs the SonarQube server; non-blocking, see deviations |

Hooks (`npm run hooks:install` sets `core.hooksPath`): pre-commit runs `verify` and a staged
secret scan; pre-push runs `verify:full`.

**Known deviations and gaps**

- SonarQube is non-blocking (owner: vannifr, deadline: 2026-11-01). Its quality gate fails on
  coverage of new code. It cannot run locally without the server.
- Development-dependency advisories (high) are not blocking; production dependencies are.
- The `.feature` scenarios are not executed by `verify` or CI: the BDD runner loads no
  step definitions for `specs/`. Tracked in `docs/review-report.md` (finding 12).
- Lighthouse, axe and k6 are not CI steps. The earlier placeholder steps were removed
  because they checked nothing.
- CI images are pinned by digest. Bump them deliberately and update the digest.
- `npm run test:tools` runs contract tests against the real tools (gitleaks, semgrep, npm). It is not part of `verify` or CI because the CI image lacks the tools.

### Coverage Thresholds

Enforced floor (vitest `thresholds`), raised as tests improve; the target is 80% globally:
- Global: statements 79%, branches 66%, functions 86%, lines 81%
- `src/scan/**`: statements 85%, branches 80%, functions 90%, lines 90%
- `src/evidence/**`: statements 83%, branches 74%, functions 82%, lines 88%

The gate was proven to fail: raising one per-glob threshold to 99% gives exit 1. The new modules use hermetic tests
(fake process runner and store), so their coverage is the same locally and in CI.

The earlier deviation on the global functions floor (84% to 82%) is closed: the scanner modules raised it to 86%.
The plan target for the new modules is 90/85/90/90 (statements, branches, functions, lines); `src/evidence` store (78%) and the
process runner (75%) are still below that.
The older tests that call real tools make the global figure lower in the CI container than on a developer machine; make them
hermetic before raising the global floor.

---

## Project Structure

```
temporal-security-audit-framework/
├── src/
│   ├── activities/          # Temporal activities (19)
│   ├── workflows/           # Workflow definitions
│   ├── types/               # TypeScript types
│   └── config/              # Audit domain config
├── tests/
│   ├── unit/                # Unit tests
│   ├── integration/         # Integration tests
│   └── step_definitions/    # BDD step definitions
├── specs/
│   ├── 001-start-audit-workflow/
│   ├── 002-p0-approval-workflow/
│   └── 003-generate-audit-report/
├── scripts/
│   ├── setup-tools.sh       # Tool installation
│   └── test-audit-run.ts    # E2E test
├── .githooks/               # Pre-commit/pre-push
├── CONSTITUTION.md          # Governance
├── STATUS.md                # Project status
└── README.md                # This file
```

---

## IIKit Governance

This project follows Intent Integrity Kit governance:

| Artifact | Status |
|----------|--------|
| CONSTITUTION.md | ✓ Active |
| PREMISE.md | ✓ Active |
| Feature Specs | ✓ 3 features |
| BDD Tests | ✓ 4 .feature files |
| Plans & Tasks | ✓ Complete |

---

## ISO 25010 NFR Implementation

This framework implements ISO/IEC 25010:2011 software quality characteristics as Temporal activities:

### Performance Effectiveness
- **Throughput** - k6 load testing (measureThroughput activity)
- **Lighthouse** - Core Web Vitals: LCP, FID, CLS (runLighthouse activity)

### Reliability
- **Durability** - Data retention checks (assessDurability activity)
- **Stability** - Error pattern detection (assessStability activity)
- **Robustness** - Exception handling coverage (assessRobustness activity)
- **Resilience** - Failover/recovery patterns (assessResilience activity)

### Security
- **Exploitability** - CVSS score assessment (assessExploitability activity)
- **SQL Injection** - Custom semgrep rules (runSqlInjectionCheck activity)

### Maintainability
- **Readability** - Code clarity scoring (measureReadability activity)
- **Modifiability** - Architecture check (planned)
- **Testability** - Coverage analysis (planned)
- **Analyzability** - Logging/metrics (checkObservability activity)

### Portability
- **Adaptability** - Cross-platform check (planned)
- **Installability** - Deployment check (planned)

### Functional Suitability
- **Completeness** - Requirements coverage (checkFunctionalRequirements activity)
- **Correctness** - Test validation (planned)
- **Appropriateness** - Domain mapping (generateScopeDocument activity)

### Compatibility
- **Interoperability** - API compliance (planned)
- **Co-existence** - Environment check (planned)

### Usability
- **Accessibility** - WCAG 2.2 AA via axe-cli (runAxeAccessibility activity)
- **Understandability** - Documentation check (checkDocumentation activity)

### Safety
- **Risk mitigation** - Blind spots detection (checkBlindSpots activity)

---

## Contributing

1. Follow CONSTITUTION.md governance
2. TDD required - write tests first
3. Do not lower the coverage floor; raise it as coverage grows
4. Run `npm run verify` before commit

---

## License

MIT