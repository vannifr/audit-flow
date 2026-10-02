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

# Coverage (65% threshold)
npm run test:coverage

# Full verification
npm run verify
```

**Current Status:**
- Tests: 171 passing
- Coverage: 64%
- Build: 0 errors

---

## Guardrails

### Git Hooks

```bash
# Pre-commit: build + test + lint
# Pre-push: verify + gitleaks secret scanning
```

### Coverage Thresholds

Phase 1 interim:
- Statements: 65%
- Branches: 40%
- Functions: 75%
- Lines: 68%

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
3. 65% coverage minimum
4. Run `npm run verify` before commit

---

## License

MIT