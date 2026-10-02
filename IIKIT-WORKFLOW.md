# IIKit Workflow — Temporal Security Audit Framework

## Overzicht

IIKit (Intent Integrity Kit) is een governance framework dat zorgt voor traceerbaarheid van requirements naar implementatie.

---

## IIKit Phases

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           IIKit PHASES                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Phase 0: INIT                                                          │
│    ├── CONSTITUTION.md  ← Governance (TDD, Security, Compliance)        │
│    ├── PREMISE.md       ← Project scope, actors, domain                 │
│    └── Directory structure                                               │
│                                                                          │
│  Phase 1: SPECIFY                                                       │
│    ├── spec.md          ← User stories, requirements (FR-XXX)           │
│    └── Success criteria (SC-XXX)                                        │
│                                                                          │
│  Phase 2: PLAN                                                          │
│    ├── plan.md          ← Technical design, architecture                │
│    ├── data-model.md    ← Entities, relationships                       │
│    ├── contracts/       ← API contracts                                  │
│    └── research.md      ← Technology decisions                          │
│                                                                          │
│  Phase 3: CHECKLIST                                                     │
│    └── Quality checklist for spec validation                            │
│                                                                          │
│  Phase 4: TESTIFY                                                       │
│    ├── .feature files   ← Gherkin BDD scenarios                         │
│    └── Hash-locked assertions                                           │
│                                                                          │
│  Phase 5: TASKS                                                         │
│    └── tasks.md         ← Dependency-ordered implementation tasks       │
│                                                                          │
│  Phase 6: ANALYZE                                                       │
│    └── Cross-artifact consistency check                                 │
│                                                                          │
│  Phase 7: IMPLEMENT                                                     │
│    └── Execute tasks → Write code → Run tests → Commit                  │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Project Artifacts

### 1. CONSTITUTION.md

**Doel:** Governance regels die niet onderhandelbaar zijn.

```markdown
# Audit Orchestration Constitution

## Core Principles

### I. Security-First Development
- All code must pass security scanning before merge
- No hardcoded secrets, credentials, or API keys
- Input validation at all system boundaries

### II. Test-Driven Development (NON-NEGOTIABLE)
- TDD mandatory for all production code
- Minimum 80% code coverage for all modules
- 100% coverage for critical paths

### III. Enterprise Compliance
- ISO 27001:2022, SOC 2 Type II, PCI-DSS, GDPR
- Every finding must map to compliance controls
```

**Impact:**
- Pre-commit hooks met security scanning
- Coverage gates in CI
- Compliance mapping in elke audit

---

### 2. PREMISE.md

**Doel:** Wat bouwen we, voor wie, en waarom?

```markdown
## What
Temporal-based workflow orchestration for enterprise application audits.

## Who
- Enterprise Consultants — Deliver traceable audits
- DevOps Teams — Integrate audits in CI/CD
- Security Teams — Continuous security validation

## Why
Enterprise applications require rigorous, auditable security reviews.
Manual audits are time-consuming, inconsistent, non-repeatable.
```

---

### 3. Feature Specs (3 features)

#### Feature 001: Start Audit Workflow

**spec.md — User Stories:**
```gherkin
### User Story 1 - Start Security Audit (Priority: P1)
As a security auditor, I want to start an automated security audit...

Acceptance Scenarios:
1. Given I have a valid GitHub URL, When I start an audit, 
   Then the system initiates a new workflow
```

**plan.md — Technical Design:**
```
Architecture:
  Temporal Server → Worker → Activities
  
Activities:
  - validateRepoUrl
  - cloneRepository
  - detectTechStack
  - runNpmAudit
  - runGitleaks
  - runSemgrep
```

**tasks.md — Implementation:**
```markdown
### Task 1.1: Create Workflow Definition
- [x] Priority: P1, Estimate: 2 hours
- Files: src/workflows/index.ts

### Task 1.2: Implement Discovery Activities
- [x] Priority: P1, Estimate: 4 hours
- Files: src/activities/index.ts
```

**tests/features/start-audit.feature — BDD:**
```gherkin
Feature: Start Security Audit

  @TS-001 @FR-001 @FR-002 @SC-001
  Scenario: Start audit with valid repository URL
    Given I have a valid GitHub repository URL
    When I start an audit with default settings
    Then the system initiates a new audit workflow
    And returns a unique workflow ID
```

---

#### Feature 002: P0 Approval Workflow

**spec.md:**
```gherkin
### User Story 1 - Pause for P0 Approval (Priority: P1)
As a security auditor, I want the workflow to pause automatically 
when critical (P0) findings are detected...
```

**plan.md:**
```
Architecture:
  Scanning → Review → P0 Approval Gate → Reporting
                           ↑
                     Signal Handler
```

**tasks.md:**
```markdown
### Task 1.1: Add Approval Gate to Workflow
- [x] Workflow pauses when P0 findings detected

### Task 1.2: Create Approval Signal Handler
- [x] Signal handler accepts boolean approval
```

---

#### Feature 003: Generate Audit Report

**spec.md:**
```gherkin
### User Story 1 - Generate Markdown Report (Priority: P1)
As a security auditor, I want a comprehensive audit report in 
Markdown format...
```

**plan.md:**
```
Report Sections:
  - Executive Summary
  - Methodology
  - Findings Table
  - Compliance Mapping
  - Recommendations
```

---

## Traceability Matrix

| Requirement | Spec | BDD Test | Code | Status |
|-------------|------|----------|------|--------|
| FR-001: Start audit | ✓ | TS-001 | validateRepoUrl | ✓ |
| FR-002: Clone repo | ✓ | TS-002 | cloneRepository | ✓ |
| FR-003: Tech stack | ✓ | TS-003 | detectTechStack | ✓ |
| FR-004: Security scan | ✓ | TS-004 | runNpmAudit | ✓ |
| FR-005: P0 approval | ✓ | TS-005 | waitForApproval | ✓ |
| FR-006: Generate report | ✓ | TS-006 | generateReport | ✓ |

---

## BDD Test Execution

```bash
# Run BDD tests
npx cucumber-js specs/*/tests/features

# Result
Feature: Start Security Audit
  ✓ TS-001: Start audit with valid repository URL
  ✓ TS-002: Reject invalid repository URL
  ✓ TS-003: Detect tech stack
  ✓ TS-004: Run security scans
  ✓ TS-005: Generate report
```

---

## Dashboard

IIKit genereert automatisch een dashboard:

```
file://.specify/dashboard.html
```

Toont:
- Feature progress
- Test coverage
- Artifact status
- Next steps

---

## Benefits

### 1. Governance
- Constitution dwingt security en TDD af
- Geen code zonder tests
- Geen merge zonder security scan

### 2. Traceability
- Elke requirement (FR-XXX) → BDD test (TS-XXX) → Code
- Wijzigingen zijn traceerbaar
- Audit trail voor compliance

### 3. Quality Gates
- Spec quality score (min 6/10)
- Coverage thresholds (65% interim, 80% target)
- BDD tests must pass before merge

### 4. Consistency
- Alle features volgen zelfde structuur
- Templates voor spec, plan, tasks
- Standaard BDD syntax

---

## Commands

```bash
# Check status
/iikit-core status

# Select feature
/iikit-core use 001

# Clarify ambiguities
/iikit-clarify

# Generate plan
/iikit-02-plan

# Generate BDD tests
/iikit-04-testify

# Generate tasks
/iikit-05-tasks

# Implement
/iikit-07-implement
```

---

## Summary

IIKit heeft dit project gestructureerd van:

```
Idee → Constitution → Spec → Plan → BDD Tests → Tasks → Code
```

Met:
- 3 features compleet
- 19 activities geïmplementeerd
- 171 tests passing
- Full traceability van requirements naar code