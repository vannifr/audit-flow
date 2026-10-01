# Data Model: Start Audit Workflow

**Date**: 2026-10-01
**Feature**: 001-start-audit-workflow

## Core Entities

### Audit

Represents a complete security audit of a repository.

**Fields**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| workflowId | string | ✅ | Unique Temporal workflow ID |
| repoUrl | string | ✅ | GitHub repository URL |
| status | AuditStatus | ✅ | Current workflow status |
| startTime | Date | ✅ | Audit start timestamp |
| endTime | Date? | ❌ | Audit completion timestamp |
| techStack | TechStack | ✅ | Detected technology stack |
| scope | ScopeDocument | ✅ | Audit scope definition |
| findings | Finding[] | ✅ | List of identified issues |
| complianceMaps | ComplianceMap[] | ❌ | Framework mappings |
| reportPath | string? | ❌ | Path to generated report |
| evidencePath | string? | ❌ | Path to evidence directory |

**State Transitions**:

```
Created → Discovery → Scanning → Reviewing → Compliance → Validation → Reporting → Completed
         ↓           ↓           ↓
         Failed      Failed      Failed
                     ↓
                     Waiting for P0 Approval → Approved → Continue
                                                  ↓
                                                  Rejected → Failed
```

**Validation Rules**:
- `workflowId` must match pattern `audit-.*-[0-9]+`
- `repoUrl` must be valid GitHub URL (https://github.com/owner/repo)
- `startTime` must be set before workflow execution
- `endTime` only set when status is `Completed` or `Failed`

---

### Finding

Represents an identified security issue or compliance violation.

**Fields**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| id | string | ✅ | Unique finding identifier (e.g., NPM-1, LEAK-2) |
| title | string | ✅ | Brief description |
| description | string | ✅ | Detailed explanation |
| severity | 'P0' \| 'P1' \| 'P2' \| 'P3' | ✅ | Severity level |
| category | string | ✅ | Category (e.g., security-dependencies, security-data) |
| evidence | Evidence[] | ✅ | Proof artifacts |
| remediation | Remediation | ✅ | Fix guidance |
| verified | boolean | ✅ | Whether finding is validated |
| complianceMappings | string[] | ❌ | Related compliance controls |
| createdAt | Date | ✅ | Finding timestamp |

**Severity Definitions**:

| Level | Definition | Examples |
|-------|------------|----------|
| **P0** | Critical - Immediate action required | Hardcoded secrets, RCE vulnerabilities, exposed credentials |
| **P1** | High - Fix within 24-48 hours | SQL injection, XSS, broken auth |
| **P2** | Medium - Fix within 1-2 weeks | Outdated dependencies, missing encryption |
| **P3** | Low - Fix within 1 month | License violations, code quality issues |

**Validation Rules**:
- `id` must be unique across all findings in audit
- `severity` must be one of P0, P1, P2, P3
- `evidence` array must have at least 1 item
- `createdAt` must be within audit timeframe

---

### Evidence

Proof artifact for a finding.

**Fields**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| type | string | ✅ | Evidence type (scan-output, code-snippet, screenshot) |
| content | string? | ❌ | Text content (for scan-output) |
| file | string? | ❌ | File path (for code-snippet) |
| line | number? | ❌ | Line number (for code-snippet) |
| tool | string | ✅ | Tool that generated evidence |
| timestamp | Date | ✅ | Evidence collection time |

**Validation Rules**:
- Either `content` OR `file` must be present
- `line` only valid when `file` is present
- `tool` must match one of: npm-audit, gitleaks, semgrep, license-checker

---

### TechStack

Detected technology stack of the audited repository.

**Fields**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| language | string | ✅ | Primary language (nodejs, python, go, unknown) |
| frameworks | string[] | ✅ | Detected frameworks |
| hasPayments | boolean | ✅ | Whether payment processing detected |
| hasPII | boolean | ✅ | Whether PII handling detected |
| packageManager | string | ✅ | Package manager (npm, yarn, pnpm, pip) |
| database | string? | ❌ | Database type if detected |

**Detection Rules**:
- Check `package.json` for Node.js
- Check `requirements.txt` for Python
- Check `go.mod` for Go
- Detect Stripe/Braintree for payments
- Detect email/password fields for PII

---

### ScopeDocument

Defines the audit scope and boundaries.

**Fields**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| repoUrl | string | ✅ | Repository being audited |
| techStack | TechStack | ✅ | Detected tech stack |
| securityLevel | 1 \| 2 \| 3 | ✅ | Security classification |
| frameworks | ComplianceFramework[] | ✅ | Applicable compliance frameworks |
| inScope | string[] | ✅ | Audit domains included |
| outOfScope | string[] | ✅ | Audit domains excluded |
| createdAt | Date | ✅ | Scope definition timestamp |

**Security Level Classification**:

| Level | Criteria | Implications |
|-------|----------|--------------|
| **1** | No payments, no PII | Standard audit |
| **2** | PII detected | GDPR compliance required |
| **3** | Payments detected | PCI-DSS compliance required |

---

### ComplianceMap

Maps findings to compliance framework controls.

**Fields**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| framework | ComplianceFramework | ✅ | Compliance framework name |
| controls | Control[] | ✅ | List of controls |
| overallScore | number | ✅ | Compliance score (0-100) |

**Compliance Framework Types**:
- ISO27001
- SOC2
- PCI-DSS
- GDPR
- HIPAA
- OWASP-ASVS

---

### Control

Individual compliance control.

**Fields**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| id | string | ✅ | Control identifier (e.g., A.8.1.1) |
| title | string | ✅ | Control title |
| category | string | ✅ | Control category |
| status | 'compliant' \| 'non-compliant' \| 'unverified' | ✅ | Compliance status |
| evidence | string[] | ❌ | Related finding IDs |

---

### AuditStatus

Workflow status enum.

**Values**:
- `Created` — Workflow initialized
- `Discovery` — Detecting tech stack
- `Scanning` — Running security scans
- `Reviewing` — AI code review
- `Compliance` — Mapping to frameworks
- `Validation` — Cross-validation
- `Waiting for P0 Approval` — Paused for human input
- `Reporting` — Generating report
- `Completed` — Audit finished successfully
- `Failed` — Audit failed

---

### AuditInput

Input for starting a new audit.

**Fields**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| repoUrl | string | ✅ | GitHub repository URL |
| frameworks | ComplianceFramework[] | ❌ | Compliance frameworks (default: OWASP-ASVS) |
| scope | 'full' \| 'security' \| 'compliance' | ❌ | Audit scope type (default: full) |
| skipApproval | boolean | ❌ | Skip P0 approval (default: false) |
| outputDir | string | ❌ | Output directory (default: /tmp/audit-<id>) |

---

### AuditResult

Final audit result.

**Fields**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| workflowId | string | ✅ | Workflow ID |
| reportPath | string | ✅ | Path to audit report |
| evidencePath | string | ✅ | Path to evidence directory |
| findings | Finding[] | ✅ | All findings |
| duration | number | ✅ | Audit duration in milliseconds |
| summary | AuditSummary | ✅ | High-level summary |

---

## Relationships

```
Audit
  ├── 1 TechStack
  ├── 1 ScopeDocument
  ├── N Finding
  │    ├── N Evidence
  │    └── 1 Remediation
  ├── N ComplianceMap
  │    └── N Control
  └── 1 AuditResult
       └── 1 AuditSummary
```

---

## File Structure

```
/tmp/audit-<workflow-id>/
├── audit-report.md           # Main report
├── npm-audit.json            # Raw npm audit output
├── gitleaks-report.json      # Raw gitleaks output
├── semgrep-report.json       # Raw semgrep output
├── licenses.json             # Raw license check output
└── evidence/                 # Evidence per finding
    ├── NPM-1.json
    ├── LEAK-1.json
    └── ...
```

---

## Index Recommendations

**Workflow Queries** (Temporal):
- Query by workflow ID: `statusQuery`, `findingsQuery`
- Filter by severity: Client-side filtering of findings array

**Future Database Indexes** (if persistence added):
- `workflowId` (primary key)
- `repoUrl` (index for history lookup)
- `startTime` (index for time-based queries)
- `severity` (index for finding prioritization)