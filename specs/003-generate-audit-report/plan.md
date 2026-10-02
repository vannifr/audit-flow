# Technical Design: Generate Audit Report

**Feature**: 003-generate-audit-report
**Created**: 2026-10-02
**Status**: Planned

---

## Technical Context

| Aspect | Decision | Rationale |
|--------|----------|-----------|
| **Language** | TypeScript 5.x | Existing codebase |
| **Runtime** | Node.js 20 LTS | Temporal SDK compatibility |
| **Framework** | Temporal.io | Durable workflow orchestration |
| **Testing** | Vitest | Existing test framework |
| **Report Format** | Markdown | Human-readable, version-controllable |
| **Evidence Storage** | File system | Simple, portable |

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Reporting Phase                        │
│                                                           │
│  ┌──────────────────┐    ┌──────────────────┐           │
│  │ Collect Findings │───▶│ Generate Report  │           │
│  │                  │    │                  │           │
│  └──────────────────┘    └────────┬─────────┘           │
│                                   │                      │
│                     ┌─────────────┼─────────────┐       │
│                     │             │             │       │
│              ┌──────▼──────┐ ┌────▼────┐ ┌─────▼─────┐ │
│              │ Markdown    │ │ Evidence│ │ Compliance│ │
│              │ Report      │ │ Bundle  │ │ Mapping   │ │
│              │ .md file    │ │ /evidence│ │ Report    │ │
│              └─────────────┘ └─────────┘ └───────────┘ │
│                                                           │
└─────────────────────────────────────────────────────────┘
```

---

## Implementation Plan

### 1. Report Generator Activity

**File**: `src/activities/report.ts`

```typescript
export async function generateReport(input: ReportInput): Promise<ReportOutput> {
  const { repoUrl, findings, complianceMaps, outputDir } = input;
  
  // Create output directory
  const reportDir = path.join(outputDir, 'report');
  const evidenceDir = path.join(outputDir, 'evidence');
  
  // Generate report sections
  const sections = [
    generateExecutiveSummary(findings),
    generateMethodology(),
    generateFindingsTable(findings),
    generateComplianceSection(complianceMaps),
    generateRecommendations(findings),
  ];
  
  // Write report
  const reportPath = path.join(reportDir, 'audit-report.md');
  writeFileSync(reportPath, sections.join('\n\n'));
  
  // Collect evidence
  await collectEvidence(findings, evidenceDir);
  
  return { reportPath, evidencePath: evidenceDir };
}
```

### 2. Report Sections

**Executive Summary**
- Total findings by severity
- Risk level (Critical/High/Medium/Low)
- Key recommendations

**Methodology**
- Tools used
- Standards applied
- Scope

**Findings Table**
- ID, Title, Severity, Category, Evidence link

**Compliance Mapping**
- Framework (ISO27001, OWASP-ASVS)
- Control coverage
- Gaps

**Recommendations**
- Prioritized by severity
- Effort estimates

---

## Data Model

### ReportInput

```typescript
interface ReportInput {
  repoUrl: string;
  workflowId: string;
  techStack: TechStack;
  scope: ScopeDocument;
  findings: Finding[];
  complianceMaps: ComplianceMap[];
  outputDir: string;
}
```

### ReportOutput

```typescript
interface ReportOutput {
  reportPath: string;
  evidencePath: string;
  findingCount: number;
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
}
```

---

## Report Template

```markdown
# Security Audit Report

**Repository**: {repoUrl}
**Date**: {date}
**Workflow ID**: {workflowId}

## Executive Summary

**Total Findings**: {count}
**Risk Level**: {riskLevel}

| Severity | Count |
|----------|-------|
| P0 (Critical) | {p0} |
| P1 (High) | {p1} |
| P2 (Medium) | {p2} |
| P3 (Low) | {p3} |

## Methodology

**Tools**: npm audit, gitleaks, semgrep, lighthouse
**Standards**: ISO27001, OWASP-ASVS
**Scope**: Full security audit

## Findings

| ID | Title | Severity | Category |
|----|-------|----------|----------|
{findings_table}

## Compliance Mapping

### ISO27001

| Control | Status | Evidence |
|---------|--------|----------|
{iso_controls}

## Recommendations

{recommendations}

## Evidence

Evidence artifacts collected at: `{evidencePath}`
```

---

## Tests

### Integration Tests

1. **Report generation**
   - Complete audit workflow
   - Verify report file created
   - Verify all sections present

2. **Evidence collection**
   - Findings with evidence
   - Verify evidence files exist

3. **Compliance mapping**
   - ISO27001 controls
   - Verify mapping in report

### BDD Scenarios

```gherkin
Feature: Generate Audit Report

  Scenario: Generate complete report
    Given an audit completes successfully
    When the reporting phase runs
    Then a markdown report is generated
    And the report contains all required sections

  Scenario: Evidence collection
    Given findings with evidence
    When the report is generated
    Then evidence files are collected
    And evidence paths are linked in report
```

---

## Effort Estimate

| Task | Hours | Priority |
|------|-------|----------|
| Report generator | 3 | P1 |
| Template system | 2 | P1 |
| Evidence collector | 2 | P1 |
| Tests | 2 | P1 |
| **Total** | **9** | - |

---

## Dependencies

- Finding type with evidence
- ComplianceMap type
- File system access

---

## Risks

| Risk | Mitigation |
|------|------------|
| Large reports | Section splitting, summary mode |
| Evidence size | Compress large files |
| Template changes | Versioned templates |