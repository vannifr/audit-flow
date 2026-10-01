# Feature Specification: Generate Audit Report

**Feature Branch**: `003-generate-audit-report`
**Created**: 2026-10-01
**Status**: Draft
**Input**: User description: "Generate comprehensive audit report with evidence"

## User Stories *(mandatory)*

### User Story 1 - Generate Markdown Report (Priority: P1)

**As a security auditor**, I want a comprehensive audit report in Markdown format so that I can review findings and present them to stakeholders.

**Why this priority**: The report is the primary deliverable of the audit. Without it, the audit has no output.

**Independent Test**: Can be tested by completing an audit and verifying the report is generated with all required sections.

**Acceptance Scenarios**:

1. **Given** an audit completes successfully, **When** the Reporting phase runs, **Then** the system generates a Markdown report at the specified path
2. **Given** a report is generated, **When** I open it, **Then** it contains: executive summary, methodology, findings by severity, compliance mappings, recommendations
3. **Given** findings exist, **When** the report is generated, **Then** each finding includes: ID, severity, title, description, evidence path, remediation

---

### User Story 2 - Collect Evidence Artifacts (Priority: P1)

**As a compliance officer**, I want evidence artifacts for each finding so that I can validate the audit results and demonstrate compliance.

**Why this priority**: Evidence is required for compliance audits. Without it, findings are not actionable.

**Independent Test**: Can be tested by checking that evidence files exist for each finding.

**Acceptance Scenarios**:

1. **Given** a finding is identified, **When** the report is generated, **Then** an evidence JSON file is created
2. **Given** an evidence file exists, **When** I open it, **Then** it contains: scan type, raw output, affected files, line numbers, timestamps
3. **Given** multiple scans run, **When** evidence is collected, **Then** each scan type produces separate evidence files

---

### User Story 3 - Export Compliance Report (Priority: P2)

**As a compliance officer**, I want compliance-specific reports for each framework so that I can demonstrate compliance to auditors.

**Why this priority**: Compliance reporting is essential for enterprise customers but can be derived from main report.

**Independent Test**: Can be tested by running audit with specific framework and checking compliance report output.

**Acceptance Scenarios**:

1. **Given** I specified ISO 27001, **When** the audit completes, **Then** a compliance report is generated with ISO 27001 control mappings
2. **Given** I specified multiple frameworks, **When** the audit completes, **Then** separate compliance reports are generated for each framework
3. **Given** a compliance report is generated, **When** I open it, **Then** it shows: control ID, control name, status (pass/fail), evidence

---

### User Story 4 - Archive Audit Artifacts (Priority: P3)

**As a security auditor**, I want all audit artifacts archived in a single location so that I can access them later for reference.

**Why this priority**: Convenience for audit trail and historical reference. Not critical for immediate use.

**Independent Test**: Can be tested by verifying all artifacts are collected in the output directory.

**Acceptance Scenarios**:

1. **Given** an audit completes, **When** I check the output directory, **Then** all artifacts are present: report, evidence, raw scan outputs, compliance reports
2. **Given** artifacts are archived, **When** I list the directory, **Then** it follows the structure: /tmp/audit-<id>/{report.md, evidence/, raw/, compliance/}

---

### Edge Cases

- What happens if the output directory is not writable?
- How does the system handle very large evidence files (>100MB)?
- What happens if report generation fails partway through?
- How are evidence files named to avoid collisions?

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST generate a Markdown audit report
- **FR-002**: System MUST include executive summary with finding counts by severity
- **FR-003**: System MUST document methodology and scope
- **FR-004**: System MUST list all findings with severity, description, remediation
- **FR-005**: System MUST map findings to compliance frameworks when specified
- **FR-006**: System MUST generate evidence JSON files for each finding
- **FR-007**: System MUST include raw scan outputs in evidence directory
- **FR-008**: System MUST generate compliance-specific reports per framework
- **FR-009**: System MUST use configurable output directory (default: /tmp/audit-<id>)
- **FR-010**: System MUST clean up temporary files after archiving
- **FR-011**: System MUST log report generation success/failure

### Key Entities

- **AuditReport**: Primary audit deliverable; attributes include path, summary, findings list, compliance mappings, timestamp
- **EvidenceFile**: Proof artifact for finding; attributes include finding ID, scan type, file path, format (JSON), size
- **ComplianceReport**: Framework-specific report; attributes include framework name, control mappings, pass/fail counts
- **OutputDirectory**: Archive location; attributes include path, structure, size, retention

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Report generated within 30 seconds of audit completion
- **SC-002**: 100% of findings have corresponding evidence files
- **SC-003**: Evidence files valid JSON format
- **SC-004**: Report file size under 10MB for typical audits
- **SC-005**: Compliance reports generated for all specified frameworks
- **SC-006**: Output directory follows documented structure 100% of the time