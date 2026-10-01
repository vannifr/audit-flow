# Feature Specification: Start Audit Workflow

**Feature Branch**: `001-start-audit-workflow`
**Created**: 2026-10-01
**Status**: Draft
**Input**: User description: "Start audit workflow for a repository"

## User Stories *(mandatory)*

### User Story 1 - Start Security Audit (Priority: P1)

**As a security auditor**, I want to start an automated security audit for a code repository so that I can identify security vulnerabilities and compliance issues.

**Why this priority**: This is the core functionality - without it, the system provides no value. Auditors must be able to initiate audits to do their job.

**Independent Test**: Can be fully tested by starting an audit for a public GitHub repository and verifying that the workflow initiates correctly.

**Acceptance Scenarios**:

1. **Given** I have a valid GitHub repository URL, **When** I start an audit with default settings, **Then** the system initiates a new audit workflow and returns a workflow ID
2. **Given** I have started an audit, **When** I check the status, **Then** the system shows the current phase (Discovery, Scanning, Reviewing, etc.)
3. **Given** an audit is running, **When** the Discovery phase completes, **Then** the system detects the tech stack and generates the audit scope

---

### User Story 2 - Configure Audit Parameters (Priority: P2)

**As a compliance officer**, I want to specify compliance frameworks and audit scope so that the audit focuses on relevant requirements for my organization.

**Why this priority**: Allows customization for different compliance needs. Not critical for MVP but essential for enterprise use.

**Independent Test**: Can be tested by starting an audit with specific frameworks (ISO 27001, PCI-DSS) and verifying that findings are mapped to those frameworks.

**Acceptance Scenarios**:

1. **Given** I want ISO 27001 compliance, **When** I start an audit with `--frameworks ISO27001`, **Then** the system maps all findings to ISO 27001 controls
2. **Given** I want multiple frameworks, **When** I specify `--frameworks ISO27001,PCI-DSS,GDPR`, **Then** the system maps findings to all specified frameworks
3. **Given** I only want security scanning, **When** I specify `--scope security`, **Then** the system skips compliance mapping and focuses on security scans

---

### User Story 3 - Monitor Audit Progress (Priority: P2)

**As a DevOps engineer**, I want to monitor the progress of running audits so that I can track completion and identify issues.

**Why this priority**: Essential for operational visibility. Users need to know if audits are progressing or stuck.

**Independent Test**: Can be tested by starting an audit and using watch/status commands to monitor progress.

**Acceptance Scenarios**:

1. **Given** an audit is running, **When** I run the watch command, **Then** the system displays real-time phase updates
2. **Given** an audit encounters an error, **When** I check the status, **Then** the system shows the error details and failed phase
3. **Given** an audit completes, **When** I query the result, **Then** the system returns the report path and summary

---

### User Story 4 - View Audit Findings (Priority: P3)

**As a developer**, I want to view audit findings while the audit is running so that I can start addressing issues immediately.

**Why this priority**: Convenience feature that improves workflow but not critical for MVP.

**Independent Test**: Can be tested by starting an audit and querying findings mid-execution.

**Acceptance Scenarios**:

1. **Given** an audit has found vulnerabilities, **When** I query findings, **Then** the system returns a prioritized list (P0, P1, P2, P3)
2. **Given** no findings yet, **When** I query findings, **Then** the system returns an empty list
3. **Given** multiple findings exist, **When** I query by severity, **Then** the system filters results appropriately

---

### Edge Cases

- What happens when the repository URL is invalid or inaccessible?
- How does the system handle a repository that requires authentication?
- What happens when the repository is extremely large (10GB+)?
- How does the system handle rate limiting from GitHub API?
- What happens when Temporal server is unavailable?
- How does the system handle activity timeouts or failures?

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST accept a GitHub repository URL as input
- **FR-002**: System MUST validate the repository URL format and accessibility
- **FR-003**: System MUST clone the repository to a temporary location for analysis
- **FR-004**: System MUST detect the technology stack (languages, frameworks, dependencies)
- **FR-005**: System MUST run security scans in parallel (npm audit, gitleaks, semgrep, license check)
- **FR-006**: System MUST generate a unique workflow ID for each audit
- **FR-007**: System MUST persist audit state in Temporal workflow
- **FR-008**: System MUST support optional compliance framework specification
- **FR-009**: System MUST map findings to specified compliance frameworks
- **FR-010**: System MUST provide real-time status updates via Temporal queries
- **FR-011**: System MUST generate audit report upon completion
- **FR-012**: System MUST collect evidence for each finding
- **FR-013**: System MUST handle failures gracefully with retry logic
- **FR-014**: System MUST enforce timeouts for all activities
- **FR-015**: System MUST clean up temporary resources after completion

### Key Entities

- **Audit**: Represents a complete security audit of a repository; attributes include workflow ID, repository URL, status, start time, end time, findings count
- **Finding**: Represents an identified security issue; attributes include ID, severity (P0-P3), title, description, evidence path, compliance mappings
- **Evidence**: Proof artifact for a finding; attributes include file path, scan type, raw data, timestamp
- **Workflow**: Temporal workflow instance; attributes include workflow ID, status, current phase, signals, queries
- **Activity**: Atomic audit task; attributes include activity type, input, output, duration, retries

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Audit workflow starts within 5 seconds of request
- **SC-002**: System handles repositories up to 5GB in size
- **SC-003**: Discovery phase completes within 2 minutes for typical repositories
- **SC-004**: Security scans complete within 15 minutes for repositories with <1000 dependencies
- **SC-005**: Status queries return within 100ms
- **SC-006**: 99% of initiated audits complete successfully (excluding external failures)
- **SC-007**: Audit reports generated with evidence for 100% of findings
- **SC-008**: System handles 10 concurrent audits without degradation