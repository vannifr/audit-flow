# Feature Specification: P0 Approval Workflow

**Feature Branch**: `002-p0-approval-workflow`
**Created**: 2026-10-01
**Status**: Draft
**Input**: User description: "Human approval for critical (P0) findings"

## User Stories *(mandatory)*

### User Story 1 - Pause for P0 Approval (Priority: P1)

**As a security auditor**, I want the workflow to pause automatically when critical (P0) findings are detected so that I can review and approve them before proceeding.

**Why this priority**: Critical findings require human judgment. This is the core value proposition of human-in-the-loop.

**Independent Test**: Can be tested by scanning a repository with known P0 vulnerabilities and verifying the workflow pauses.

**Acceptance Scenarios**:

1. **Given** P0 findings are detected, **When** the Reviewing phase completes, **Then** the workflow pauses and waits for approval signal
2. **Given** no P0 findings exist, **When** the Reviewing phase completes, **Then** the workflow proceeds directly to Reporting
3. **Given** the workflow is paused for approval, **When** I send approval signal (true), **Then** the workflow proceeds to Reporting

---

### User Story 2 - Reject and Stop (Priority: P2)

**As a security lead**, I want to reject P0 findings and stop the audit so that critical issues can be addressed before continuing.

**Why this priority**: Safety mechanism to prevent audits from proceeding when critical issues need immediate attention.

**Independent Test**: Can be tested by sending reject signal and verifying workflow stops.

**Acceptance Scenarios**:

1. **Given** the workflow is paused for approval, **When** I send reject signal (false), **Then** the workflow stops and marks the audit as failed
2. **Given** the workflow is rejected, **When** I check the status, **Then** the system shows "rejected" with P0 finding details

---

### User Story 3 - Skip Approval (Priority: P3)

**As a CI/CD pipeline**, I want to skip P0 approval for automated audits so that audits can run unattended.

**Why this priority**: Automation use case. Not critical for human-driven audits but useful for CI integration.

**Independent Test**: Can be tested by starting audit with --skip-approval flag.

**Acceptance Scenarios**:

1. **Given** I start an audit with --skip-approval, **When** P0 findings are detected, **Then** the workflow proceeds without pausing

---

### Edge Cases

- What happens if approval signal is never sent?
- How long does the workflow wait for approval?
- Can approval be revoked after being sent?
- What happens if multiple users send conflicting signals?

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST detect P0 severity findings during Reviewing phase
- **FR-002**: System MUST pause workflow execution when P0 findings exist (unless --skip-approval)
- **FR-003**: System MUST expose approval signal endpoint
- **FR-004**: System MUST accept approval signal (true/false) via Temporal signal
- **FR-005**: System MUST timeout after configurable wait period (default 24 hours)
- **FR-006**: System MUST log all approval decisions with timestamp and user
- **FR-007**: System MUST notify users when workflow is waiting for approval
- **FR-008**: System MUST allow query of approval status

### Key Entities

- **P0Finding**: Critical severity finding requiring approval; attributes include finding ID, title, severity, evidence
- **ApprovalSignal**: Human decision signal; attributes include approved (boolean), timestamp, user
- **ApprovalTimeout**: Maximum wait time for approval; attributes include duration, action on timeout

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Workflow pauses within 1 second of P0 detection
- **SC-002**: Approval signal processed within 500ms
- **SC-003**: 100% of P0 findings trigger approval workflow (when not skipped)
- **SC-004**: Timeout enforced at exactly configured duration