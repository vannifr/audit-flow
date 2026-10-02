# Tasks: P0 Approval Workflow

**Feature**: 002-p0-approval-workflow
**Created**: 2026-10-02
**Status**: Implemented

---

## Phase 1: Workflow Changes

### Task 1.1: Add Approval Gate to Workflow
**Priority**: P1
**Estimate**: 2 hours
**Dependencies**: None
**Files**: `src/activities/index.ts`
**Description**: Add approval gate after reviewing phase that checks for P0 findings and waits for signal.

**Acceptance Criteria**:
- [x] Workflow pauses when P0 findings detected
- [x] Workflow proceeds directly when no P0 findings
- [x] Workflow respects --skip-approval flag

---

### Task 1.2: Create Approval Signal Handler
**Priority**: P1
**Estimate**: 1 hour
**Dependencies**: Task 1.1
**Files**: `src/activities/index.ts`
**Description**: Create waitForApproval function with signal handler and timeout.

**Acceptance Criteria**:
- [x] Signal handler accepts boolean approval
- [x] Timeout enforced at configurable duration
- [x] Returns ApprovalResult with decision

---

## Phase 2: Client Integration

### Task 2.1: Create Client Signal Method
**Priority**: P1
**Estimate**: 1 hour
**Dependencies**: Task 1.2
**Files**: `src/activities/index.ts`
**Description**: Create method to send approval signal to running workflow.

**Acceptance Criteria**:
- [x] sendApproval method works with workflowId
- [x] Supports both approve and reject
- [x] Returns success/error status

---

## Phase 3: Testing

### Task 3.1: Integration Tests
**Priority**: P1
**Estimate**: 2 hours
**Dependencies**: Tasks 1.1, 1.2, 2.1
**Files**: `tests/integration/new-domains.test.ts`
**Description**: Write integration tests for approval workflow.

**Acceptance Criteria**:
- [x] Test: P0 detected → workflow pauses
- [x] Test: Approval sent → workflow continues
- [x] Test: Rejection sent → workflow fails
- [x] Test: Timeout → workflow fails

---

## Summary

| Phase | Tasks | Estimate |
|-------|-------|----------|
| Workflow Changes | 2 | 3 hours |
| Client Integration | 1 | 1 hour |
| Testing | 1 | 2 hours |
| **Total** | **4** | **6 hours** |

---

## Implementation Notes

All activities implemented in `src/activities/index.ts`:
- `waitForHumanApproval` function at line 1642
- Auto-approves when no P0 findings
- Returns pending state for P0 findings requiring manual review