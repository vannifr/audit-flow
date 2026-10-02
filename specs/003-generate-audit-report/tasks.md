# Tasks: Generate Audit Report

**Feature**: 003-generate-audit-report
**Created**: 2026-10-02
**Status**: Implemented

---

## Phase 1: Report Generator

### Task 1.1: Create Report Generator Activity
**Priority**: P1
**Estimate**: 3 hours
**Dependencies**: None
**Files**: `src/activities/index.ts`
**Description**: Update generateReport activity with complete report generation logic.

**Acceptance Criteria**:
- [x] Report generated at specified path
- [x] All sections included (executive summary, methodology, findings, compliance, recommendations)
- [x] Report is valid Markdown

---

### Task 1.2: Create Report Template System
**Priority**: P1
**Estimate**: 2 hours
**Dependencies**: Task 1.1
**Files**: `src/activities/index.ts`
**Description**: Create reusable Markdown template for reports.

**Acceptance Criteria**:
- [x] Template supports all sections
- [x] Template supports variable substitution
- [x] Template is version-controlled

---

## Phase 2: Evidence Collection

### Task 2.1: Create Evidence Collector
**Priority**: P1
**Estimate**: 2 hours
**Dependencies**: Task 1.1
**Files**: `src/activities/index.ts`
**Description**: Create activity to collect and organize evidence files.

**Acceptance Criteria**:
- [x] Evidence files copied to output directory
- [x] Evidence paths linked in report
- [x] Large files handled

---

## Phase 3: Testing

### Task 3.1: Integration Tests
**Priority**: P1
**Estimate**: 2 hours
**Dependencies**: Tasks 1.1, 1.2, 2.1
**Files**: `tests/integration/activities-full.test.ts`
**Description**: Write integration tests for report generation.

**Acceptance Criteria**:
- [x] Test: Report generated with all sections
- [x] Test: Evidence collected
- [x] Test: Compliance mapping included

---

## Summary

| Phase | Tasks | Estimate |
|-------|-------|----------|
| Report Generator | 2 | 5 hours |
| Evidence Collection | 1 | 2 hours |
| Testing | 1 | 2 hours |
| **Total** | **4** | **9 hours** |

---

## Implementation Notes

All activities implemented in `src/activities/index.ts`:
- `generateReport` function at line 763
- Generates Markdown report with all sections
- Collects evidence files
- Maps findings to compliance frameworks