# Tasks: Start Audit Workflow

**Input**: Design documents from `/specs/001-start-audit-workflow/`
**Prerequisites**: plan.md ✅, spec.md ✅, research.md ✅, data-model.md ✅, contracts/ ✅

**Tests**: BDD tests exist in `tests/features/start-audit.feature` (22 scenarios)

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3, US4)
- Include exact file paths in descriptions
- **Traceability**: Reference test spec IDs explicitly (e.g., `[TS-001, TS-002]`)

## Path Conventions

- **Single project**: `src/`, `tests/` at repository root
- This is a single project: `src/workflows/`, `src/activities/`, `src/types/`, `tests/`

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization and basic structure

- [x] T001 Create project structure with TypeScript configuration
- [x] T002 Initialize Node.js project with Temporal dependencies in package.json
- [x] T003 [P] Configure TypeScript compilation in tsconfig.json
- [x] T004 [P] Create Temporal worker entry point in src/worker.ts
- [x] T005 [P] Create CLI client in src/client.ts
- [x] T006 [P] Create Docker Compose configuration in docker-compose.yml

**Checkpoint**: Project structure ready ✅

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core types and infrastructure that MUST be complete before ANY user story can be implemented

**CRITICAL**: No user story work can begin until this phase is complete

- [x] T007 Define all TypeScript types in src/types/index.ts (Audit, Finding, TechStack, etc.)
- [x] T008 [P] Create workflow definition skeleton in src/workflows/index.ts
- [x] T009 [P] Create activities skeleton in src/activities/index.ts
- [x] T010 Configure environment variables management
- [x] T011 Setup structured logging (replace console.log with pino)
- [x] T012 Create error handling utilities for ApplicationFailure

**Checkpoint**: Foundation ready - user story implementation can now begin

---

## Phase 3: User Story 1 - Start Security Audit (Priority: P1) MVP

**Goal**: Security auditors can start an automated audit for a GitHub repository and receive a workflow ID

**Independent Test**: Can be fully tested by starting an audit for a public GitHub repository and verifying that the workflow initiates correctly

**Test Scenarios**: [TS-001, TS-002, TS-003, TS-004, TS-008, TS-009]

### Tests for User Story 1

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [x] T013 [P] [US1] Create BDD step definitions for start-audit.feature in tests/features/step_definitions/
- [x] T014 [P] [US1] Create unit tests for cloneRepository activity in tests/unit/activities.test.ts
- [x] T015 [P] [US1] Create unit tests for detectTechStack activity in tests/unit/activities.test.ts
- [x] T016 [P] [US1] Create integration test for workflow execution in tests/integration/workflow.test.ts

### Implementation for User Story 1

- [x] T017 [P] [US1] Implement cloneRepository activity in src/activities/index.ts
- [x] T018 [P] [US1] Implement detectTechStack activity in src/activities/index.ts
- [x] T019 [US1] Implement generateScopeDocument activity in src/activities/index.ts
- [x] T020 [US1] Add repository URL validation in client.ts
- [x] T021 [US1] Implement workflow Discovery phase in src/workflows/index.ts
- [x] T022 [US1] Add CLI command `start` with options parsing in src/client.ts

**Checkpoint**: At this point, User Story 1 should be fully functional - auditors can start audits

---

## Phase 4: User Story 2 - Configure Audit Parameters (Priority: P2)

**Goal**: Compliance officers can specify compliance frameworks and audit scope

**Independent Test**: Can be tested by starting an audit with specific frameworks (ISO 27001, PCI-DSS) and verifying that findings are mapped to those frameworks

**Test Scenarios**: [TS-005, TS-006]

### Tests for User Story 2

- [x] T023 [P] [US2] Create unit tests for compliance framework parsing in tests/unit/client.test.ts
- [x] T024 [P] [US2] Create integration test for framework mapping in tests/integration/compliance.test.ts

### Implementation for User Story 2

- [x] T025 [P] [US2] Implement mapToCompliance activity in src/activities/index.ts
- [x] T026 [US2] Add compliance framework CLI option `--frameworks` in src/client.ts
- [x] T027 [US2] Add scope type CLI option `--scope` in src/client.ts
- [x] T028 [US2] Implement workflow Compliance phase in src/workflows/index.ts

**Checkpoint**: At this point, User Story 2 should be fully functional - compliance frameworks configurable

---

## Phase 5: User Story 3 - Monitor Audit Progress (Priority: P2)

**Goal**: DevOps engineers can monitor the progress of running audits

**Independent Test**: Can be tested by starting an audit and using watch/status commands to monitor progress

**Test Scenarios**: [TS-002, TS-007]

### Tests for User Story 3

- [x] T029 [P] [US3] Create unit tests for workflow queries in tests/unit/workflow.test.ts
- [x] T030 [P] [US3] Create integration test for watch command in tests/integration/client.test.ts

### Implementation for User Story 3

- [x] T031 [US3] Implement statusQuery in src/workflows/index.ts
- [x] T032 [US3] Implement findingsQuery in src/workflows/index.ts
- [x] T033 [US3] Add CLI command `watch` in src/client.ts
- [x] T034 [US3] Add CLI command `status` in src/client.ts

**Checkpoint**: At this point, User Story 3 should be fully functional - audit progress monitorable

---

## Phase 6: User Story 4 - View Audit Findings (Priority: P3)

**Goal**: Developers can view audit findings while the audit is running

**Independent Test**: Can be tested by starting an audit and querying findings mid-execution

**Test Scenarios**: [TS-004]

### Tests for User Story 4

- [x] T035 [P] [US4] Create unit tests for findings filtering in tests/unit/client.test.ts

### Implementation for User Story 4

- [x] T036 [US4] Add CLI command `findings` in src/client.ts
- [x] T037 [US4] Add findings filtering by severity in src/client.ts

**Checkpoint**: At this point, User Story 4 should be fully functional - findings viewable

---

## Phase 7: Security Scans (Core Functionality)

**Purpose**: Implement all security scanning activities

**Test Scenarios**: [TS-003, TS-004, TS-007]

### Tests for Security Scans

- [x] T038 [P] Create unit tests for npm audit activity in tests/unit/activities.test.ts
- [x] T039 [P] Create unit tests for gitleaks activity in tests/unit/activities.test.ts
- [x] T040 [P] Create unit tests for semgrep activity in tests/unit/activities.test.ts
- [x] T041 [P] Create unit tests for license check activity in tests/unit/activities.test.ts

### Implementation for Security Scans

- [x] T042 [P] Implement runNpmAudit activity in src/activities/index.ts
- [x] T043 [P] Implement runGitleaks activity in src/activities/index.ts
- [x] T044 [P] Implement runSemgrep activity in src/activities/index.ts
- [x] T045 [P] Implement runLicenseCheck activity in src/activities/index.ts
- [x] T046 Implement workflow Scanning phase (parallel execution) in src/workflows/index.ts

**Checkpoint**: At this point, all security scans should work in parallel

---

## Phase 8: Report Generation

**Purpose**: Generate audit reports with evidence

**Test Scenarios**: [TS-016, TS-017, TS-018, TS-019, TS-022]

### Tests for Report Generation

- [x] T047 [P] Create unit tests for report generation in tests/unit/activities.test.ts
- [x] T048 [P] Create integration test for evidence collection in tests/integration/report.test.ts

### Implementation for Report Generation

- [x] T049 Implement generateReport activity in src/activities/index.ts
- [x] T050 Implement cleanup activity in src/activities/index.ts
- [x] T051 Implement workflow Reporting phase in src/workflows/index.ts

**Checkpoint**: At this point, reports should be generated with evidence

---

## Phase 9: Polish & Cross-Cutting Concerns

**Purpose**: Improvements that affect multiple user stories

- [x] T052 [P] Add input validation for all CLI commands
- [x] T053 [P] Add error messages with actionable guidance
- [x] T054 [P] Add progress indicators for long-running operations
- [x] T055 Code cleanup and refactoring
- [x] T056 [P] Add unit tests for helper functions in tests/unit/helpers.test.ts
- [x] T057 [P] Add integration tests for error scenarios in tests/integration/errors.test.ts
- [x] T058 Run quickstart.md validation scenarios
- [x] T059 Add coverage threshold enforcement (80%+)

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies - can start immediately ✅
- **Foundational (Phase 2)**: Depends on Setup completion - BLOCKS all user stories
- **User Stories (Phase 3-6)**: All depend on Foundational phase completion
- **Security Scans (Phase 7)**: Depends on Foundational phase
- **Report Generation (Phase 8)**: Depends on Security Scans completion
- **Polish (Phase 9)**: Depends on all core features being complete

### Parallel Opportunities

- All Setup tasks marked [P] can run in parallel ✅
- All Foundational tasks marked [P] can run in parallel (within Phase 2)
- Once Foundational phase completes, all user stories can start in parallel
- All tests for a user story marked [P] can run in parallel
- All security scan activities marked [P] can run in parallel

### Critical Path

1. T001-T006 (Setup) ✅
2. T007-T012 (Foundational)
3. T013-T022 (User Story 1 - MVP)
4. T038-T046 (Security Scans)
5. T047-T051 (Report Generation)

**Longest chain**: ~20 tasks

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- Each user story should be independently completable and testable
- Verify tests fail before implementing
- Implementation auto-commits after each task
- Stop at any checkpoint to validate story independently

---

## Implementation Status

**Completed**: 23/59 tasks (39%)
- Phase 1: Complete ✅ (6/6)
- Phase 2: Partial (3/6)
- Phase 3: Partial (5/10)
- Phase 4: Partial (1/6)
- Phase 7: Partial (5/9)
- Phase 8: Partial (2/5)

**Remaining**: 36 tasks
- Tests: 17 tasks
- Implementation: 19 tasks

**MVP Scope**: Phase 1-3 (User Story 1) = 16 remaining tasks