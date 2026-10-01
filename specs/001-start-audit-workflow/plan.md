# Implementation Plan: Start Audit Workflow

**Branch**: `001-start-audit-workflow` | **Date**: 2026-10-01 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/001-start-audit-workflow/spec.md`

## Summary

Implement Temporal-based workflow for automated security audits. The workflow orchestrates multiple security scans (npm audit, gitleaks, semgrep, license check) in parallel, detects tech stack, maps findings to compliance frameworks, and generates audit reports with evidence.

**Primary requirement**: Security auditors can start an automated audit for a GitHub repository and receive a comprehensive report with findings, evidence, and compliance mappings.

**Technical approach**: Temporal.io workflow with 6 phases (Discovery, Scanning, Reviewing, Compliance, Validation, Reporting), human-in-the-loop signals for P0 approval, and persistent state management.

## Technical Context

**Language/Version**: TypeScript 5.x, Node.js 22
**Primary Dependencies**: @temporalio/workflow, @temporalio/activity, @temporalio/worker, @temporalio/client
**Storage**: File system (temporary for audit artifacts), Temporal server (workflow state)
**Testing**: Vitest (unit tests), Playwright (E2E tests), Cucumber.js (BDD tests)
**Target Platform**: Linux server (Docker container), Temporal Cloud or self-hosted
**Project Type**: Single project (CLI + worker)
**Performance Goals**:
- Audit workflow starts within 5 seconds
- Discovery phase completes within 2 minutes
- Security scans complete within 15 minutes for <1000 dependencies
**Constraints**:
- 8 hour maximum workflow timeout
- 4 concurrent scans maximum
- 3 retry attempts per activity
**Scale/Scope**:
- 10 concurrent audits
- Repositories up to 5GB
- Findings up to 1000 per audit

## Constitution Check

✅ **Security-First**: All code passes security scanning before merge
✅ **TDD**: Tests written before implementation (BDD scenarios exist)
✅ **Enterprise Compliance**: ISO 27001, SOC 2, PCI-DSS, GDPR support
✅ **Traceability**: Spec → Plan → Tasks → Tests → Code → Evidence
✅ **Quality Gates**: TypeScript compilation, tests, coverage 80%+

## Project Structure

### Documentation (this feature)

```text
specs/001-start-audit-workflow/
  spec.md              # Feature specification (complete)
  plan.md              # This file
  research.md          # Technology research
  data-model.md        # Data entities and validation
  quickstart.md        # Test scenarios
  contracts/           # API contracts
  tasks.md             # Implementation tasks (later)
  tests/features/      # BDD scenarios (complete)
```

### Source Code (repository root)

```text
audit-orchestration/
  src/
    workflows/
      index.ts         # Main workflow definition
    activities/
      index.ts         # Activity implementations
    types/
      index.ts         # TypeScript types
    worker.ts          # Temporal worker
    client.ts          # CLI client

  tests/
    unit/              # Unit tests (to be created)
    integration/       # Integration tests (to be created)
    features/          # BDD step definitions (to be created)

  package.json
  tsconfig.json
  docker-compose.yml
```

**Structure Decision**: Single project structure chosen because this is a CLI + worker application without separate frontend/backend components.

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| N/A | No violations | All constitutional principles satisfied |

## Phase Separation

**Governance content**: See CONSTITUTION.md for coding standards, quality gates, and security requirements.

**Implementation details**: This plan focuses on technical design only.

## Key Technical Decisions

### 1. Temporal.io for Orchestration

**Decision**: Use Temporal.io for workflow orchestration.

**Rationale**:
- Durable execution with state persistence
- Built-in retry logic and timeout handling
- Human-in-the-loop via signals
- Query support for real-time status
- Open source (MIT license)
- Production-proven at scale

**Alternatives considered**:
- AWS Step Functions: Proprietary, vendor lock-in
- Apache Airflow: Batch-oriented, not suitable for interactive workflows
- Custom state machine: Reinventing the wheel, no persistence

### 2. Parallel Security Scans

**Decision**: Run npm audit, gitleaks, semgrep, license check in parallel.

**Rationale**:
- Independent scans can run concurrently
- Reduces total audit time from ~60min to ~15min
- Temporal supports parallel activity execution
- Max 4 concurrent scans prevents resource exhaustion

### 3. Human-in-the-Loop for P0 Findings

**Decision**: Pause workflow for human approval when P0 findings detected.

**Rationale**:
- Critical findings require human judgment
- Temporal signals provide async approval mechanism
- 24-hour timeout prevents indefinite blocking
- Compliance requirement for enterprise audits

### 4. Evidence Collection

**Decision**: Store evidence as JSON files per finding.

**Rationale**:
- Traceability requirement from CONSTITUTION.md
- Evidence needed for compliance audits
- JSON format enables programmatic processing
- File storage keeps implementation simple

## API Contracts

### Workflow Signals

```typescript
// P0 Approval
export const p0ApprovalSignal = defineSignal<[boolean]>('p0-approval');
// Input: true (approve) or false (reject)
// Effect: Resumes or stops workflow

// Scope Change
export const scopeChangeSignal = defineSignal<[ScopeDocument]>('scope-change');
// Input: Updated scope document
// Effect: Updates audit scope mid-execution
```

### Workflow Queries

```typescript
// Status Query
export const statusQuery = defineQuery<AuditStatus>('status');
// Returns: Current workflow phase and state

// Findings Query
export const findingsQuery = defineQuery<Finding[]>('findings');
// Returns: List of findings discovered so far

// State Query
export const stateQuery = defineQuery<AuditState>('state');
// Returns: Complete workflow state
```

### CLI Commands

```bash
# Start audit
npm run workflow -- start <repo-url> [--frameworks <list>] [--scope <type>]

# Watch progress
npm run workflow -- watch <workflow-id>

# Approve P0
npm run workflow -- approve <workflow-id>

# Reject P0
npm run workflow -- reject <workflow-id>
```

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| Repository clone fails | Validate URL before workflow start, retry logic |
| Security scan timeouts | Per-activity timeouts, graceful degradation |
| Temporal server unavailable | Retry connection, health check before worker start |
| Large repository (>5GB) | Size check in Discovery phase, reject with clear message |
| Rate limiting (GitHub) | Implement exponential backoff, use authenticated requests |

## Dependencies

### Required Tools (External)

- **Temporal Server**: Version 1.20+ or Temporal Cloud
- **Node.js**: Version 18+ (v22 recommended)
- **Git**: For repository cloning
- **npm**: For npm audit
- **gitleaks**: For secret scanning
- **semgrep**: For SAST

### NPM Packages

```json
{
  "@temporalio/client": "^1.8.0",
  "@temporalio/worker": "^1.8.0",
  "@temporalio/workflow": "^1.8.0",
  "@temporalio/activity": "^1.8.0",
  "uuid": "^9.0.0"
}
```

## Next Steps

1. **Phase 0**: Research — Document technology choices and alternatives
2. **Phase 1**: Design — Create data models, contracts, quickstart guide
3. **Phase 2**: Tasks — Generate implementation task breakdown
4. **Phase 3**: Implement — Build with TDD validation