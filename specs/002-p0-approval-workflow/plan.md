# Technical Design: P0 Approval Workflow

**Feature**: 002-p0-approval-workflow
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
| **Primary Dependency** | @temporalio/workflow | Signals, conditions |

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Temporal Workflow                      │
│                                                           │
│  ┌──────────┐    ┌──────────┐    ┌──────────────────┐   │
│  │ Scanning │───▶│ Review   │───▶│ P0 Approval Gate │   │
│  │ Phase    │    │ Phase    │    │ (condition)       │   │
│  └──────────┘    └──────────┘    └─────────┬────────┘   │
│                                             │             │
│                     ┌───────────────────────┤             │
│                     │                       │             │
│              ┌──────▼──────┐         ┌──────▼──────┐     │
│              │  Approved   │         │  Rejected   │     │
│              │  (signal)   │         │  (signal)   │     │
│              └──────┬──────┘         └──────┬──────┘     │
│                     │                       │             │
│              ┌──────▼──────┐         ┌──────▼──────┐     │
│              │  Reporting  │         │   Failed    │     │
│              │  Phase      │         │   State     │     │
│              └─────────────┘         └─────────────┘     │
│                                                           │
└─────────────────────────────────────────────────────────┘
         ▲                              ▲
         │                              │
    ┌────┴────┐                   ┌────┴────┐
    │ Client  │                   │ Client  │
    │ (start) │                   │(signal) │
    └─────────┘                   └─────────┘
```

---

## Implementation Plan

### 1. Workflow Changes

**File**: `src/workflows/index.ts`

```typescript
// Add approval gate after reviewing phase
const p0Findings = findings.filter(f => f.severity === 'P0');

if (p0Findings.length > 0 && !input.skipApproval) {
  // Wait for approval signal
  const approval = await waitForApproval(p0Findings, input.deadline);
  
  if (!approval.approved) {
    throw new ApplicationFailure('P0 findings rejected', true);
  }
}
```

### 2. Approval Signal Handler

**File**: `src/workflows/approval.ts`

```typescript
export async function waitForApproval(
  p0Findings: Finding[],
  deadline?: string
): Promise<ApprovalResult> {
  let approved: boolean | undefined;
  
  // Set up signal handler
  setHandler(approvalSignal, (decision: boolean) => {
    approved = decision;
  });
  
  // Wait for signal or timeout
  await condition(() => approved !== undefined, deadline || '24h');
  
  return { approved: approved ?? false };
}
```

### 3. Client Signal Method

**File**: `src/client/approval.ts`

```typescript
export async function sendApproval(
  workflowId: string,
  approved: boolean
): Promise<void> {
  const handle = await client.getHandle(workflowId);
  await handle.signal(approvalSignal, approved);
}
```

---

## Data Model

### ApprovalSignal

```typescript
interface ApprovalSignal {
  workflowId: string;
  approved: boolean;
  user: string;
  timestamp: Date;
  notes?: string;
}
```

### ApprovalState

```typescript
interface ApprovalState {
  status: 'pending' | 'approved' | 'rejected' | 'timeout';
  p0Findings: Finding[];
  decision?: ApprovalSignal;
  timeoutAt?: Date;
}
```

---

## API Contracts

### Signal: approve

```yaml
signal: approve
input:
  type: boolean
  description: true = approved, false = rejected
```

### Query: approval-status

```yaml
query: approval-status
output:
  type: ApprovalState
```

---

## Tests

### Integration Tests

1. **P0 detected → workflow pauses**
   - Start workflow with P0-producing repo
   - Verify workflow state = 'awaiting-approval'

2. **Approval sent → workflow continues**
   - Send approval signal
   - Verify workflow proceeds to reporting

3. **Rejection sent → workflow fails**
   - Send rejection signal
   - Verify workflow fails with rejection message

4. **Timeout → workflow fails**
   - Start workflow with short timeout
   - Verify workflow fails after timeout

### BDD Scenarios

```gherkin
Feature: P0 Approval Workflow

  Scenario: Pause on P0 findings
    Given an audit finds P0 vulnerabilities
    When the reviewing phase completes
    Then the workflow pauses for approval

  Scenario: Approve and continue
    Given the workflow is paused for approval
    When I send approval signal true
    Then the workflow proceeds to reporting

  Scenario: Reject and stop
    Given the workflow is paused for approval
    When I send approval signal false
    Then the workflow stops with rejected status
```

---

## Effort Estimate

| Task | Hours | Priority |
|------|-------|----------|
| Workflow approval gate | 2 | P1 |
| Signal handler | 1 | P1 |
| Client signal method | 1 | P1 |
| Tests | 2 | P1 |
| **Total** | **6** | - |

---

## Dependencies

- Temporal SDK signals
- Existing workflow structure
- Finding type with severity field

---

## Risks

| Risk | Mitigation |
|------|------------|
| Signal lost | Use durable signals with Temporal |
| Timeout handling | Configurable timeout with clear error |
| Multiple signals | Only first signal processed |