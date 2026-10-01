# Workflow API Contract

## Signals

### p0ApprovalSignal

**Purpose**: Human approval for P0 findings

**Input Type**: `boolean`

**Behavior**:
- `true` → Resume workflow, proceed to Reporting
- `false` → Stop workflow, mark as Failed

**Usage**:
```typescript
// Temporal client
await handle.signal(p0ApprovalSignal, true);
```

**Contract**:
- Signal MUST be sent when workflow status is "Waiting for P0 Approval"
- Signal MUST be processed within 500ms
- Signal MUST be logged with timestamp and decision

---

### scopeChangeSignal

**Purpose**: Update audit scope mid-execution

**Input Type**: `ScopeDocument`

**Behavior**:
- Updates `scope` field in workflow state
- Triggers re-evaluation of compliance frameworks

**Usage**:
```typescript
await handle.signal(scopeChangeSignal, updatedScope);
```

**Contract**:
- Signal MUST be sent before Reporting phase
- Signal MUST validate ScopeDocument schema
- Signal MUST NOT affect already-completed phases

---

## Queries

### statusQuery

**Purpose**: Get current workflow status

**Return Type**: `AuditStatus`

**Values**: `Created` | `Discovery` | `Scanning` | `Reviewing` | `Compliance` | `Validation` | `Waiting for P0 Approval` | `Reporting` | `Completed` | `Failed`

**Usage**:
```typescript
const status = await handle.query(statusQuery);
```

**Contract**:
- Query MUST return within 100ms
- Query MUST be side-effect free
- Query MUST reflect current workflow state

---

### findingsQuery

**Purpose**: Get all findings discovered so far

**Return Type**: `Finding[]`

**Usage**:
```typescript
const findings = await handle.query(findingsQuery);
```

**Contract**:
- Query MUST return within 100ms
- Query MUST be side-effect free
- Query MUST return findings from completed phases only

---

### stateQuery

**Purpose**: Get complete workflow state

**Return Type**: `AuditState`

**Usage**:
```typescript
const state = await handle.query(stateQuery);
```

**Contract**:
- Query MUST return within 100ms
- Query MUST be side-effect free
- Query MUST include all phases and findings

---

## CLI Commands

### start

**Command**: `npm run workflow -- start <repo-url> [options]`

**Options**:
- `--frameworks <list>` — Compliance frameworks (comma-separated)
- `--scope <type>` — Audit scope (full, security, compliance)
- `--skip-approval` — Skip P0 approval
- `--output <dir>` — Output directory

**Output**:
- Workflow ID
- Repository URL
- Selected frameworks
- Temporal UI URL

**Exit Codes**:
- 0 — Success
- 1 — Invalid input
- 2 — Temporal server unavailable

---

### watch

**Command**: `npm run workflow -- watch <workflow-id>`

**Behavior**:
- Polls workflow status every 2 seconds
- Displays phase changes in real-time
- Shows final result when completed

**Exit Codes**:
- 0 — Workflow completed successfully
- 1 — Workflow failed
- 2 — Workflow not found

---

### approve

**Command**: `npm run workflow -- approve <workflow-id>`

**Behavior**:
- Sends `p0ApprovalSignal` with `true`
- Confirms approval sent

**Exit Codes**:
- 0 — Signal sent successfully
- 1 — Workflow not in approval state
- 2 — Workflow not found

---

### reject

**Command**: `npm run workflow -- reject <workflow-id>`

**Behavior**:
- Sends `p0ApprovalSignal` with `false`
- Confirms rejection sent

**Exit Codes**:
- 0 — Signal sent successfully
- 1 — Workflow not in approval state
- 2 — Workflow not found

---

### status

**Command**: `npm run workflow -- status <workflow-id>`

**Output**:
- Current workflow status
- Current phase
- Start time
- Findings count (if any)

**Exit Codes**:
- 0 — Success
- 2 — Workflow not found

---

### findings

**Command**: `npm run workflow -- findings <workflow-id>`

**Output**:
- Total findings count
- Findings by severity (P0, P1, P2, P3)
- Finding ID and title per severity

**Exit Codes**:
- 0 — Success
- 2 — Workflow not found