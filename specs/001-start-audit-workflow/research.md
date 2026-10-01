# Research: Start Audit Workflow

**Date**: 2026-10-01
**Feature**: 001-start-audit-workflow

## Technology Stack Decisions

### 1. Temporal.io — Workflow Orchestration

**Decision**: ✅ Selected

**Rationale**:
- Durable execution with automatic state persistence
- Built-in retry logic, timeouts, and error handling
- Human-in-the-loop via signals
- Real-time queries for monitoring
- Open source (MIT license)
- Production-proven (Uber, Coinbase, Netflix)

**Eval Score**: N/A (not in Tessl registry yet)

**Alternatives Considered**:

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| AWS Step Functions | Managed service, AWS integration | Vendor lock-in, proprietary, costs | Need open source, portable solution |
| Apache Airflow | Mature, large community | Batch-oriented, DAG model, no human-in-the-loop | Not designed for interactive workflows |
| Camunda | BPMN standard, visual modeling | Java-centric, heavy weight | Overkill for this use case |
| Custom state machine | Full control | No persistence, reinventing patterns | Too much boilerplate, error-prone |

**Implementation Notes**:
- Use Temporal CLI for local development: `temporal server start-dev`
- Use Docker Compose for production-like setup
- Consider Temporal Cloud for enterprise deployments

---

### 2. TypeScript — Primary Language

**Decision**: ✅ Selected

**Rationale**:
- Type safety for complex workflow logic
- Excellent Temporal SDK support
- Node.js ecosystem for security tools
- Familiar to target users (DevOps, security teams)

**Version**: TypeScript 5.x, Node.js 22 (LTS)

---

### 3. Security Scanning Tools

#### npm audit (Node.js)

**Decision**: ✅ Selected

**Rationale**:
- Built into npm, no installation required
- Checks against GitHub Advisory Database
- JSON output for programmatic processing
- Supports audit fix suggestions

**Limitations**:
- Only scans package-lock.json dependencies
- No transitive dependency vulnerabilities (partial)

#### gitleaks (Secret Scanning)

**Decision**: ✅ Selected

**Rationale**:
- Open source (MIT license)
- 100+ built-in secret patterns
- Git history scanning
- JSON report output
- Actively maintained

**Installation**: `brew install gitleaks` or download binary

#### semgrep (SAST)

**Decision**: ✅ Selected

**Rationale**:
- Open source (LGPL 2.1)
- Multi-language support (JS, TS, Python, Go, etc.)
- Custom rules support
- Fast and low false positive rate
- `--config=auto` for best practices rules

**Installation**: `brew install semgrep` or Docker

#### license-checker (License Compliance)

**Decision**: ✅ Selected

**Rationale**:
- Open source (BSD-2-Clause)
- Scans all npm dependencies
- JSON output
- Configurable license policies

**Installation**: `npx license-checker`

---

### 4. Testing Framework

**Decision**: ✅ Vitest (unit) + Cucumber.js (BDD)

**Rationale**:
- **Vitest**: Fast, Vite-native, Jest-compatible API
- **Cucumber.js**: BDD testing for Gherkin scenarios
- Both work well with TypeScript
- Good coverage support

**Alternatives Considered**:

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| Jest | Mature, large ecosystem | Slower, more config | Vitest faster and simpler |
| Mocha | Flexible | No built-in assertions | Too much boilerplate |
| Playwright Test | E2E focus | Not for unit tests | Keep for E2E tests |

---

### 5. Data Storage

**Decision**: ✅ File System (temporary)

**Rationale**:
- Audit artifacts are temporary per workflow
- Temporal persists workflow state
- No database overhead for MVP
- Evidence files can be archived later

**Future Considerations**:
- S3 bucket for evidence storage
- Database for audit history and analytics

---

## Integration Patterns

### Temporal Workflow Patterns

1. **Parallel Execution**: Use `Promise.all()` for concurrent activities
2. **Human-in-the-Loop**: Use `condition()` + signals
3. **Query Pattern**: Use `defineQuery()` for status checks
4. **Timeout Pattern**: Set per-activity timeouts
5. **Retry Pattern**: Configure retry policy per activity

### Error Handling

```typescript
// Activity-level retries
const { activity } = proxyActivities({
  startToCloseTimeout: '1 hour',
  retry: {
    initialInterval: '10 seconds',
    maximumInterval: '5 minutes',
    maximumAttempts: 3,
    nonRetryableErrorTypes: ['InvalidRepoError'],
  },
});

// Workflow-level timeout
if (Date.now() - startTime > 8 * 60 * 60 * 1000) {
  throw new ApplicationFailure('Audit timeout exceeded (8 hours)');
}
```

---

## Performance Benchmarks

### Expected Timings

| Phase | Duration | Notes |
|-------|----------|-------|
| Discovery | 1-2 min | Clone repo, detect tech stack |
| Scanning | 5-15 min | Parallel execution, depends on repo size |
| Reviewing | 1-5 min | AI code review (placeholder) |
| Compliance | <1 min | Mapping logic |
| Validation | 1-2 min | Cross-validation (placeholder) |
| Reporting | <1 min | Generate Markdown report |
| **Total** | **10-25 min** | For typical repository |

### Resource Usage

| Resource | Limit | Rationale |
|----------|-------|-----------|
| Concurrent scans | 4 | Prevent resource exhaustion |
| Repo size | 5GB | Timeout consideration |
| Findings | 1000 | Report size limit |
| Workflow timeout | 8 hours | Constitutional limit |

---

## Deployment Options

### Development

```bash
# Local Temporal server
temporal server start-dev

# Worker
npm run start

# CLI client
npm run workflow -- start vannifr/event-ticketing
```

### Docker Compose

```yaml
services:
  temporal:
    image: temporalio/auto-setup:latest
    ports: ["7233:7233"]

  temporal-ui:
    image: temporalio/ui:latest
    ports: ["8233:8233"]

  audit-worker:
    build: .
    command: npm run start
    depends_on: [temporal]
```

### Production (Kubernetes)

- Temporal Cloud or self-hosted Temporal cluster
- Worker deployment (horizontal scaling)
- Configurable worker replicas based on load

---

## Open Questions

1. **AI Code Review**: Which LLM to use for critical path review?
   - Options: OpenAI GPT-4, Anthropic Claude, local LLM
   - **Decision**: Placeholder for now, integrate Qwen Agent later

2. **Evidence Archival**: How long to retain evidence?
   - **Decision**: 90 days default, configurable per compliance framework

3. **Multi-repo Audits**: Support for monorepos?
   - **Decision**: Phase 2 feature, not in MVP

---

## References

- [Temporal Documentation](https://docs.temporal.io/)
- [Temporal TypeScript SDK](https://github.com/temporalio/sdk-typescript)
- [npm audit documentation](https://docs.npmjs.com/cli/v8/commands/npm-audit)
- [gitleaks repository](https://github.com/gitleaks/gitleaks)
- [semgrep documentation](https://semgrep.dev/docs/)