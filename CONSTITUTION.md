# Audit Orchestration Constitution

## Core Principles

### I. Security-First Development

**Critical systems require security-first mindset.** This framework handles:
- Customer data in enterprise environments
- Security audit results with compliance implications
- Financial data (trading bots, payment systems)

**Requirements**:
- All code must pass security scanning before merge
- No hardcoded secrets, credentials, or API keys
- Input validation at all system boundaries
- Secure defaults for all configurations
- Audit trails for all security-relevant operations

### II. Test-Driven Development (NON-NEGOTIABLE)

**TDD mandatory for all production code**:
1. Write tests first → Get approval → Verify tests fail
2. Implement minimum code to pass tests
3. Refactor while keeping tests green

**Coverage requirements**:
- Minimum 80% code coverage for all modules
- 100% coverage for critical paths (workflow orchestration, security scans)
- Integration tests required for:
  - Temporal workflow execution
  - Security scan activities
  - Compliance mapping
  - Report generation

**Test types required**:
- Unit tests for activities and utilities
- Integration tests for workflows
- E2E tests for complete audit cycles
- BDD tests for user-facing features (via IIKit)

### III. Enterprise Compliance

**Regulatory requirements are non-negotiable**:
- ISO 27001:2022 — Information security management
- SOC 2 Type II — Service organization controls
- PCI-DSS — Payment card data security (when applicable)
- GDPR — EU data protection (when processing EU personal data)

**Compliance mapping**:
- Every finding must map to compliance controls
- Evidence must be traceable to requirements
- Audit reports must include compliance status
- Changes must be documented for audit trails

### IV. Traceability & Governance

**Every feature must be traceable**:
- Spec → Plan → Tasks → Tests → Code → Evidence
- User stories with acceptance criteria
- BDD scenarios for validation
- Pre-commit hooks for integrity

**Documentation requirements**:
- All public APIs documented with examples
- All workflows documented with diagrams
- All compliance mappings documented
- All security decisions documented

### V. Reliability & Observability

**Production systems must be observable**:
- Structured logging (JSON format)
- Request IDs for correlation
- Metrics for all operations
- Alerts for critical failures

**Reliability requirements**:
- Retry logic for transient failures
- Timeouts for all external calls
- Graceful degradation where possible
- Circuit breakers for dependencies

**Temporal-specific**:
- All workflows must have timeouts
- All activities must be idempotent where possible
- Signals must be documented
- Queries must be side-effect free

## Quality Gates

### Pre-Commit Checks (NON-NEGOTIABLE)

**Required before every commit**:
- ✅ TypeScript compilation (`tsc --noEmit`)
- ✅ Linting passes (`npm run lint`)
- ✅ Tests pass (`npm test`)
- ✅ Coverage threshold met (80%+)
- ✅ Security scan passes (`npm audit`)
- ✅ No secrets detected

**Bypassing prohibited**:
- ❌ NEVER use `git commit --no-verify` or `git commit -n`
- ❌ NEVER disable or delete `.git/hooks/`
- ❌ NEVER use git plumbing commands to circumvent hooks
- If blocked, **fix the root cause** — do not work around

### Pre-Merge Checks

**Required before merging to main**:
- ✅ All pre-commit checks pass
- ✅ Code review approved
- ✅ Integration tests pass
- ✅ Security review (for security-related changes)
- ✅ Documentation updated
- ✅ CHANGELOG updated

### CI/CD Pipeline

**Automated checks in CI**:
- Build: TypeScript compilation
- Test: Unit + integration tests
- Security: npm audit, gitleaks, semgrep
- Coverage: Report generation, threshold enforcement
- Compliance: Schema validation, assertion integrity

## Development Workflow

### Branch Strategy

**Trunk-based development**:
- Main branch is always deployable
- Feature branches: `feature/XXX-description`
- Fix branches: `fix/XXX-description`
- Short-lived branches (< 1 day preferred)

**Commit standards**:
- Conventional Commits format
- One logical change per commit
- Reference issue/task in commit message
- Sign commits (GPG recommended)

### Code Review

**All changes require review**:
- Minimum 1 approval for non-critical changes
- Minimum 2 approvals for critical changes (security, compliance, workflows)
- Security review required for:
  - Authentication/authorization changes
  - Data handling changes
  - Cryptographic operations
  - External integrations

**Review checklist**:
- [ ] Code follows standards
- [ ] Tests adequate and passing
- [ ] Security implications considered
- [ ] Documentation updated
- [ ] No hardcoded secrets
- [ ] Error handling appropriate
- [ ] Logging adequate

### Technology Stack

**Approved technologies**:
- Runtime: Node.js 18+ (v22 recommended)
- Language: TypeScript (strict mode)
- Orchestration: Temporal.io
- Testing: Vitest (unit), Playwright (E2E)
- Linting: ESLint
- Security: npm audit, gitleaks, semgrep

**Dependency management**:
- Minimal dependencies (security surface)
- Lock files required (package-lock.json)
- Regular security audits (automated)
- License compliance checking

## Security Requirements

### Secrets Management

**NEVER**:
- Commit secrets to version control
- Log secrets or sensitive data
- Hardcode API keys or credentials
- Use production secrets in development

**ALWAYS**:
- Use environment variables for secrets
- Use `.env` files locally (gitignored)
- Use secure secret management in production
- Rotate secrets on compromise

### Data Protection

**Classification levels**:
- **Level 3 (Critical)**: Financial, health, government data
- **Level 2 (Sensitive)**: Personal data, credentials
- **Level 1 (Internal)**: Business data, non-public
- **Level 0 (Public)**: Publicly available data

**Handling requirements**:
- Level 3: Encryption at rest + in transit, audit logging
- Level 2: Encryption in transit, access control, audit logging
- Level 1: Access control, audit logging
- Level 0: No special handling

### Audit Trail

**All security-relevant operations must be logged**:
- Who performed the action
- What action was performed
- When the action occurred
- Where the action originated
- Result of the action

**Retention**:
- Audit logs retained for minimum 1 year
- Logs must be immutable
- Logs must be searchable

## Governance

### Constitution Authority

**This constitution supersedes**:
- Individual preferences
- Team conventions (unless documented in CONSTITUTION)
- External practices (unless explicitly adopted)

**Amendments require**:
- Documented rationale
- User approval
- Migration plan for existing code
- Version increment

### Conflict Resolution

**When conflicts arise**:
1. Refer to CONSTITUTION.md first
2. Check compliance requirements
3. Consult security team (for security matters)
4. Document decision and rationale

### Continuous Improvement

**Regular reviews**:
- Constitution review: Quarterly
- Security review: Monthly
- Dependency audit: Weekly (automated)
- Compliance review: Per regulatory cycle

## Integrity

### Pre-Commit Hook Enforcement (NON-NEGOTIABLE)

Pre-commit hooks are a critical integrity gate. The following are prohibited:

- **NEVER** use `git commit --no-verify` or `git commit -n` to bypass hooks
- **NEVER** delete, modify, or disable files in `.git/hooks/`
- **NEVER** use git plumbing commands (`git commit-tree`, `git mktree`) to circumvent hooks
- If a pre-commit hook blocks your commit, **fix the root cause** — do not work around the hook
- For assertion integrity failures: re-run `/iikit-04-testify` to regenerate hashes

**CI enforcement**: Add `verify-assertion-integrity.sh` to CI pipeline for server-side verification.

---

**Version**: 1.0.0 | **Ratified**: 2026-10-01 | **Last Amended**: 2026-10-01

---

## Definition of Done (DoD)

### Feature-Level DoD

**A feature is DONE when ALL criteria are met**:

**Code Quality**:
- [ ] Code compiles without errors (`npm run build`)
- [ ] TypeScript strict mode enabled, no `any` types without justification
- [ ] ESLint passes with 0 errors (`npm run lint`)
- [ ] No console.log in production code (use structured logging)
- [ ] All functions have explicit return types
- [ ] All public APIs documented with JSDoc

**Testing**:
- [ ] Unit tests written and passing (`npm run test`)
- [ ] Test coverage ≥ 80% for new code (`npm run test:coverage`)
- [ ] Integration tests for workflow changes
- [ ] BDD scenarios pass for user-facing features (`npm run test:bdd`)
- [ ] Edge cases and error paths tested

**Security**:
- [ ] No hardcoded secrets (gitleaks scan clean)
- [ ] Input validation at all boundaries
- [ ] No SQL injection/command injection vulnerabilities
- [ ] Dependencies audited (`npm audit --audit-level=high`)
- [ ] Security review completed for security-sensitive changes

**Documentation**:
- [ ] README updated if public API changed
- [ ] CHANGELOG updated
- [ ] Inline comments for complex logic
- [ ] Architecture diagrams updated if structure changed

**Review & Integration**:
- [ ] Code reviewed and approved
- [ ] All CI checks pass (green build)
- [ ] No merge conflicts
- [ ] Branch merged to main (trunk-based)

### Task-Level DoD

**A task is DONE when**:
- [ ] Implementation complete
- [ ] Tests written and passing
- [ ] Code reviewed
- [ ] Documentation updated
- [ ] Committed to main

---

## Quality Metrics

### Code Quality Gates

**Thresholds (INTERIM - Phase 1)**:
| Metric | Threshold | Target | Enforced By |
|--------|-----------|--------|-------------|
| Code Coverage | >= 65% | 80% (Phase 2) | Vitest `coverageThreshold` |
| TypeScript Errors | 0 | 0 | `tsc --noEmit` |
| ESLint Errors | 0 | 0 | `npm run lint` |
| Security Vulnerabilities (high/critical) | 0 | 0 | `npm audit --audit-level=high` |
| Secrets Detected | 0 | 0 | gitleaks |
| Bundle Size | < 5MB | < 5MB | Build check |

**Phase 2 Coverage Target (80%)**:
- Requires integration tests with Temporal server
- Requires real tool execution tests
- Current coverage: 64.89% (161 tests passing)
- See COVERAGE.md for improvement plan

### Maintainability Metrics

**Code complexity**:
- Cyclomatic complexity ≤ 10 per function
- Cognitive complexity ≤ 15 per function
- Function length ≤ 50 lines (exceptions require justification)
- File length ≤ 500 lines (exceptions require justification)

**Dependencies**:
- Direct dependencies ≤ 10 per module
- Total dependencies tracked in package-lock.json
- No deprecated dependencies
- License compliance checked

### Test Quality Metrics

**Coverage breakdown (Phase 1 Interim)**:
- Statement coverage >= 65% (target: 80%)
- Branch coverage >= 40% (target: 80%)
- Function coverage >= 75% (target: 80%)
- Line coverage >= 68% (target: 80%)

**Test effectiveness**:
- All test scenarios from spec covered
- All acceptance criteria tested
- Edge cases covered
- Error paths covered

---

## Non-Functional Requirements (NFR)

### Performance Requirements

**Response times**:
| Operation | Target | Max |
|-----------|--------|-----|
| Workflow start | < 1s | 5s |
| Status query | < 100ms | 500ms |
| Audit discovery phase | < 2 min | 5 min |
| Security scan (1000 deps) | < 15 min | 30 min |
| Report generation | < 30s | 60s |
| Complete audit cycle | < 25 min | 60 min |

**Throughput**:
- 10 concurrent audits per worker
- 100 findings per second processing
- 1000 repository files per scan

### Reliability Requirements

**Availability**:
- System uptime ≥ 99.9%
- Worker availability ≥ 99.5%
- Temporal server availability ≥ 99.99%

**Failure handling**:
- Activity retries: max 3 attempts
- Workflow retries: configurable per use case
- Circuit breaker: open after 5 consecutive failures
- Graceful degradation: continue with partial results

**Data integrity**:
- All findings persisted with evidence
- No data loss on worker restart
- Idempotent activities where possible

### Scalability Requirements

**Horizontal scaling**:
- Workers scale independently
- Multiple Temporal server instances (production)
- Database connection pooling

**Vertical limits**:
- Memory per worker: ≤ 2GB
- CPU per worker: ≤ 2 cores
- Disk per audit: ≤ 1GB temporary

### Security Requirements

**Authentication**:
- Temporal server: mTLS (production)
- Worker: Namespace + Task Queue isolation
- API: Token-based (if exposed)

**Authorization**:
- Role-based access control
- Least privilege principle
- Audit trail for all access

**Data protection**:
- Encryption at rest (Level 2+ data)
- Encryption in transit (TLS 1.2+)
- Secrets in environment variables only

---

## Performance Metrics

### System Metrics

**Resource utilization**:
| Metric | Warning | Critical |
|--------|---------|----------|
| CPU usage | > 70% | > 90% |
| Memory usage | > 70% | > 90% |
| Disk I/O | > 100 MB/s | > 500 MB/s |
| Network I/O | > 10 MB/s | > 50 MB/s |

**Temporal metrics**:
- Workflow execution latency: < 100ms
- Activity task queue latency: < 50ms
- Workflow task queue latency: < 50ms

### Application Metrics

**Business metrics**:
- Audits completed per hour
- Findings per audit (P0, P1, P2, P3)
- False positive rate
- Time to remediation

**Quality metrics**:
- Build success rate: > 95%
- Test pass rate: > 99%
- Code coverage trend: increasing
- Technical debt ratio: < 5%

### Monitoring & Alerting

**Required monitoring**:
- Workflow execution success/failure rate
- Activity execution latency
- Queue depth (pending tasks)
- Error rates by type

**Alerting thresholds**:
- P0 finding detected → Immediate alert
- Workflow failure rate > 5% → Alert
- Queue depth > 100 → Alert
- Worker down → Immediate alert

---

## Enforcement

### Automated Enforcement

**CI Pipeline (NON-NEGOTIABLE)**:
```yaml
verify:
  - npm run build (TypeScript compilation)
  - npm run test:coverage (Tests + 80% threshold)
  - npm run lint (ESLint 0 errors)
  - npm audit --audit-level=high (Security)
  - gitleaks scan (Secrets)
```

**Pre-commit Hooks (NON-NEGOTIABLE)**:
- `.githooks/pre-commit`: `npm run verify`
- `.githooks/pre-push`: `npm run verify` + gitleaks

**Coverage enforcement**:
- `vitest.config.ts`: `threshold.global: { lines: 80, functions: 80, branches: 80, statements: 80 }`
- Build fails if coverage < 80%

### Manual Review

**Code review checklist**:
- DoD checklist verified
- Quality metrics met
- NFR requirements satisfied
- Security implications considered

**Sign-off requirements**:
- Technical lead: Architecture changes
- Security lead: Security-sensitive changes
- Product owner: User-facing features